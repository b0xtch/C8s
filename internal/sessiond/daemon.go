package sessiond

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	sessionv1alpha1 "github.com/confidential-dot-ai/c8s/api/session/v1alpha1"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/disclosure"
)

const (
	// parallelBoots is how many TDs of one pool boot at once. A boot accepts
	// memory with the host's cores, and the TDs that serve need them too.
	parallelBoots = 2
	// readyPoll is how often a booting guest is asked whether it serves, and
	// readyDial how long a connection to it may take to open. A guest that is
	// up accepts within a fraction of that. One that is not answers nothing,
	// and the kernel would wait a second before it asked again: a new
	// connection each time asks at once.
	readyPoll = 20 * time.Millisecond
	readyDial = 25 * time.Millisecond
	// warmEvery is how often a ready guest is asked for what a claim relays.
	// A guest closes a connection that was idle for a minute.
	warmEvery = 20 * time.Second
	// retention is how long the record of an ended TD is kept, to answer a
	// repeat of the request that ended it.
	retention = 10 * time.Minute
	// maxBootBackoff bounds the wait between boots of a pool that fail.
	maxBootBackoff = time.Minute
	// workDir is where a TD's launch disk and scratch disk live, in its own
	// directory.
	workDir = "vm"
	// endFile is where a TD's launcher keeps the guest's last word, in the
	// TD's own directory.
	endFile = "end.json"
	// collateralDir is where the launchers keep the vendor's documents they
	// answer their guests with, in the state directory: one set for every TD
	// of the host.
	collateralDir = "collateral"
	// maxCallerRelays bounds the evidence requests one caller has in flight
	// at once, and maxStreams the connections the daemon carries, for every
	// caller together.
	maxCallerRelays = 64
	maxStreams      = 4096
	// maxWatchers bounds the streams that watch pools' ready TDs, for every
	// binder together.
	maxWatchers = 64
)

// Daemon keeps the pools of one host and serves the session API over them.
type Daemon struct {
	sessionv1alpha1.UnimplementedSessionsServer

	cfg    *Config
	log    *slog.Logger
	runner Runner
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
	now    func() time.Time
	// bootTimeout is how long a TD may take to serve.
	bootTimeout time.Duration
	// writeFile puts a record's file in place, whole or not at all, where a
	// test has its own way to: see write.
	writeFile atomic.Pointer[func(path string, data []byte, mode os.FileMode) error]

	mu  sync.Mutex
	tds map[string]*td
	// changed is closed, and replaced, whenever a TD changes state.
	changed chan struct{}
	pools   map[string]*poolState
	// streams counts the Connect streams in flight.
	streams int
	// relays bounds the evidence requests in flight, by caller.
	relays relays
	// watchers counts the WatchReady streams in flight, and eventWatchers
	// the Watch streams.
	watchers, eventWatchers int
	// orchestrators is the authority an orchestrator's certificate chains
	// to, and chains the outcome of that check for the certificates seen.
	orchestrators *x509.CertPool
	chains        chains
	// stop is closed when Run's context ends: the daemon's own work stops,
	// and its TDs run on.
	stop chan struct{}
	wg   sync.WaitGroup
}

// poolState is what the daemon knows of a pool beyond its configuration.
type poolState struct {
	cfg *Pool
	// failures counts the boots that failed since one last succeeded, and
	// nextBoot is when the next may start.
	failures int
	nextBoot time.Time
	// bootTime is how long the last TD took from launch to ready.
	bootTime time.Duration
}

// New returns a daemon over runner. Nothing runs until Run.
func New(cfg *Config, runner Runner, log *slog.Logger) *Daemon {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	d := &Daemon{
		cfg: cfg, log: log, runner: runner, dial: dialer.DialContext, now: time.Now,
		bootTimeout: DefaultBootTimeout,
		tds:         map[string]*td{}, changed: make(chan struct{}), pools: map[string]*poolState{},
		stop: make(chan struct{}),
	}
	for i := range cfg.Pools {
		d.pools[cfg.Pools[i].name] = &poolState{cfg: &cfg.Pools[i]}
	}
	return d
}

// Run takes over the TDs an earlier daemon left, then keeps every pool at its
// depth until ctx ends. The TDs outlive it: a daemon started later finds them.
func (d *Daemon) Run(ctx context.Context) error {
	if err := os.MkdirAll(d.cfg.StateDir, 0o700); err != nil {
		return err
	}
	if err := d.adopt(); err != nil {
		return err
	}
	for _, pool := range d.pools {
		d.wg.Go(func() { d.keep(ctx, pool) })
	}
	d.wg.Go(func() { d.sweep(ctx) })
	d.wg.Go(func() { d.keepWarm(ctx) })
	<-ctx.Done()
	close(d.stop)
	d.wg.Wait()
	return nil
}

// Drain ends every TD the state directory records and waits for their
// memory to be the host's again. It is for a host that leaves service, with
// no daemon running over the same state.
func (d *Daemon) Drain(ctx context.Context) (int, error) {
	if err := d.adopt(); err != nil {
		return 0, err
	}
	d.mu.Lock()
	var live []*td
	for _, t := range d.tds {
		if t.inst != nil {
			live = append(live, t)
			d.endLocked(t, "drained", "")
		}
	}
	d.mu.Unlock()
	// What adopt started watches the TDs go.
	defer func() {
		close(d.stop)
		d.wg.Wait()
	}()
	for _, t := range live {
		select {
		case <-t.inst.Done():
		case <-ctx.Done():
			return len(live), fmt.Errorf("TD %s is still going: %w", t.rec.ID, ctx.Err())
		}
	}
	return len(live), nil
}

// notify wakes whoever waits for a TD to change. The caller holds the lock.
func (d *Daemon) notify() {
	close(d.changed)
	d.changed = make(chan struct{})
}

// adopt takes over the TDs of an earlier daemon whose processes still run,
// and ends the records of the others.
func (d *Daemon) adopt() error {
	records, err := d.load()
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, rec := range records {
		t := &td{rec: rec, gone: true, guests: newGuestClient(d.dial)}
		t.ctx, t.cancel = context.WithCancel(context.Background())
		d.tds[rec.ID] = t
		if rec.State == StateEnded {
			t.cancel()
			continue
		}
		pool, ok := d.pools[rec.Pool]
		var inst Instance
		err := fmt.Errorf("its pool %s is no longer configured", rec.Pool)
		if ok {
			inst, err = d.runner.Adopt(d.spec(rec.ID, rec.Slot, pool.cfg), rec.Handle)
		}
		if err != nil {
			d.log.Warn("a TD of an earlier daemon is gone", "td", rec.ID, "state", rec.State, "error", err)
			d.endLocked(t, "host lost: "+err.Error(), "")
			continue
		}
		t.inst, t.gone = inst, false
		switch rec.State {
		case StateBooting:
			// Nobody watched it become ready. Its boot is taken up again.
			d.wg.Go(func() { d.await(t, pool, d.now()) })
		case StateClaimed:
			d.armLapse(t)
		}
		d.wg.Go(func() { d.watch(t) })
		d.log.Info("took over a TD", "td", rec.ID, "state", rec.State, "pool", rec.Pool)
	}
	return nil
}

func (d *Daemon) spec(id string, slot int, pool *Pool) Spec {
	return Spec{ID: id, Dir: d.dir(id), Slot: slot, Pool: pool, Class: d.cfg.Classes[pool.class]}
}

// keep boots TDs until the pool has its depth ready or booting, within the
// host's capacity.
func (d *Daemon) keep(ctx context.Context, pool *poolState) {
	for {
		d.mu.Lock()
		changed := d.changed
		var wait <-chan time.Time
		for d.wantsBoot(pool) {
			if now := d.now(); now.Before(pool.nextBoot) {
				wait = time.After(pool.nextBoot.Sub(now))
				break
			}
			t, err := d.newTD(pool)
			if err != nil {
				d.log.Error("a TD could not be set up", "pool", pool.cfg.name, "error", err)
				d.failed(pool)
				continue
			}
			d.wg.Go(func() { d.boot(ctx, t, pool) })
		}
		d.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-changed:
		case <-wait:
		}
	}
}

// wantsBoot reports whether the pool is short of TDs it may boot now. The
// caller holds the lock.
func (d *Daemon) wantsBoot(pool *poolState) bool {
	ahead, booting, held := 0, 0, 0
	for _, t := range d.tds {
		if !t.gone {
			held++
		}
		if t.rec.Pool != pool.cfg.name {
			continue
		}
		switch t.rec.State {
		case StateBooting:
			booting++
			ahead++
		case StateReady:
			ahead++
		}
	}
	return ahead < pool.cfg.Depth && booting < parallelBoots && held < d.cfg.Capacity
}

// failed counts a boot of the pool that failed and puts the next one off.
// The caller holds the lock.
func (d *Daemon) failed(pool *poolState) {
	pool.failures++
	pool.nextBoot = d.now().Add(min(time.Second<<min(pool.failures-1, 6), maxBootBackoff))
}

// newTD records a TD about to boot, in the lowest slot no live TD holds. The
// caller holds the lock.
func (d *Daemon) newTD(pool *poolState) (*td, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	taken := map[int]bool{}
	for _, t := range d.tds {
		if !t.gone {
			taken[t.rec.Slot] = true
		}
	}
	slot := 0
	for taken[slot] {
		slot++
	}
	t := &td{rec: record{ID: id, Pool: pool.cfg.name, State: StateBooting, Slot: slot, Created: d.now()}, guests: newGuestClient(d.dial)}
	t.ctx, t.cancel = context.WithCancel(context.Background())
	if err := os.MkdirAll(d.dir(id), 0o700); err != nil {
		return nil, err
	}
	if err := d.save(t); err != nil {
		_ = os.RemoveAll(d.dir(id))
		return nil, err
	}
	d.tds[id] = t
	// Whoever watches the host's TDs sees it boot.
	d.notify()
	return t, nil
}

// boot launches a TD and waits for its guest to serve.
func (d *Daemon) boot(ctx context.Context, t *td, pool *poolState) {
	started := d.now()
	inst, err := d.runner.Start(ctx, d.spec(t.rec.ID, t.rec.Slot, pool.cfg))
	d.mu.Lock()
	if err != nil {
		d.log.Error("a TD did not launch", "td", t.rec.ID, "pool", pool.cfg.name, "error", err)
		t.gone = true
		d.failed(pool)
		d.endLocked(t, "launch failed", "")
		d.mu.Unlock()
		return
	}
	t.inst, t.rec.Handle, t.rec.Address = inst, inst.Handle(), inst.Address()
	if err := d.save(t); err != nil {
		d.log.Error("a TD's record could not be kept", "td", t.rec.ID, "error", err)
	}
	d.mu.Unlock()
	d.wg.Go(func() { d.watch(t) })
	d.await(t, pool, started)
}

// await asks a booting guest whether it serves until it does, the TD ends or
// the boot runs out of time.
func (d *Daemon) await(t *td, pool *poolState, started time.Time) {
	deadline := time.NewTimer(d.bootTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(readyPoll)
	defer tick.Stop()
	var offered *session.StateResponse
	var leaf, collateral []byte
	for {
		probe, cancel := context.WithTimeout(withDialLimit(t.ctx, readyDial), 5*time.Second)
		if offered, leaf = t.guests.ready(probe, t.rec.Address); offered != nil {
			collateral = t.guests.collateral(probe, t.rec.Address)
		}
		cancel()
		if offered != nil {
			break
		}
		select {
		case <-t.ctx.Done():
			return
		case <-d.stop:
			return
		case <-deadline.C:
			d.mu.Lock()
			d.failed(pool)
			d.mu.Unlock()
			d.end(t, fmt.Sprintf("did not serve within %s", d.bootTimeout), "")
			return
		case <-tick.C:
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if t.rec.State != StateBooting {
		return
	}
	t.rec.State = StateReady
	t.serves(offered, leaf)
	t.collateral = collateral
	pool.failures, pool.bootTime = 0, d.now().Sub(started)
	if err := d.save(t); err != nil {
		d.log.Error("a TD's record could not be kept", "td", t.rec.ID, "error", err)
	}
	d.log.Info("a TD is ready", "td", t.rec.ID, "pool", pool.cfg.name, "boot_ms", pool.bootTime.Milliseconds())
	d.notify()
}

// watch waits for the TD's process to go, which ends the TD if nothing else
// did, and frees its share of the host.
func (d *Daemon) watch(t *td) {
	select {
	case <-t.inst.Done():
	case <-d.stop:
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	t.gone = true
	if t.rec.State != StateEnded {
		if pool := d.pools[t.rec.Pool]; pool != nil && t.rec.State == StateBooting {
			d.failed(pool)
		}
		// An age limit, a refused bind, a crash: the guest's last word says
		// which, where it gave one.
		d.endLocked(t, d.guestEnded(t), "")
	}
	// The launch disk and the scratch disk held only what the guest wrote
	// under keys that died with it.
	_ = os.RemoveAll(filepath.Join(d.dir(t.rec.ID), workDir))
	d.notify()
}

// guestEnded is the reason of a TD whose guest ended: with the guest's last
// word, as its launcher kept it, or without one. A guest that says none
// crashed, or its VMM was ended under it. The word is an operator's to read
// and nothing here acts on it.
func (d *Daemon) guestEnded(t *td) string {
	const reason = "the guest ended"
	data, err := session.ReadBounded(filepath.Join(d.dir(t.rec.ID), endFile), disclosure.MaxEnd)
	if err != nil {
		return reason
	}
	end, err := disclosure.ParseEnd(bytes.TrimSpace(data))
	if err != nil {
		return reason
	}
	return reason + ": " + end.String()
}

// end ends a TD: no state leads out of it.
func (d *Daemon) end(t *td, reason, requestID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.endLocked(t, reason, requestID)
}

// endLocked is end for a caller that holds the lock.
func (d *Daemon) endLocked(t *td, reason, requestID string) {
	if t.rec.State == StateEnded {
		return
	}
	d.log.Info("a TD ended", "td", t.rec.ID, "pool", t.rec.Pool, "was", t.rec.State, "reason", reason)
	t.rec.State = StateEnded
	t.rec.Ended = &ended{At: d.now(), Reason: reason, RequestID: requestID}
	if t.lapse != nil {
		t.lapse.Stop()
	}
	t.cancel()
	// Its connections end with it: none is kept for whatever has its address
	// next.
	t.guests.reconnect()
	if err := d.save(t); err != nil {
		d.log.Error("a TD's record could not be kept", "td", t.rec.ID, "error", err)
	}
	if t.inst != nil {
		t.inst.Stop()
	}
	d.notify()
}

// armLapse returns a claimed TD to its pool when its bind grace runs out.
// The caller holds the lock.
func (d *Daemon) armLapse(t *td) {
	wait := max(t.rec.Claim.BindBy.Sub(d.now()), 0)
	t.lapse = time.AfterFunc(wait, func() { d.lapsed(t) })
}

// lapsed returns a TD whose claim nobody bound to its pool.
func (d *Daemon) lapsed(t *td) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.releasable(t) {
		d.log.Info("a claim lapsed", "td", t.rec.ID, "session", t.rec.Claim.Session)
		d.release(t, "")
	}
}

// releasable reports whether the TD is claimed and has been sent no bind.
// Nothing of a tenant entered such a TD: the daemon relayed it nothing, and
// nobody else reaches a guest that is not bound. The caller holds the lock.
func (d *Daemon) releasable(t *td) bool {
	return t.rec.State == StateClaimed && t.rec.Bind == nil && !t.busy
}

// release returns a releasable TD to its pool, for destroyID when a Destroy
// gave the claim back. The caller holds the lock.
func (d *Daemon) release(t *td, destroyID string) {
	if t.lapse != nil {
		t.lapse.Stop()
	}
	t.rec.Released = append(t.rec.Released, released{Claim: t.rec.Claim.RequestID, Destroy: destroyID, Session: t.rec.Claim.Session})
	if len(t.rec.Released) > keptReleases {
		t.rec.Released = t.rec.Released[len(t.rec.Released)-keptReleases:]
	}
	t.rec.Claim, t.rec.State = nil, StateReady
	if err := d.save(t); err != nil {
		d.log.Error("a TD's record could not be kept", "td", t.rec.ID, "error", err)
	}
	d.notify()
}

// keepWarm asks every ready guest what it says of itself and for the
// vendor's documents it holds, a few times a minute. That keeps what a claim
// relays current, since a claim asks the guest nothing, and keeps the
// daemon's connection to the guest from idling out, so that a bind finds it
// open. A guest whose certificate is about to run out is asked over a new
// connection, which it answers under the one it serves now.
func (d *Daemon) keepWarm(ctx context.Context) {
	tick := time.NewTicker(warmEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		d.mu.Lock()
		var ready []*td
		for _, t := range d.tds {
			if t.rec.State == StateReady && !t.busy {
				ready = append(ready, t)
			}
		}
		d.mu.Unlock()
		for _, t := range ready {
			probe, cancel := context.WithTimeout(ctx, 5*time.Second)
			offered, leaf := t.guests.ready(probe, t.rec.Address)
			if offered != nil && !lasts(leaf, d.now()) {
				t.guests.reconnect()
				offered, leaf = t.guests.ready(probe, t.rec.Address)
			}
			var collateral []byte
			if offered != nil {
				collateral = t.guests.collateral(probe, t.rec.Address)
			}
			cancel()
			if offered == nil {
				continue
			}
			d.mu.Lock()
			if t.rec.State == StateReady {
				// Whoever watches the pool is shown a certificate the guest
				// came to serve since: a claim is answered with it.
				renewed := !bytes.Equal(t.leaf, leaf)
				t.serves(offered, leaf)
				if collateral != nil {
					t.collateral = collateral
				}
				if renewed {
					d.notify()
				}
			}
			d.mu.Unlock()
		}
	}
}

// sweep forgets ended TDs once their records have been kept long enough.
func (d *Daemon) sweep(ctx context.Context) {
	tick := time.NewTicker(retention / 10)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		d.mu.Lock()
		for id, t := range d.tds {
			if t.rec.State == StateEnded && t.gone && d.now().Sub(t.rec.Ended.At) > retention {
				delete(d.tds, id)
				_ = os.RemoveAll(d.dir(id))
			}
		}
		d.mu.Unlock()
	}
}
