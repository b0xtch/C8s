package sessiond

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	sessionv1alpha1 "github.com/confidential-dot-ai/c8s/api/session/v1alpha1"
)

const (
	// parallelBoots is how many TDs of one pool boot at once. A boot accepts
	// memory with the host's cores, and the TDs that serve need them too.
	parallelBoots = 2
	// readyPoll is how often a booting guest is asked whether it serves.
	readyPoll = 100 * time.Millisecond
	// retention is how long the record of an ended TD is kept, to answer a
	// repeat of the request that ended it.
	retention = 10 * time.Minute
	// maxBootBackoff bounds the wait between boots of a pool that fail.
	maxBootBackoff = time.Minute
	// workDir is where a TD's launch disk and scratch disk live, in its own
	// directory.
	workDir = "vm"
	// collateralDir is where the launchers keep the vendor's documents they
	// answer their guests with, in the state directory: one set for every TD
	// of the host.
	collateralDir = "collateral"
	// maxRelays bounds the evidence requests the daemon relays at once, and
	// maxStreams the connections it carries, for every caller together.
	maxRelays  = 64
	maxStreams = 4096
)

// Daemon keeps the pools of one host and serves the session API over them.
type Daemon struct {
	sessionv1alpha1.UnimplementedSessionsServer

	cfg    *Config
	log    *slog.Logger
	runner Runner
	guests *guestClient
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
	now    func() time.Time
	// bootTimeout is how long a TD may take to serve.
	bootTimeout time.Duration

	mu  sync.Mutex
	tds map[string]*td
	// changed is closed, and replaced, whenever a TD changes state.
	changed chan struct{}
	pools   map[string]*poolState
	// streams counts the Connect streams in flight.
	streams int
	// relays bounds the evidence requests in flight.
	relays chan struct{}
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
		stop:   make(chan struct{}),
		relays: make(chan struct{}, maxRelays),
	}
	d.guests = newGuestClient(d.dial)
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
		t := &td{rec: rec, gone: true}
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
	t := &td{rec: record{ID: id, Pool: pool.cfg.name, State: StateBooting, Slot: slot, Created: d.now()}}
	t.ctx, t.cancel = context.WithCancel(context.Background())
	if err := os.MkdirAll(d.dir(id), 0o700); err != nil {
		return nil, err
	}
	if err := d.save(t); err != nil {
		_ = os.RemoveAll(d.dir(id))
		return nil, err
	}
	d.tds[id] = t
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
	for {
		probe, cancel := context.WithTimeout(t.ctx, 5*time.Second)
		ready := d.guests.ready(probe, t.rec.Address)
		cancel()
		if ready {
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
		// An age limit, a refused bind, a crash: the host cannot tell which.
		d.endLocked(t, "the guest ended", "")
	}
	// The launch disk and the scratch disk held only what the guest wrote
	// under keys that died with it.
	_ = os.RemoveAll(filepath.Join(d.dir(t.rec.ID), workDir))
	d.notify()
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
