package sessiond

import (
	"context"
	"net"
	"sync"

	"google.golang.org/grpc/peer"

	sessionv1alpha1 "github.com/confidential-dot-ai/c8s/api/session/v1alpha1"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// relays bounds the evidence requests of one caller that the daemon has in
// flight at once. Evidence is open to anyone, and a bound that every caller
// shared would let one of them crowd out everybody else's.
type relays struct {
	mu       sync.Mutex
	byCaller map[string]int
}

// enter takes a place for one request of caller and returns how to give it
// back, or nil for a caller that has as many in flight as it may.
func (r *relays) enter(caller string) (leave func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byCaller[caller] >= maxCallerRelays {
		return nil
	}
	if r.byCaller == nil {
		r.byCaller = map[string]int{}
	}
	r.byCaller[caller]++
	return sync.OnceFunc(func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		// A count that is back at nothing is no entry: the map holds those
		// in flight and no more.
		if r.byCaller[caller]--; r.byCaller[caller] == 0 {
			delete(r.byCaller, caller)
		}
	})
}

// callerOf names who makes a call, for the bound a caller has to itself: the
// key of the certificate it presented, and without one the address it calls
// from. Callers the daemon can tell nothing of share one name.
func callerOf(ctx context.Context) string {
	if certs := presented(ctx); len(certs) > 0 {
		if name, err := session.InstanceKeyDigest(certs[0].PublicKey); err == nil {
			return "key " + name
		}
	}
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		if host, _, err := net.SplitHostPort(p.Addr.String()); err == nil {
			return "address " + host
		}
		return "address " + p.Addr.String()
	}
	return ""
}

// asked is one request to a guest for its evidence, done once done is
// closed. A guest serves the same to anyone, so the daemon has it answer one
// such request at a time, and everyone who asks while one is in flight
// shares the next: an answer is of a request sent after its caller asked,
// and no caller can keep another's from being served.
type asked struct {
	done     chan struct{}
	evidence *sessionv1alpha1.Evidence
	err      error
}

// askLocked returns the request for t's evidence whose answer a caller that
// asks now takes: a new one, sent at once if none is in flight and else when
// the one in flight is done. The request is the TD's and no caller's: it
// outlives a caller that leaves, and ends with the TD. The caller holds the
// daemon's lock.
func (d *Daemon) askLocked(t *td) *asked {
	if t.asking != nil {
		if t.asksNext == nil {
			t.asksNext = &asked{done: make(chan struct{})}
		}
		return t.asksNext
	}
	t.asking = &asked{done: make(chan struct{})}
	go d.ask(t, t.asking, t.rec.Address)
	return t.asking
}

// ask sends the request to t's guest, and then each request that came to
// wait behind the one before it.
func (d *Daemon) ask(t *td, request *asked, address string) {
	for request != nil {
		ctx, cancel := context.WithTimeout(t.ctx, evidenceTimeout)
		request.evidence, request.err = t.guests.evidence(ctx, address)
		cancel()
		d.mu.Lock()
		t.asking, t.asksNext = t.asksNext, nil
		next := t.asking
		address = t.rec.Address
		d.mu.Unlock()
		close(request.done)
		request = next
	}
}
