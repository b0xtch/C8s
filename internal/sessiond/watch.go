package sessiond

import (
	"cmp"
	"context"
	"crypto/sha256"
	"slices"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sessionv1alpha1 "github.com/confidential-dot-ai/c8s/api/session/v1alpha1"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// WatchReady streams what each ready TD of a pool says of itself, as a claim
// of it would be answered: the TDs ready now, oldest first, then each as it
// becomes ready or comes to serve another certificate. A binder judges them
// ahead of its claims, so that its check is off the path of a start.
//
// A stream shows how fast the pool refills, which is every tenant's starts
// together, so it is open only to the binders the pool's configuration
// names. The daemon says nothing here that it would not say in a claim's
// answer, and what it holds back or adds costs a binder time and nothing
// else: a claimed TD the binder never judged is judged at its claim.
func (d *Daemon) WatchReady(req *sessionv1alpha1.WatchReadyRequest, stream sessionv1alpha1.Sessions_WatchReadyServer) error {
	ctx := stream.Context()
	d.mu.Lock()
	pool, ok := d.pools[req.GetPool()]
	if !ok {
		d.mu.Unlock()
		return status.Errorf(codes.NotFound, "no pool %q", req.GetPool())
	}
	if !watches(ctx, pool.cfg) {
		d.mu.Unlock()
		return status.Errorf(codes.PermissionDenied, "pool %s does not name this caller as one of its binders", pool.cfg.name)
	}
	if d.watchers >= maxWatchers {
		d.mu.Unlock()
		return status.Error(codes.ResourceExhausted, "too many streams watch this host's pools")
	}
	d.watchers++
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.watchers--
		d.mu.Unlock()
	}()

	// shown is the certificate each TD was last shown under.
	shown := map[string][sha256.Size]byte{}
	for {
		due, changed := d.readyUnshown(pool, shown)
		for _, evidence := range due {
			if err := stream.Send(evidence); err != nil {
				return err
			}
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return status.FromContextError(ctx.Err()).Err()
		case <-d.stop:
			return status.Error(codes.Unavailable, "the daemon is stopping")
		}
	}
}

// readyUnshown returns the evidence of the pool's ready TDs that shown does
// not hold under the certificate they serve now, oldest TD first, notes them
// in shown, and forgets there the TDs that are ready no more. changed is
// closed when a TD next changes.
func (d *Daemon) readyUnshown(pool *poolState, shown map[string][sha256.Size]byte) (due []*sessionv1alpha1.Evidence, changed <-chan struct{}) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	var ready []*td
	for _, t := range d.tds {
		// What a claim would be answered with from the daemon's own record.
		// A TD it has nothing current of is asked at its claim, and is
		// judged then.
		if t.rec.Pool == pool.cfg.name && t.rec.State == StateReady && t.offered != nil && lasts(t.leaf, now) {
			ready = append(ready, t)
		}
	}
	slices.SortFunc(ready, func(a, b *td) int {
		if c := a.rec.Created.Compare(b.rec.Created); c != 0 {
			return c
		}
		return cmp.Compare(a.rec.ID, b.rec.ID)
	})
	still := make(map[string]bool, len(ready))
	for _, t := range ready {
		still[t.rec.ID] = true
		digest := sha256.Sum256(t.leaf)
		if shown[t.rec.ID] == digest {
			continue
		}
		shown[t.rec.ID] = digest
		due = append(due, readyEvidence(t))
	}
	for id := range shown {
		if !still[id] {
			delete(shown, id)
		}
	}
	return due, d.changed
}

// readyEvidence is what a ready TD last said of itself, as a claim of it is
// answered. The caller holds the lock.
func readyEvidence(t *td) *sessionv1alpha1.Evidence {
	return &sessionv1alpha1.Evidence{
		Certificate: t.leaf, LaunchDocument: t.offered.Launch, LaunchSignature: []byte(t.offered.Signature),
		Events: t.offered.Events, Phase: string(session.PhaseReady), Collateral: t.collateral,
	}
}

// watches reports whether the caller of ctx is one of the binders pool's
// configuration names: the public key of the certificate it presented, whose
// private key the handshake proved it holds, is one of them. Who issued the
// certificate does not matter, and is not checked.
func watches(ctx context.Context, pool *Pool) bool {
	certs := presented(ctx)
	if len(certs) == 0 {
		return false
	}
	digest, err := session.InstanceKeyDigest(certs[0].PublicKey)
	return err == nil && slices.Contains(pool.Binders, digest)
}
