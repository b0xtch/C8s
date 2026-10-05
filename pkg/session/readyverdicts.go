package session

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"sync"
	"time"
)

// maxReadyVerdicts bounds the verdicts a binder keeps on guests it was shown
// and has not been handed: a host can show it any number.
const maxReadyVerdicts = 1024

// RefreshEvery is how often a binder that keeps verdicts refreshes them: see
// ReadyVerdicts.KeepCurrent.
const RefreshEvery = time.Minute

// ReadyVerdicts keeps a binder's verdicts on ready guests it was shown ahead
// of a claim, as a daemon's WatchReady shows a pool's, so that a claim finds
// its guest judged and the binder's check is off the path of a start.
//
// A verdict is kept under the digest of the certificate it was made on, and
// a claimed guest is found by its certificate's digest alone: never by the
// name its host gives it. Everything else is taken from the evidence that
// was judged, and nothing from the claim's. A verdict is used once, and only
// while nothing it rests on has changed: this binder's policy, the time it
// stands for, and the vendor's documents it was made under, which must still
// be the newest its engine holds. Otherwise, and for a guest the binder was
// never shown, the claim's evidence is judged on the path.
//
// Every verdict is made as one that lets a secret go (VerifyReadyToRelease):
// a binder that watches a pool seals what it sends with its binds. Such a
// verdict stands for an hour from when the binder fetched the vendor's
// documents under it, so a binder keeps the evidence it judged and judges it
// again as the documents are replaced, off the path of any claim: see
// Refresh.
type ReadyVerdicts struct {
	engine Engine
	now    func() time.Time

	mu     sync.Mutex
	policy Policy
	// epoch counts the policies this binder has had: a verdict made under
	// an earlier one is none.
	epoch  uint64
	judged map[[sha256.Size]byte]*readyVerdict
}

// readyVerdict is one verdict, or one on its way.
type readyVerdict struct {
	// done is closed once the verdict is made.
	done chan struct{}
	// evidence is what the guest gave and the verdict was made on, kept to
	// be judged again: no document the guest's host relayed is among it.
	evidence *Relayed
	ready    *ReadyTD
	err      error
	// epoch and documents are the binder's policy and its engine's count of
	// the vendor's documents when the verdict was made. settled says that
	// count did not move while it was.
	epoch     uint64
	documents uint64
	settled   bool
	began     time.Time
	took      time.Duration
}

// JudgedReady is a ready guest as ReadyVerdicts.Claimed found it.
type JudgedReady struct {
	*ReadyTD
	// Ahead says the verdict was made before the claim, on evidence the
	// guest gave while it was ready. Took is how long making it took, then
	// or now.
	Ahead bool
	Took  time.Duration
}

// NewReadyVerdicts returns an empty set of verdicts under policy, which is a
// policy for guests nobody has bound.
func NewReadyVerdicts(policy Policy, engine Engine) (*ReadyVerdicts, error) {
	if err := policy.validate(); err != nil {
		return nil, err
	}
	if engine == nil {
		return nil, errors.New("verdicts need an engine to be made with")
	}
	return &ReadyVerdicts{engine: engine, now: time.Now, policy: policy, judged: map[[sha256.Size]byte]*readyVerdict{}}, nil
}

// SetPolicy has the binder judge under policy from now on, and drops every
// verdict it keeps: each was made under the policy before. A change to what
// the binder pins, to the TCB statuses it accepts or to the machines or the
// releases it takes is a change of policy.
func (v *ReadyVerdicts) SetPolicy(policy Policy) error {
	if err := policy.validate(); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.policy, v.epoch = policy, v.epoch+1
	clear(v.judged)
	return nil
}

// documents is the engine's count of the vendor's documents it came to
// hold. An engine that counts none judges by none.
func (v *ReadyVerdicts) documents() uint64 {
	if counter, ok := v.engine.(DocumentCounter); ok {
		return counter.Documents()
	}
	return 0
}

// Judge judges evidence a ready guest gave, and keeps the verdict for the
// claim that hands the binder that guest. Evidence it has a verdict on, or
// is judging, is not judged again. An error is evidence that did not pass,
// or could not be judged: nothing is kept on it.
func (v *ReadyVerdicts) Judge(ctx context.Context, r *Relayed) error {
	digest := sha256.Sum256(r.Certificate)
	v.mu.Lock()
	if kept := v.judged[digest]; kept != nil && (!kept.made() || v.usableLocked(kept)) {
		v.mu.Unlock()
		return nil
	}
	v.evictLocked()
	verdict := &readyVerdict{
		done: make(chan struct{}), epoch: v.epoch, began: v.now(),
		evidence: &Relayed{Certificate: r.Certificate, Phase: r.Phase, Launch: r.Launch, Signature: r.Signature, Events: r.Events},
	}
	v.judged[digest] = verdict
	policy := v.policy
	v.mu.Unlock()

	v.judge(ctx, policy, verdict.evidence, verdict)
	v.mu.Lock()
	// A verdict that failed is none, and neither is one made under a policy
	// the binder has since changed: SetPolicy dropped it from the set.
	if verdict.err != nil && v.judged[digest] == verdict {
		delete(v.judged, digest)
	}
	v.mu.Unlock()
	close(verdict.done)
	return verdict.err
}

// judge makes verdict on r under policy. A verdict made while the engine
// was still taking documents in rests on one or another of them, so it is
// made once more, on an engine that has them all.
func (v *ReadyVerdicts) judge(ctx context.Context, policy Policy, r *Relayed, verdict *readyVerdict) {
	for range 2 {
		before := v.documents()
		began := v.now()
		verdict.ready, verdict.err = VerifyReadyToRelease(ctx, policy, v.engine, r, began)
		verdict.took = v.now().Sub(began)
		verdict.documents = v.documents()
		verdict.settled = verdict.documents == before
		if verdict.err != nil || verdict.settled {
			return
		}
	}
}

func (k *readyVerdict) made() bool {
	select {
	case <-k.done:
		return true
	default:
		return false
	}
}

// usableLocked reports whether a verdict that was made still stands: under
// this policy, within its time, and on the newest documents the engine
// holds. The caller holds the lock.
func (v *ReadyVerdicts) usableLocked(kept *readyVerdict) bool {
	return kept.err == nil && kept.ready != nil && kept.settled && kept.epoch == v.epoch &&
		v.now().Before(kept.ready.Until) && kept.documents == v.documents()
}

// evictLocked makes room for one more verdict: it drops those that no longer
// stand, and then the oldest. The caller holds the lock.
func (v *ReadyVerdicts) evictLocked() {
	if len(v.judged) < maxReadyVerdicts {
		return
	}
	for digest, kept := range v.judged {
		if kept.made() && !v.usableLocked(kept) {
			delete(v.judged, digest)
		}
	}
	for len(v.judged) >= maxReadyVerdicts {
		var oldest [sha256.Size]byte
		var at time.Time
		for digest, kept := range v.judged {
			if at.IsZero() || kept.began.Before(at) {
				oldest, at = digest, kept.began
			}
		}
		delete(v.judged, oldest)
	}
}

// Claimed returns the binder's verdict on the guest a claim handed it, as
// the claim's evidence shows it. A guest judged ahead is found by its
// certificate's digest, and the verdict it is returned with is the one made
// on the evidence that was judged then: whatever else the claim says of the
// guest is not read. A verdict that no longer stands, and a guest the binder
// was never shown, is judged now, on the claim's evidence. Either way the
// verdict leaves the set: a guest is claimed once.
func (v *ReadyVerdicts) Claimed(ctx context.Context, r *Relayed) (*JudgedReady, error) {
	if _, err := x509.ParseCertificate(r.Certificate); err != nil {
		return nil, refuse("the relayed certificate does not parse: %v", err)
	}
	digest := sha256.Sum256(r.Certificate)
	v.mu.Lock()
	kept := v.judged[digest]
	v.mu.Unlock()
	if kept != nil {
		// One on its way is waited for: it began before this claim did.
		select {
		case <-kept.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	v.mu.Lock()
	policy := v.policy
	usable := kept != nil && v.usableLocked(kept)
	if v.judged[digest] == kept {
		delete(v.judged, digest)
	}
	v.mu.Unlock()
	if usable {
		return &JudgedReady{ReadyTD: kept.ready, Ahead: true, Took: kept.took}, nil
	}
	began := v.now()
	ready, err := VerifyReadyToRelease(ctx, policy, v.engine, r, began)
	if err != nil {
		return nil, err
	}
	return &JudgedReady{ReadyTD: ready, Took: v.now().Sub(began)}, nil
}

// Refresh keeps the verdicts current, off the path of any claim. It has the
// engine ask the vendor again for the documents that are due (Renewer), and
// judges again, on the evidence it keeps, every verdict that no longer rests
// on the newest documents the engine holds or that ends within five minutes.
// A guest whose evidence is refused now is dropped. One that could not be
// judged, for want of a document, keeps its verdict for what is left of its
// time. judged is how many verdicts were made anew, and the error a document
// the vendor could not be asked for.
func (v *ReadyVerdicts) Refresh(ctx context.Context) (judged int, err error) {
	if renewer, ok := v.engine.(Renewer); ok {
		err = renewer.Renew(ctx)
	}
	type stale struct {
		digest [sha256.Size]byte
		kept   *readyVerdict
	}
	v.mu.Lock()
	policy, epoch, now := v.policy, v.epoch, v.now()
	var due []stale
	for digest, kept := range v.judged {
		// One on its way is made on what the engine holds now.
		if kept.made() && (!v.usableLocked(kept) || kept.ready.Until.Sub(now) <= RenewAhead) {
			due = append(due, stale{digest, kept})
		}
	}
	v.mu.Unlock()
	for _, d := range due {
		if ctx.Err() != nil {
			return judged, ctx.Err()
		}
		again := &readyVerdict{done: d.kept.done, evidence: d.kept.evidence, epoch: epoch, began: v.now()}
		v.judge(ctx, policy, again.evidence, again)
		var refused *VerificationError
		v.mu.Lock()
		// A claim may have taken the verdict meanwhile, or the policy changed.
		if v.judged[d.digest] == d.kept && v.epoch == epoch {
			switch {
			case again.err == nil:
				v.judged[d.digest] = again
				judged++
			case errors.As(again.err, &refused):
				delete(v.judged, d.digest)
			}
		}
		v.mu.Unlock()
	}
	return judged, err
}

// KeepCurrent refreshes the verdicts every RefreshEvery until ctx ends: what
// a binder runs beside its watch of a pool. refreshed, when set, is told of
// each refresh that judged a verdict anew or could not ask the vendor.
func (v *ReadyVerdicts) KeepCurrent(ctx context.Context, refreshed func(judged int, took time.Duration, err error)) {
	tick := time.NewTicker(RefreshEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		began := time.Now()
		judged, err := v.Refresh(ctx)
		if refreshed != nil && ctx.Err() == nil && (judged > 0 || err != nil) {
			refreshed(judged, time.Since(began), err)
		}
	}
}

// Kept is how many verdicts the binder keeps, made or on their way.
func (v *ReadyVerdicts) Kept() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.judged)
}
