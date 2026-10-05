package session_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// counted is an engine that counts what it is asked to verify and says how
// many of the vendor's documents it holds. With hold set, a verification
// waits there until the test lets it go.
type counted struct {
	session.Engine
	asked     atomic.Int64
	documents atomic.Uint64
	// taking, when set, is how many documents each of that many next
	// verifications takes in while it runs.
	taking atomic.Int64
	hold   chan struct{}
	inside chan struct{}
	// context is the last context a verification ran under.
	mu      sync.Mutex
	context context.Context //nolint:containedctx // what a test reads back
}

func (e *counted) VerifyEvidence(ctx context.Context, env teetypes.AttestationEvidence, reportData []byte) (*teetypes.VerificationResult, error) {
	e.asked.Add(1)
	e.mu.Lock()
	e.context = ctx
	e.mu.Unlock()
	if e.taking.Add(-1) >= 0 {
		e.documents.Add(1)
	}
	if e.hold != nil {
		e.inside <- struct{}{}
		select {
		case <-e.hold:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return e.Engine.VerifyEvidence(ctx, env, reportData)
}

func (e *counted) Documents() uint64 { return e.documents.Load() }

func newCounted() *counted { return &counted{Engine: sessiontest.Engine{}} }

func keyDigest(t *testing.T, key crypto.PublicKey) string {
	t.Helper()
	digest, err := session.InstanceKeyDigest(key)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func watching(t *testing.T, s *served, engine session.Engine) *session.ReadyVerdicts {
	t.Helper()
	verdicts, err := session.NewReadyVerdicts(s.policy, engine)
	if err != nil {
		t.Fatal(err)
	}
	return verdicts
}

// A binder that was shown a ready guest ahead of its claim finds it judged
// when the claim hands it over: by its certificate's digest alone, with
// everything else taken from the evidence that was judged and nothing from
// the claim's. The verdict is used once, and is one that lets a secret go.
func TestClaimFindsAGuestJudgedAheadByItsCertificate(t *testing.T) {
	s := serveReady(t, sessiontest.NewTD())
	engine := newCounted()
	verdicts := watching(t, s, engine)
	shown := relayedState(t, s)
	if err := verdicts.Judge(within(t), shown); err != nil {
		t.Fatalf("Judge: %v", err)
	}
	if engine.asked.Load() != 1 || verdicts.Kept() != 1 {
		t.Fatalf("after one guest was shown the engine was asked %d times, and %d verdicts are kept", engine.asked.Load(), verdicts.Kept())
	}
	// A verdict made to release: the root CA CRL under it is not one the
	// guest's host handed over.
	if session.MayStapleRoot(engine.context) {
		t.Fatal("a verdict made ahead may rest on a root CA CRL that was handed over")
	}
	// Shown again, it is not judged again.
	if err := verdicts.Judge(within(t), shown); err != nil || engine.asked.Load() != 1 {
		t.Fatalf("the same guest shown again: %v, the engine asked %d times", err, engine.asked.Load())
	}

	// The claim names its guest by a certificate, and says of it whatever
	// its host likes: another launch document, another phase, other events.
	claim := &session.Relayed{
		Certificate: shown.Certificate, Phase: session.PhaseRunning, Launch: []byte("another document"),
		Signature: "another signature", Events: []string{"sha256:another"}, Bind: []byte("a bind"),
	}
	judged, err := verdicts.Claimed(within(t), claim)
	if err != nil {
		t.Fatalf("Claimed: %v", err)
	}
	if !judged.Ahead || engine.asked.Load() != 1 {
		t.Fatalf("a guest judged ahead was judged on the path: ahead %t, the engine asked %d times", judged.Ahead, engine.asked.Load())
	}
	want, err := session.VerifyReadyToRelease(within(t), s.policy, sessiontest.Engine{}, shown, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if string(judged.Launch) != string(shown.Launch) || judged.Signature != shown.Signature ||
		!bytes.Equal(judged.OneTime.KEM, want.OneTime.KEM) || !bytes.Equal(judged.OneTime.Signing, want.OneTime.Signing) ||
		keyDigest(t, judged.InstanceKey) != keyDigest(t, want.InstanceKey) {
		t.Fatal("the verdict on a claimed guest is not the one made on the evidence that was judged")
	}
	if !judged.Until.After(time.Now()) {
		t.Fatalf("a verdict made ahead lets nothing be sealed: until %s", judged.Until)
	}
	if _, err := session.SealWithBind(judged.ReadyTD, bindFor(t, s, judged.ReadyTD), s.signer, session.SealedParts{Command: &session.ExecRequest{Argv: []string{"/bin/true"}}}); err != nil {
		t.Fatalf("sealing on a verdict made ahead: %v", err)
	}

	// Used once: the same claim again is judged on what it says itself.
	if verdicts.Kept() != 0 {
		t.Fatalf("%d verdicts are kept after the claim", verdicts.Kept())
	}
	if again, err := verdicts.Claimed(within(t), claim); !isVerdict(err) {
		t.Fatalf("the claim's own words passed as a ready guest's: %+v, %v", again, err)
	}
	// A guest the binder was never shown is judged on the path.
	late, err := verdicts.Claimed(within(t), shown)
	if err != nil || late.Ahead || engine.asked.Load() != 2 {
		t.Fatalf("a guest never shown: %v, ahead %t, the engine asked %d times", err, late != nil && late.Ahead, engine.asked.Load())
	}
}

// A verdict made ahead is reused only while nothing under it has changed:
// the vendor's documents its engine holds, the time it stands for, and the
// binder's own policy. Otherwise the claim's evidence is judged on the path.
func TestVerdictMadeAheadIsReusedOnlyWhileItStands(t *testing.T) {
	s := serveReady(t, sessiontest.NewTD())
	shown := relayedState(t, s)

	t.Run("the engine took in another document", func(t *testing.T) {
		engine := newCounted()
		verdicts := watching(t, s, engine)
		if err := verdicts.Judge(within(t), shown); err != nil {
			t.Fatal(err)
		}
		engine.documents.Add(1)
		judged, err := verdicts.Claimed(within(t), shown)
		if err != nil || judged.Ahead || engine.asked.Load() != 2 {
			t.Fatalf("after a new document: %v, ahead %t, the engine asked %d times", err, judged != nil && judged.Ahead, engine.asked.Load())
		}
		// Shown again once that verdict is spent, the guest is judged anew.
		if err := verdicts.Judge(within(t), shown); err != nil || engine.asked.Load() != 3 {
			t.Fatalf("shown again: %v, the engine asked %d times", err, engine.asked.Load())
		}
		engine.documents.Add(1)
		// A verdict that no longer stands is no reason not to judge again.
		if err := verdicts.Judge(within(t), shown); err != nil || engine.asked.Load() != 4 {
			t.Fatalf("shown again after another document: %v, the engine asked %d times", err, engine.asked.Load())
		}
	})

	t.Run("the engine was still taking documents in", func(t *testing.T) {
		engine := newCounted()
		// The first verification takes a document in while it runs: its
		// verdict rests on one set or another, so it is made once more.
		engine.taking.Store(1)
		verdicts := watching(t, s, engine)
		if err := verdicts.Judge(within(t), shown); err != nil || engine.asked.Load() != 2 {
			t.Fatalf("Judge: %v, the engine asked %d times", err, engine.asked.Load())
		}
		if judged, err := verdicts.Claimed(within(t), shown); err != nil || !judged.Ahead || engine.asked.Load() != 2 {
			t.Fatalf("a verdict made twice over: %v, the engine asked %d times", err, engine.asked.Load())
		}
		// An engine that takes one in every time gives no verdict to keep.
		engine.taking.Store(1 << 30)
		if err := verdicts.Judge(within(t), shown); err != nil {
			t.Fatal(err)
		}
		before := engine.asked.Load()
		if judged, err := verdicts.Claimed(within(t), shown); err != nil || judged.Ahead || engine.asked.Load() != before+1 {
			t.Fatalf("a verdict made while documents kept coming was reused: %v", err)
		}
	})

	t.Run("its time is up", func(t *testing.T) {
		engine := newCounted()
		verdicts := watching(t, s, engine)
		now := time.Now()
		clock := now
		verdicts.SetClock(func() time.Time { return clock })
		if err := verdicts.Judge(within(t), shown); err != nil {
			t.Fatal(err)
		}
		clock = now.Add(session.ServingVerdictTTL - time.Second)
		if judged, err := verdicts.Claimed(within(t), shown); err != nil || !judged.Ahead {
			t.Fatalf("a verdict within its time: %v", err)
		}
		clock = now
		if err := verdicts.Judge(within(t), shown); err != nil {
			t.Fatal(err)
		}
		clock = now.Add(session.ServingVerdictTTL)
		if judged, err := verdicts.Claimed(within(t), shown); err != nil || judged.Ahead {
			t.Fatalf("a verdict past its time was reused: %v", err)
		}
	})

	t.Run("the binder changed its policy", func(t *testing.T) {
		engine := newCounted()
		verdicts := watching(t, s, engine)
		if err := verdicts.Judge(within(t), shown); err != nil {
			t.Fatal(err)
		}
		// The same pins again are a change all the same: nothing here tells
		// two policies apart.
		if err := verdicts.SetPolicy(s.policy); err != nil || verdicts.Kept() != 0 {
			t.Fatalf("SetPolicy: %v, %d verdicts kept", err, verdicts.Kept())
		}
		if judged, err := verdicts.Claimed(within(t), shown); err != nil || judged.Ahead || engine.asked.Load() != 2 {
			t.Fatalf("a verdict of the policy before was reused: %v", err)
		}
		// A policy that takes another image refuses the guest at its claim.
		other := s.policy
		other.LaunchKey = []byte(keyPEM(t, newKey(t)))
		if err := verdicts.Judge(within(t), shown); err != nil {
			t.Fatal(err)
		}
		if err := verdicts.SetPolicy(other); err != nil {
			t.Fatal(err)
		}
		if judged, err := verdicts.Claimed(within(t), shown); !isVerdict(err) {
			t.Fatalf("a guest of a pool the binder no longer pins: %+v, %v", judged, err)
		}
		if err := verdicts.SetPolicy(session.Policy{}); err == nil {
			t.Fatal("a policy that pins nothing was taken")
		}
	})

	t.Run("it rests on a root CA CRL somebody handed over", func(t *testing.T) {
		engine := resting{sessiontest.Engine{}, &session.CollateralFinding{RootCRLStapled: true, Expires: time.Now().Add(time.Hour)}}
		verdicts := watching(t, s, engine)
		if err := verdicts.Judge(within(t), shown); err != nil {
			t.Fatal(err)
		}
		judged, err := verdicts.Claimed(within(t), shown)
		if err != nil || judged.Ahead || !judged.Until.IsZero() {
			t.Fatalf("a verdict nothing may be sealed on was kept for a claim: %v", err)
		}
	})
}

// A claim that comes while its guest is being judged waits for that verdict,
// and judges nothing a second time. A policy changed meanwhile leaves the
// verdict unused.
func TestClaimWaitsForAVerdictOnItsWay(t *testing.T) {
	s := serveReady(t, sessiontest.NewTD())
	shown := relayedState(t, s)
	engine := newCounted()
	engine.hold, engine.inside = make(chan struct{}), make(chan struct{}, 4)
	verdicts := watching(t, s, engine)
	judging := make(chan error, 1)
	go func() { judging <- verdicts.Judge(within(t), shown) }()
	<-engine.inside
	type claimed struct {
		judged *session.JudgedReady
		err    error
	}
	claim := make(chan claimed, 1)
	go func() {
		judged, err := verdicts.Claimed(within(t), shown)
		claim <- claimed{judged, err}
	}()
	select {
	case early := <-claim:
		t.Fatalf("a claim did not wait for the verdict on its way: %+v, %v", early.judged, early.err)
	case <-time.After(50 * time.Millisecond):
	}
	// A claim whose caller gives up leaves the verdict to whoever comes next.
	gone, cancel := context.WithCancel(within(t))
	cancel()
	if _, err := verdicts.Claimed(gone, shown); !errors.Is(err, context.Canceled) {
		t.Fatalf("a claim whose caller left: %v", err)
	}
	close(engine.hold)
	if err := <-judging; err != nil {
		t.Fatal(err)
	}
	got := <-claim
	if got.err != nil || !got.judged.Ahead || engine.asked.Load() != 1 {
		t.Fatalf("the claim that waited: %v, the engine asked %d times", got.err, engine.asked.Load())
	}
}

// A verdict that was on its way when the binder changed its policy is one of
// the policy before: it is not kept, and the claim that waited for it judges
// its guest under the policy the binder has now.
func TestVerdictOnItsWayIsDroppedWhenThePolicyChanges(t *testing.T) {
	s := serveReady(t, sessiontest.NewTD())
	shown := relayedState(t, s)
	engine := newCounted()
	engine.hold, engine.inside = make(chan struct{}), make(chan struct{}, 4)
	verdicts := watching(t, s, engine)
	judging := make(chan error, 1)
	go func() { judging <- verdicts.Judge(within(t), shown) }()
	<-engine.inside
	claim := make(chan *session.JudgedReady, 1)
	go func() {
		judged, err := verdicts.Claimed(within(t), shown)
		if err != nil {
			t.Errorf("the claim that waited: %v", err)
		}
		claim <- judged
	}()
	time.Sleep(20 * time.Millisecond)
	if err := verdicts.SetPolicy(s.policy); err != nil {
		t.Fatal(err)
	}
	close(engine.hold)
	if err := <-judging; err != nil {
		t.Fatal(err)
	}
	if judged := <-claim; judged == nil || judged.Ahead || engine.asked.Load() != 2 {
		t.Fatalf("a verdict of the policy before was used: the engine was asked %d times", engine.asked.Load())
	}
	if verdicts.Kept() != 0 {
		t.Fatalf("%d verdicts of the policy before are kept", verdicts.Kept())
	}
}

// Evidence that does not pass leaves no verdict, and neither does what is no
// evidence: the claim that names such a guest is judged, and refused, on the
// path. A binder keeps no more verdicts than its bound, however many guests
// its host shows it: the oldest go first.
func TestVerdictsAreKeptOnlyOnWhatPassedAndWithinABound(t *testing.T) {
	s := serveReady(t, sessiontest.NewTD())
	shown := relayedState(t, s)
	engine := newCounted()
	verdicts := watching(t, s, engine)

	bound := *shown
	bound.Phase, bound.Bind = session.PhaseRunning, []byte("a bind")
	if err := verdicts.Judge(within(t), &bound); !isVerdict(err) {
		t.Fatalf("a guest that says it is bound: %v", err)
	}
	other := s.policy
	other.LaunchKey = []byte(keyPEM(t, newKey(t)))
	elsewhere := watching(t, s, engine)
	if err := elsewhere.SetPolicy(other); err != nil {
		t.Fatal(err)
	}
	if err := elsewhere.Judge(within(t), shown); !isVerdict(err) || elsewhere.Kept() != 0 {
		t.Fatalf("a guest of another pool: %v, %d verdicts kept", err, elsewhere.Kept())
	}
	for name, evidence := range map[string]*session.Relayed{
		"no certificate":         {Launch: shown.Launch, Signature: shown.Signature, Events: shown.Events, Phase: shown.Phase},
		"what is no certificate": {Certificate: []byte("certificate"), Launch: shown.Launch, Signature: shown.Signature, Events: shown.Events, Phase: shown.Phase},
	} {
		if err := verdicts.Judge(within(t), evidence); !isVerdict(err) {
			t.Errorf("%s was judged: %v", name, err)
		}
		if _, err := verdicts.Claimed(within(t), evidence); !isVerdict(err) {
			t.Errorf("%s was claimed: %v", name, err)
		}
	}
	if verdicts.Kept() != 0 {
		t.Fatalf("%d verdicts are kept on evidence that did not pass", verdicts.Kept())
	}

	digests := session.FillReadyVerdicts(verdicts, session.MaxReadyVerdicts)
	if err := verdicts.Judge(within(t), shown); err != nil {
		t.Fatal(err)
	}
	if verdicts.Kept() != session.MaxReadyVerdicts {
		t.Fatalf("%d verdicts are kept, and the bound is %d", verdicts.Kept(), session.MaxReadyVerdicts)
	}
	if verdicts.KeepsReadyVerdict(digests[0]) || !verdicts.KeepsReadyVerdict(digests[1]) || !verdicts.KeepsReadyVerdict(sha256.Sum256(shown.Certificate)) {
		t.Fatal("room for a new verdict was not made by dropping the oldest")
	}
	// Those that no longer stand go before any that does.
	engine.documents.Add(1)
	if err := verdicts.Judge(within(t), shown); err != nil {
		t.Fatal(err)
	}
	if verdicts.Kept() != 1 {
		t.Fatalf("%d verdicts are kept once none of the old ones stands", verdicts.Kept())
	}
}
