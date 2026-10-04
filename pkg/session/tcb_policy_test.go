package session_test

import (
	"context"
	"slices"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// accepting is the test engine that notes which TCB statuses each judgment
// was asked to accept.
type accepting struct {
	sessiontest.Engine
	mu   sync.Mutex
	seen [][]string
}

func (e *accepting) VerifyEvidence(ctx context.Context, env teetypes.AttestationEvidence, reportData []byte) (*teetypes.VerificationResult, error) {
	e.mu.Lock()
	e.seen = append(e.seen, session.AcceptedTCB(ctx))
	e.mu.Unlock()
	return e.Engine.VerifyEvidence(ctx, env, reportData)
}

func (e *accepting) judgments() [][]string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.seen)
}

// What a policy accepts of a platform reaches the engine at every judgment
// under that policy: the certificate at the handshake and the fresh
// attestation alike. A policy that names nothing has the engine accept
// nothing but UpToDate, and a verdict kept under one policy is not taken
// under the other.
func TestPolicyCarriesItsAcceptedTCBToTheEngine(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	lenient := s.policy
	lenient.AcceptTCBStatus = []string{"OutOfDate", "SWHardeningNeeded"}

	for name, policy := range map[string]session.Policy{"a policy that names two": lenient, "a policy that names none": s.policy} {
		engine := &accepting{}
		client, err := session.NewClient("https://"+s.addr, policy, engine, s.signer)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Attest(within(t)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		run(t, client)
		client.Close()
		seen := engine.judgments()
		if len(seen) == 0 {
			t.Fatalf("%s: the engine judged nothing", name)
		}
		for i, accepted := range seen {
			if !slices.Equal(accepted, policy.AcceptTCBStatus) {
				t.Errorf("%s: judgment %d was asked to accept %v", name, i, accepted)
			}
		}
	}

	// The list is the policy's own: changing the caller's slice afterwards
	// changes nothing for a context made from it.
	statuses := []string{"OutOfDate"}
	ctx := session.WithAcceptedTCB(context.Background(), statuses)
	statuses[0] = "SWHardeningNeeded"
	if got := session.AcceptedTCB(ctx); !slices.Equal(got, []string{"OutOfDate"}) {
		t.Fatalf("the context accepts %v", got)
	}
	if got := session.AcceptedTCB(session.WithAcceptedTCB(context.Background(), nil)); got != nil {
		t.Fatalf("a context that names nothing accepts %v", got)
	}

	// A verdict kept under the lenient policy is of no use to the strict one.
	engine := &accepting{}
	client, err := session.NewClient("https://"+s.addr, lenient, engine, s.signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Attest(within(t)); err != nil {
		t.Fatal(err)
	}
	kept, ok := client.Verdict()
	client.Close()
	if !ok {
		t.Fatal("no verdict to keep")
	}
	strict := &accepting{}
	again, err := session.NewClient("https://"+s.addr, s.policy, strict, s.signer, session.Kept(kept))
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	run(t, again)
	if len(strict.judgments()) == 0 {
		t.Fatal("a policy that accepts less took the verdict of one that accepts more")
	}
}

// A policy that names a status nobody can accept is refused before anything
// is sent.
func TestPolicyRefusesAStatusNobodyCanAccept(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	for name, statuses := range map[string][]string{"Revoked": {"Revoked"}, "unsorted": {"SWHardeningNeeded", "OutOfDate"}} {
		policy := s.policy
		policy.AcceptTCBStatus = statuses
		if client, err := session.NewClient("https://"+s.addr, policy, sessiontest.Engine{}, s.signer); err == nil {
			client.Close()
			t.Errorf("a policy that accepts %s made a client", name)
		}
	}
}
