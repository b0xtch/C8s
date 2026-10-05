package session

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Evidence that cannot be judged, because Intel cannot be asked and nothing
// was kept, can still be held to what needs none of Intel's documents: its
// signature and its chain to Intel's root, the quoting enclave's and the TDX
// module's identity, and its binding. The engine then asks Intel nothing and
// says nothing of where the platform's TCB stands. What that pass refuses, it
// refuses with a verdict: evidence that was changed, and evidence bound to
// something else.
func TestEvidenceIsHeldWithoutIntelsDocuments(t *testing.T) {
	env, reportData := fixture(t)
	k := keptCollateral(t)
	service := k.intel(true)
	// An engine with nothing kept, and no road to Intel's service.
	cache := newCollateralCache(t.TempDir())
	cache.now = func() time.Time { return k.newest.Add(10 * time.Minute) }
	engine := &dcapEngine{cache: cache, fetch: service}

	if _, err := engine.VerifyEvidence(lenient(), env, reportData); !isOutage(err) {
		t.Fatalf("evidence with no document at hand: %v, want an outage and no verdict", err)
	}
	asked := service.calls
	if asked == 0 {
		t.Fatal("the engine did not ask Intel's service for the documents")
	}

	held := offline(lenient())
	if !Offline(held) || Offline(lenient()) || Offline(context.Background()) {
		t.Fatal("a context says it asks for the offline checks when it does not, or the reverse")
	}
	res, err := engine.VerifyEvidence(held, env, reportData)
	if err != nil {
		t.Fatalf("the same evidence, held to what needs no document: %v", err)
	}
	if res.CollateralVerified || CollateralOf(res) != nil {
		t.Fatalf("a result with no document under it says one was checked: %+v", CollateralOf(res))
	}
	if service.calls != asked {
		t.Fatalf("the engine asked Intel's service %d more times for an offline check", service.calls-asked)
	}

	// Offline or not, the evidence must be the platform's own and bound to
	// what the verifier expects.
	other := append([]byte(nil), reportData...)
	other[0] ^= 1
	if _, err := engine.VerifyEvidence(held, env, other); !isVerdictError(err) {
		t.Errorf("evidence bound to other report data was held: %v", err)
	}
	for name, offset := range map[string]int{
		"a changed header":                 4,
		"a changed TD report":              0x30 + 0x80,
		"a changed register":               0x30 + 0x208,
		"a changed signature":              0x30 + 0x248 + 4 + 8,
		"a changed quoting enclave report": tdQuoteCertificationStart + 0x40 + 6 + 0x40,
	} {
		if _, err := engine.VerifyEvidence(held, flipQuote(t, env, offset), reportData); !isVerdictError(err) {
			t.Errorf("%s was held: %v", name, err)
		}
	}
	if service.calls != asked {
		t.Fatalf("the engine asked Intel's service %d more times while it refused", service.calls-asked)
	}
}

func isVerdictError(err error) bool {
	var verdict *VerificationError
	return errors.As(err, &verdict)
}
