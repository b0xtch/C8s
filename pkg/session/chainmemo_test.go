package session

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// The checks that are the same for every quote of a platform run once, and
// for a short while their outcome stands in for them. What depends on the
// quote itself is checked every time.
func TestChainChecksAreKeptForAPlatform(t *testing.T) {
	env, reportData := fixture(t)
	ctx := lenient()
	k := keptCollateral(t)
	at := k.newest.Add(10 * time.Minute)
	engine := k.engineAt(at, k.intel(true), false)
	first, err := engine.VerifyEvidence(ctx, env, reportData)
	if err != nil {
		t.Fatal(err)
	}
	if hits := engine.chains.hits.Load(); hits != 0 {
		t.Fatalf("the first verification of a platform rested on a memo (%d)", hits)
	}
	second, err := engine.VerifyEvidence(ctx, env, reportData)
	if err != nil || engine.chains.hits.Load() != 1 {
		t.Fatalf("the second verification: %v, after %d memo hits", err, engine.chains.hits.Load())
	}
	// It says what the first said, of the same documents.
	a, b := CollateralOf(first), CollateralOf(second)
	if a == nil || b == nil || a.Platform != b.Platform || a.QuotingEnclave != b.QuotingEnclave ||
		!a.Fetched.Equal(b.Fetched) || !a.Expires.Equal(b.Expires) || a.Stale != b.Stale || !second.CollateralVerified {
		t.Fatalf("findings differ: %+v and %+v", a, b)
	}

	// The memo spares nothing that the quote itself decides. Another binding
	// is refused, and so is a quote changed anywhere: in its body, in its
	// signature, or in what certifies its key, which is another platform to
	// the memo.
	if _, err := engine.VerifyEvidence(ctx, env, make([]byte, len(reportData))); err == nil {
		t.Fatal("evidence was accepted for a binding it does not carry")
	}
	// The header and the body, the signature over them, the attestation
	// key, the quoting enclave's report and its signature, and the PCK
	// certificates. (What follows the last certificate is read by nobody.)
	raw := quoteOf(t, env)
	if len(raw) < 4600 {
		t.Fatalf("fixture: the quote is %d bytes", len(raw))
	}
	for _, offset := range []int{0, 47, 48, 200, 520, 631, 636, 699, 700, 763, 764, 900, 1160, 1300, 2000, 3000, 4500} {
		var refused *VerificationError
		if _, err := engine.VerifyEvidence(ctx, flipQuote(t, env, offset), reportData); !errors.As(err, &refused) {
			t.Errorf("a quote changed at byte %d: %v", offset, err)
		}
	}
	hits := engine.chains.hits.Load()

	// A minute on, the checks run again.
	later := k.engineAt(at, k.intel(true), false)
	clock := at
	later.cache.now = func() time.Time { return clock }
	for range 2 {
		if _, err := later.VerifyEvidence(ctx, env, reportData); err != nil {
			t.Fatal(err)
		}
	}
	if later.chains.hits.Load() != 1 {
		t.Fatalf("within the minute: %d memo hits, want 1", later.chains.hits.Load())
	}
	clock = at.Add(chainMemoFor)
	if _, err := later.VerifyEvidence(ctx, env, reportData); err != nil || later.chains.hits.Load() != 1 {
		t.Fatalf("a minute on: %v, %d memo hits, want the checks run again", err, later.chains.hits.Load())
	}
	// And a clock that went back is no reason to trust a memo from its future.
	clock = at.Add(-time.Second)
	if _, err := later.VerifyEvidence(ctx, env, reportData); err != nil || later.chains.hits.Load() != 1 {
		t.Fatalf("with the clock set back: %v, %d memo hits", err, later.chains.hits.Load())
	}
	if engine.chains.hits.Load() != hits {
		t.Fatal("another engine's verifications counted here")
	}
}

// A memo is of the documents the checks were served. When the engine is
// served another document, the checks run on it: a memo never carries a
// verdict over to documents nobody checked.
func TestChainMemoIsOfItsDocuments(t *testing.T) {
	env, reportData := fixture(t)
	ctx := lenient()
	k := keptCollateral(t)
	at := k.newest.Add(10 * time.Minute)
	service := k.intel(true)
	engine := k.engineAt(at, service, false)
	for range 2 {
		if _, err := engine.VerifyEvidence(ctx, env, reportData); err != nil {
			t.Fatal(err)
		}
	}
	if engine.chains.hits.Load() != 1 {
		t.Fatalf("%d memo hits, want 1", engine.chains.hits.Load())
	}
	// The kept documents change under the engine: one byte of each body.
	// An engine that reads them anew is served other documents than its
	// memo is of. With Intel out of reach it has nothing else, and refuses.
	k.write(t, func(file *collateralFile) {
		body := append([]byte(nil), file.Body...)
		body[len(body)/2] ^= 1
		file.Body = body
	})
	changed := k.engineAt(at, service, false)
	changed.chains.byPlatform = engine.chains.byPlatform
	if _, err := changed.VerifyEvidence(ctx, env, reportData); err == nil {
		t.Fatal("evidence was accepted under documents that were changed after the checks ran")
	}
	if changed.chains.hits.Load() != 0 {
		t.Fatal("a memo stood in for checks of documents it is not of")
	}
}

func quoteOf(t *testing.T, env teetypes.AttestationEvidence) []byte {
	t.Helper()
	var body struct {
		Quote string `json:"quote"`
	}
	if err := json.Unmarshal(env.Evidence, &body); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(body.Quote)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
