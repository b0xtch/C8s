package podcvm

import (
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

//go:embed testdata/tdx-evidence.json
var fixtureTDXEvidence []byte

type countingGetter struct {
	calls int
	err   error
}

func (g *countingGetter) Get(string) (map[string][]string, []byte, error) {
	g.calls++
	if g.err != nil {
		return nil, nil, g.err
	}
	return map[string][]string{"X": {"1"}}, []byte("body"), nil
}

func TestCachingGetterFetchesEachURLOncePerTTL(t *testing.T) {
	inner := &countingGetter{}
	now := time.Unix(1_700_000_000, 0)
	getter := newCachingGetter(inner)
	getter.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if _, body, err := getter.Get("https://pcs.example/tcb"); err != nil || string(body) != "body" {
			t.Fatalf("get %d: %q, %v", i, body, err)
		}
	}
	if inner.calls != 1 {
		t.Fatalf("one URL fetched %d times within the TTL", inner.calls)
	}
	if _, _, err := getter.Get("https://pcs.example/qe"); err != nil || inner.calls != 2 {
		t.Fatalf("a second URL must be fetched on its own: calls=%d, %v", inner.calls, err)
	}
	now = now.Add(collateralTTL)
	if _, _, err := getter.Get("https://pcs.example/tcb"); err != nil || inner.calls != 3 {
		t.Fatalf("an expired entry must be fetched again: calls=%d, %v", inner.calls, err)
	}
}

func TestCachingGetterDoesNotCacheFailures(t *testing.T) {
	inner := &countingGetter{err: errors.New("pcs is down")}
	getter := newCachingGetter(inner)
	for i := 0; i < 2; i++ {
		if _, _, err := getter.Get("https://pcs.example/tcb"); err == nil {
			t.Fatal("a failed fetch was served from cache")
		}
	}
	if inner.calls != 2 {
		t.Fatalf("failures fetched %d times, want 2", inner.calls)
	}
}

// With collateral required, an unreachable Intel PCS must stop the release and
// must not read as a refusal of the evidence: nothing was learned about it.
func TestCollateralOutageIsNotAVerdict(t *testing.T) {
	var env teetypes.AttestationEvidence
	if err := json.Unmarshal(fixtureTDXEvidence, &env); err != nil {
		t.Fatal(err)
	}
	reportData, err := hex.DecodeString("b8b9e582d1efb326120f7215e75a2ac2327da81aa5b44209f69460ae5af99e00")
	if err != nil {
		t.Fatal(err)
	}
	inner := &countingGetter{err: errors.New("pcs is down")}
	engine := &dcapEngine{collateral: CollateralRequired, getter: newCachingGetter(inner)}

	res, err := engine.VerifyEvidence(context.Background(), env, reportData)
	if err == nil {
		t.Fatalf("verified without collateral: %+v", res)
	}
	var verdict *VerificationError
	if errors.As(err, &verdict) {
		t.Fatalf("a collateral outage was reported as a verdict on the evidence: %v", err)
	}
	if inner.calls == 0 {
		t.Fatal("fixture: the engine never asked for collateral")
	}
}
