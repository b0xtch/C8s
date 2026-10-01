package podcvm

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

//go:embed testdata/tdx-evidence.json
var fixtureTDXEvidence []byte

func fixture(t *testing.T) (teetypes.AttestationEvidence, []byte) {
	t.Helper()
	var env teetypes.AttestationEvidence
	if err := json.Unmarshal(fixtureTDXEvidence, &env); err != nil {
		t.Fatal(err)
	}
	reportData, err := hex.DecodeString("b8b9e582d1efb326120f7215e75a2ac2327da81aa5b44209f69460ae5af99e00")
	if err != nil {
		t.Fatal(err)
	}
	return env, reportData
}

// flipQuote returns the fixture with one bit of its quote changed at offset.
func flipQuote(t *testing.T, env teetypes.AttestationEvidence, offset int) teetypes.AttestationEvidence {
	t.Helper()
	var body struct {
		Quote string `json:"quote"`
	}
	if err := json.Unmarshal(env.Evidence, &body); err != nil {
		t.Fatal(err)
	}
	quote, err := base64.StdEncoding.DecodeString(body.Quote)
	if err != nil {
		t.Fatal(err)
	}
	quote[offset] ^= 1
	body.Quote = base64.StdEncoding.EncodeToString(quote)
	if env.Evidence, err = json.Marshal(body); err != nil {
		t.Fatal(err)
	}
	return env
}

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

func TestCollateralIsCachedOnlyAfterItVerified(t *testing.T) {
	inner := &countingGetter{}
	now := time.Unix(1_700_000_000, 0)
	cache := newCollateralCache()
	cache.now = func() time.Time { return now }
	const url = "https://pcs.example/tcb"

	// A verification that fetched and then failed leaves nothing behind.
	failed := &fetchRecorder{cache: cache, inner: inner}
	if _, body, err := failed.Get(url); err != nil || string(body) != "body" {
		t.Fatalf("fetch: %q, %v", body, err)
	}
	if _, ok := cache.lookup(url); ok {
		t.Fatal("a response was cached before any verification succeeded with it")
	}

	// One that succeeded publishes what it fetched.
	passed := &fetchRecorder{cache: cache, inner: inner}
	if _, _, err := passed.Get(url); err != nil {
		t.Fatal(err)
	}
	passed.commit()
	later := &fetchRecorder{cache: cache, inner: inner}
	for i := 0; i < 3; i++ {
		if _, _, err := later.Get(url); err != nil {
			t.Fatal(err)
		}
	}
	if inner.calls != 2 {
		t.Fatalf("inner getter was asked %d times, want 2 (cached reads must not fetch)", inner.calls)
	}
	now = now.Add(collateralTTL)
	if _, _, err := later.Get(url); err != nil || inner.calls != 3 {
		t.Fatalf("an expired entry must be fetched again: calls=%d, %v", inner.calls, err)
	}
}

func TestFetchRecorderRecognisesItsOwnFailures(t *testing.T) {
	inner := &countingGetter{err: errors.New("pcs is down")}
	recorder := &fetchRecorder{cache: newCollateralCache(), inner: inner}
	_, _, err := recorder.Get("https://pcs.example/tcb")
	if err == nil {
		t.Fatal("a failed fetch succeeded")
	}
	// go-tdx-guest flattens the error into text; the recorder must still know it.
	flattened := errors.New("unable to receive tcbInfo: " + err.Error())
	if !recorder.caused(flattened) {
		t.Fatal("a verification error caused by a failed fetch was not recognised")
	}
	if recorder.caused(errors.New("TDX TCB status is OutOfDate")) || recorder.caused(nil) {
		t.Fatal("an unrelated error was attributed to a fetch")
	}
	recorder.commit()
	if _, ok := recorder.cache.lookup("https://pcs.example/tcb"); ok {
		t.Fatal("a failed fetch was cached")
	}
}

// With collateral required, an unreachable Intel PCS must stop the release and
// must not read as a refusal of the evidence: nothing was learned about it.
func TestCollateralOutageIsNotAVerdict(t *testing.T) {
	env, reportData := fixture(t)
	inner := &countingGetter{err: errors.New("pcs is down")}
	engine := &dcapEngine{collateral: CollateralRequired, cache: newCollateralCache(), fetch: inner}

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

// A quote that does not verify offline is refused before anything is fetched.
// The lookup is keyed on fields of the PCK certificate, so fetching first would
// let a forged quote choose the request and turn its refusal into an outage.
func TestForgedQuoteIsRefusedBeforeAnyFetch(t *testing.T) {
	env, reportData := fixture(t)
	const signature = 48 + 584 + 4
	inner := &countingGetter{err: errors.New("pcs is down")}
	engine := &dcapEngine{collateral: CollateralRequired, cache: newCollateralCache(), fetch: inner}

	_, err := engine.VerifyEvidence(context.Background(), flipQuote(t, env, signature), reportData)
	var verdict *VerificationError
	if !errors.As(err, &verdict) {
		t.Fatalf("a forged quote must be a verdict, got %v", err)
	}
	if inner.calls != 0 {
		t.Fatalf("collateral was fetched %d times for a quote that fails offline", inner.calls)
	}
}

// A PCK chain alone does not say which enclave signed a quote. Each field that
// identifies Intel's production TD quoting enclave, and the TDX module's
// signer, must be what Intel publishes.
func TestQuoteOriginIsPinned(t *testing.T) {
	env, _ := fixture(t)
	if err := checkTDQuoteOrigin(env.Evidence); err != nil {
		t.Fatalf("control: a genuine quote was refused: %v", err)
	}
	// Offsets into a v4 quote: 48-byte header, 584-byte TD report body, a
	// 4-byte length, the 64-byte signature and 64-byte attestation key, then
	// 6 bytes of certification header before the 384-byte QE report.
	const (
		body     = 48
		qeReport = 48 + 584 + 4 + 64 + 64 + 6
	)
	for name, tc := range map[string]struct {
		bent teetypes.AttestationEvidence
		want string
	}{
		"another enclave signer":        {flipQuote(t, env, qeReport+128), "not Intel's TD quoting enclave"},
		"another Intel enclave product": {flipQuote(t, env, qeReport+256), "enclave product"},
		// INIT, DEBUG, MODE64BIT and PROVISION_KEY: the genuine flags plus DEBUG.
		"debug quoting enclave":          {setQuoteByte(t, env, qeReport+48, 0x17), "not the production TD quoting enclave"},
		"quoting enclave MISCSELECT set": {flipQuote(t, env, qeReport+16), "MISCSELECT"},
		"TDX module from another signer": {flipQuote(t, env, body+64), "TDX module signer"},
		"TDX module attributes set":      {flipQuote(t, env, body+112), "TDX module attributes"},
	} {
		t.Run(name, func(t *testing.T) {
			err := checkTDQuoteOrigin(tc.bent.Evidence)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want a refusal mentioning %q, got %v", tc.want, err)
			}
		})
	}
}

func setQuoteByte(t *testing.T, env teetypes.AttestationEvidence, offset int, value byte) teetypes.AttestationEvidence {
	t.Helper()
	var body struct {
		Quote string `json:"quote"`
	}
	if err := json.Unmarshal(env.Evidence, &body); err != nil {
		t.Fatal(err)
	}
	quote, err := base64.StdEncoding.DecodeString(body.Quote)
	if err != nil {
		t.Fatal(err)
	}
	quote[offset] = value
	body.Quote = base64.StdEncoding.EncodeToString(quote)
	if env.Evidence, err = json.Marshal(body); err != nil {
		t.Fatal(err)
	}
	return env
}
