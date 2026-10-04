package session

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
	cache := newCollateralCache("")
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
	recorder := &fetchRecorder{cache: newCollateralCache(""), inner: inner}
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

// An unreachable Intel PCS must stop the release and must not read as a
// refusal of the evidence: nothing was learned about it.
func TestCollateralOutageIsNotAVerdict(t *testing.T) {
	env, reportData := fixture(t)
	inner := &countingGetter{err: errors.New("pcs is down")}
	engine := &dcapEngine{cache: newCollateralCache(""), fetch: inner}

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
	engine := &dcapEngine{cache: newCollateralCache(""), fetch: inner}

	_, err := engine.VerifyEvidence(context.Background(), flipQuote(t, env, signature), reportData)
	var verdict *VerificationError
	if !errors.As(err, &verdict) {
		t.Fatalf("a forged quote must be a verdict, got %v", err)
	}
	if inner.calls != 0 {
		t.Fatalf("collateral was fetched %d times for a quote that fails offline", inner.calls)
	}
}

// A command-line client is a new process for every command. With a cache
// directory the second process fetches nothing, until the documents are an
// hour old.
func TestCollateralIsKeptBetweenProcesses(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "collateral")
	inner := &countingGetter{}
	now := time.Unix(1_700_000_000, 0)
	process := func() *collateralCache {
		cache := newCollateralCache(dir)
		cache.now = func() time.Time { return now }
		return cache
	}
	const url = "https://pcs.example/tcb?fmspc=00a0"

	// A verification that failed leaves no file, as it leaves no entry.
	failed := &fetchRecorder{cache: process(), inner: inner}
	if _, _, err := failed.Get(url); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("a response was written before any verification succeeded with it: %v", entries)
	}

	first := &fetchRecorder{cache: process(), inner: inner}
	if _, _, err := first.Get(url); err != nil {
		t.Fatal(err)
	}
	first.commit()
	if first.fromCache() {
		t.Fatal("a fetched document counts as one from the cache")
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("the cache directory: %v, %v", info, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("the cache directory holds %v, %v", entries, err)
	}
	if file, err := entries[0].Info(); err != nil || file.Mode().Perm() != 0o600 || strings.Contains(entries[0].Name(), "pcs.example") {
		t.Fatalf("the cached file: %v, %v", file, err)
	}

	// Another process, the same directory.
	second := &fetchRecorder{cache: process(), inner: inner}
	header, body, err := second.Get(url)
	if err != nil || string(body) != "body" || header["X"][0] != "1" || !second.fromCache() {
		t.Fatalf("from the directory: %q %v, %v", body, header, err)
	}
	if inner.calls != 2 {
		t.Fatalf("the second process fetched: %d calls in all, want 2", inner.calls)
	}
	// Another document is not this one.
	if _, _, err := second.Get(url + "1"); err != nil || inner.calls != 3 {
		t.Fatalf("a document nobody cached was served from the cache: calls=%d, %v", inner.calls, err)
	}

	now = now.Add(collateralTTL)
	third := &fetchRecorder{cache: process(), inner: inner}
	if _, _, err := third.Get(url); err != nil || inner.calls != 4 || third.fromCache() {
		t.Fatalf("a document an hour old must be fetched again: calls=%d, %v", inner.calls, err)
	}
}

// The directory is trusted for nothing. A file that is not an entry for the
// document asked for is no entry.
func TestCollateralFileThatIsNoEntry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	const url = "https://pcs.example/tcb"
	entry := collateralFile{URL: url, Fetched: now, Header: map[string][]string{"X": {"1"}}, Body: []byte("body")}
	for name, damage := range map[string]func(*collateralFile) []byte{
		"control":               func(f *collateralFile) []byte { return nil },
		"not json":              func(f *collateralFile) []byte { return []byte("{") },
		"another document":      func(f *collateralFile) []byte { f.URL = url + "/other"; return nil },
		"no body":               func(f *collateralFile) []byte { f.Body = nil; return nil },
		"fetched in the future": func(f *collateralFile) []byte { f.Fetched = now.Add(time.Minute); return nil },
		"an hour old":           func(f *collateralFile) []byte { f.Fetched = now.Add(-collateralTTL); return nil },
		"too large":             func(f *collateralFile) []byte { f.Body = make([]byte, maxCollateralFile); return nil },
	} {
		t.Run(name, func(t *testing.T) {
			cache := newCollateralCache(t.TempDir())
			cache.now = func() time.Time { return now }
			file := entry
			data := damage(&file)
			if data == nil {
				var err error
				if data, err = json.Marshal(file); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(cache.path(url), data, 0o600); err != nil {
				t.Fatal(err)
			}
			got, ok := cache.lookup(url)
			if want := name == "control"; ok != want || (ok && string(got.body) != "body") {
				t.Fatalf("lookup = %q, %v, want an entry: %v", got.body, ok, want)
			}
		})
	}
}

// Collateral from the cache that does not verify is no verdict on the
// evidence: it is fetched anew, once, and that run decides. What is fetched
// anew replaces what the cache held.
func TestCachedCollateralThatFailsIsFetchedAnew(t *testing.T) {
	// The one of Intel's documents an engine takes in any shape.
	const url = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"
	now := time.Unix(1_700_000_000, 0)
	cached := func(t *testing.T) *dcapEngine {
		cache := newCollateralCache(t.TempDir())
		cache.now = func() time.Time { return now }
		cache.store(url, collateralEntry{body: []byte("damaged"), fetched: now})
		return &dcapEngine{cache: cache, fetch: &countingGetter{}}
	}
	// check passes for the body the getter serves and fails for any other.
	check := func(runs *int, failure error) func(*fetchRecorder) error {
		return func(fetches *fetchRecorder) error {
			*runs++
			_, body, err := fetches.Get(url)
			if err != nil {
				return errors.New("unable to receive tcbInfo: " + err.Error())
			}
			if string(body) != "body" {
				return failure
			}
			return nil
		}
	}

	t.Run("a damaged entry", func(t *testing.T) {
		engine, runs := cached(t), 0
		fetches, err := engine.withCollateral(context.Background(), check(&runs, errors.New("tcbInfo signature does not verify")))
		if err != nil || runs != 2 || engine.fetch.(*countingGetter).calls != 1 || fetches.fromCache() {
			t.Fatalf("err %v after %d runs and %d fetches", err, runs, engine.fetch.(*countingGetter).calls)
		}
		fetches.commit()
		if entry, ok := engine.cache.lookup(url); !ok || string(entry.body) != "body" {
			t.Fatalf("the cache still holds %q", entry.body)
		}
	})
	t.Run("a damaged entry and no way to fetch", func(t *testing.T) {
		engine, runs := cached(t), 0
		engine.fetch = &countingGetter{err: errors.New("pcs is down")}
		fetches, err := engine.withCollateral(context.Background(), check(&runs, errors.New("tcbInfo signature does not verify")))
		if err == nil || runs != 2 || !fetches.caused(err) {
			t.Fatalf("err %v after %d runs: an outage must read as one, not as a verdict", err, runs)
		}
	})
	t.Run("nothing from the cache", func(t *testing.T) {
		engine, runs := &dcapEngine{cache: newCollateralCache(""), fetch: &countingGetter{}}, 0
		failing := func(fetches *fetchRecorder) error {
			runs++
			_, _, _ = fetches.Get(url)
			return errors.New("tcbInfo signature does not verify")
		}
		if _, err := engine.withCollateral(context.Background(), failing); err == nil || runs != 1 {
			t.Fatalf("err %v after %d runs: what was just fetched is not fetched again", err, runs)
		}
	})
}
