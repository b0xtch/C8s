//go:build c8s_simtee

package session

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/pcs"

	"github.com/confidential-dot-ai/c8s/internal/simtee"
)

// The engine a development build makes for a simulated TEE judges that
// TEE's evidence through whoever serves its authority's documents, refuses
// a real TD's, and says in what scopes its verdicts that it is one.
func TestNewSimulatedEngineJudgesUnderTheSimulatedAuthorityAlone(t *testing.T) {
	s := newSimulated(t)
	built, err := NewSimulatedEngine(EngineOptions{}, s.authority.Root.Cert, s.vendor)
	if err != nil {
		t.Fatal(err)
	}
	engine := built.(*dcapEngine)
	engine.cache.now = func() time.Time { return s.now }
	env := s.evidence(t, simulatedReportData)
	res, err := engine.VerifyEvidence(context.Background(), env, simulatedReportData)
	if err != nil {
		t.Fatalf("a simulated quote under its own authority: %v", err)
	}
	if finding := CollateralOf(res); finding == nil || !finding.UpToDate() || finding.Stapled || !res.CollateralVerified {
		t.Fatalf("finding %+v", CollateralOf(res))
	}
	asked := s.vendor.Asked()
	slices.Sort(asked)
	want := []string{pcs.PckCrlURL("platform"), pcs.QeIdentityURL(), pcs.TcbInfoURL(simtee.FMSPC), simtee.RootCRLURL}
	slices.Sort(want)
	if !slices.Equal(asked, want) {
		t.Fatalf("the engine asked the simulated vendor for %v", asked)
	}
	if !strings.Contains(engine.Requirements(), "simulated-tee") {
		t.Fatalf("an engine that judges a simulated TEE says it requires %q", engine.Requirements())
	}
	var verdict *VerificationError
	real, reportData := fixture(t)
	if res, err := built.VerifyEvidence(lenient(), real, reportData); !errors.As(err, &verdict) || res != nil {
		t.Fatalf("an engine built for a simulated TEE took a real TD's evidence: %+v, %v", res, err)
	}
	// Another authority's platform is nothing to this one.
	other := newSimulated(t)
	if res, err := built.VerifyEvidence(context.Background(), other.evidence(t, simulatedReportData), simulatedReportData); !errors.As(err, &verdict) || res != nil {
		t.Fatalf("an engine took a quote under another simulated authority: %+v, %v", res, err)
	}
}

// An engine is given the authority it judges under and whoever answers for
// that authority's documents, or it is not made. One that asks nobody needs
// no one to ask, and asks no one.
func TestNewSimulatedEngineNeedsItsAuthority(t *testing.T) {
	s := newSimulated(t)
	if _, err := NewSimulatedEngine(EngineOptions{}, nil, s.vendor); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("an engine with no authority: %v", err)
	}
	if _, err := NewSimulatedEngine(EngineOptions{}, s.authority.Root.Cert, nil); err == nil || !strings.Contains(err.Error(), "serves") {
		t.Fatalf("an engine that fetches, with nobody to ask: %v", err)
	}
	handed, err := NewSimulatedEngine(EngineOptions{HandedCollateralOnly: true}, s.authority.Root.Cert, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine := handed.(*dcapEngine)
	engine.cache.now = func() time.Time { return s.now }
	if _, none := engine.fetch.(noRoad); !none {
		t.Fatalf("an engine that asks nobody fetches through %T", engine.fetch)
	}
	env := s.evidence(t, simulatedReportData)
	// With nothing handed over it has no verdict, and with the host's copies
	// it has one, as a guest's engine does on TDX.
	if _, err := handed.VerifyEvidence(context.Background(), env, simulatedReportData); err == nil {
		t.Fatal("an engine that asks nobody judged with no documents")
	}
	ctx := AllowHandedDocuments(WithCollateralSource(context.Background(), func(context.Context) []CollateralDocument { return s.handed(t) }))
	if _, err := handed.VerifyEvidence(ctx, env, simulatedReportData); err != nil {
		t.Fatalf("an engine that asks nobody, with the documents handed over: %v", err)
	}
	if len(s.vendor.Asked()) != 4 {
		t.Fatalf("the simulated vendor was asked %d times: only the test's own four", len(s.vendor.Asked()))
	}
}

// The simulated authority's documents have the addresses of the vendor's
// own, so an engine keeps them apart: in a directory named for the
// authority, under the one it was given.
func TestSimulatedDocumentsAreKeptApartFromTheVendors(t *testing.T) {
	s := newSimulated(t)
	dir := t.TempDir()
	built, err := NewSimulatedEngine(EngineOptions{CollateralCacheDir: dir}, s.authority.Root.Cert, s.vendor)
	if err != nil {
		t.Fatal(err)
	}
	built.(*dcapEngine).cache.now = func() time.Time { return s.now }
	if _, err := built.VerifyEvidence(context.Background(), s.evidence(t, simulatedReportData), simulatedReportData); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !entries[0].IsDir() || !strings.HasPrefix(entries[0].Name(), "simulated-") || len(entries[0].Name()) != len("simulated-")+16 {
		t.Fatalf("the cache directory holds %v", entries)
	}
	kept, err := filepath.Glob(filepath.Join(dir, entries[0].Name(), "*.json"))
	if err != nil || len(kept) != 4 {
		t.Fatalf("the authority's directory keeps %d documents (%v)", len(kept), err)
	}
	// Another authority's are kept elsewhere again.
	other := newSimulated(t)
	second, err := NewSimulatedEngine(EngineOptions{CollateralCacheDir: dir}, other.authority.Root.Cert, other.vendor)
	if err != nil {
		t.Fatal(err)
	}
	if first := built.(*dcapEngine).cache.dir; first == second.(*dcapEngine).cache.dir || filepath.Dir(first) != dir {
		t.Fatalf("two authorities' documents are kept in %s and %s", first, second.(*dcapEngine).cache.dir)
	}
	// An engine that keeps nothing between processes keeps nothing here.
	none, err := NewSimulatedEngine(EngineOptions{}, s.authority.Root.Cert, s.vendor)
	if err != nil || none.(*dcapEngine).cache.dir != "" {
		t.Fatalf("an engine with no cache directory keeps documents in %q (%v)", none.(*dcapEngine).cache.dir, err)
	}
}

// What a simulated guest's host answers its guest with comes from whoever
// stands for the vendor: the four documents of the guest's platform.
func TestFetchSimulatedCollateralAsksTheSimulatedVendor(t *testing.T) {
	s := newSimulated(t)
	docs, err := FetchSimulatedCollateral(context.Background(), s.vendor, CollateralPlatform{FMSPC: simtee.FMSPC, CA: "platform"})
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 4 || len(s.vendor.Asked()) != 4 {
		t.Fatalf("%d documents, and the vendor was asked %d times", len(docs), len(s.vendor.Asked()))
	}
	handed, err := NewSimulatedEngine(EngineOptions{HandedCollateralOnly: true}, s.authority.Root.Cert, nil)
	if err != nil {
		t.Fatal(err)
	}
	handed.(*dcapEngine).cache.now = func() time.Time { return s.now }
	ctx := AllowHandedDocuments(WithCollateralSource(context.Background(), func(context.Context) []CollateralDocument { return docs }))
	if _, err := handed.VerifyEvidence(ctx, s.evidence(t, simulatedReportData), simulatedReportData); err != nil {
		t.Fatalf("a guest's engine, with what its host fetched: %v", err)
	}
	s.vendor.SetDown(errors.New("down"))
	if _, err := FetchSimulatedCollateral(context.Background(), s.vendor, CollateralPlatform{FMSPC: simtee.FMSPC, CA: "platform"}); err == nil {
		t.Fatal("documents were fetched from a vendor that answers nothing")
	}
}
