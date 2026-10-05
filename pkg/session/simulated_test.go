package session

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/pcs"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/simtee"
)

// simulated is a platform whose TEE is simulated in software, the vendor
// that answers for its documents, and a clock the test moves. The vendor
// here can be made to say what Intel's service cannot: that a key is
// revoked, or that a platform fell behind.
type simulated struct {
	now       time.Time
	authority *simtee.Authority
	platform  *simtee.Platform
	quoter    *simtee.Quoter
	vendor    *simtee.Vendor
	roots     *x509.CertPool
}

func newSimulated(t *testing.T) *simulated {
	t.Helper()
	s := &simulated{now: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	var err error
	if s.authority, err = simtee.NewAuthority(s.now); err != nil {
		t.Fatal(err)
	}
	if s.platform, err = s.authority.NewPlatform(s.now); err != nil {
		t.Fatal(err)
	}
	if s.quoter, err = s.platform.NewQuoter(); err != nil {
		t.Fatal(err)
	}
	s.vendor = simtee.NewVendor(s.authority, func() time.Time { return s.now })
	s.roots = x509.NewCertPool()
	s.roots.AddCert(s.authority.Root.Cert)
	return s
}

// engine is a verifier built to judge this simulated TEE, with nothing kept.
func (s *simulated) engine() *dcapEngine {
	cache := newCollateralCache("")
	cache.now = func() time.Time { return s.now }
	return &dcapEngine{cache: cache, fetch: s.vendor, roots: s.roots}
}

// evidence is a quote of the simulated TD that binds reportData, as a guest
// puts it in an envelope.
func (s *simulated) evidence(t *testing.T, reportData []byte) teetypes.AttestationEvidence {
	t.Helper()
	report := &simtee.Report{}
	copy(report.MRTD[:], "a simulated TD's first memory")
	copy(report.ReportData[:], reportData)
	quote, err := s.quoter.Quote(report)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]string{"quote": base64.StdEncoding.EncodeToString(quote)})
	if err != nil {
		t.Fatal(err)
	}
	return teetypes.AttestationEvidence{Platform: teetypes.PlatformTDX, Evidence: body}
}

// handed is the vendor's four documents as a guest's host fetched them now.
func (s *simulated) handed(t *testing.T) []CollateralDocument {
	t.Helper()
	var docs []CollateralDocument
	for _, url := range []string{pcs.TcbInfoURL(simtee.FMSPC), pcs.QeIdentityURL(), pcs.PckCrlURL("platform"), simtee.RootCRLURL} {
		header, body, err := s.vendor.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		docs = append(docs, CollateralDocument{URL: url, Header: header, Body: body})
	}
	return docs
}

var simulatedReportData = []byte("what the simulated guest binds")

// A verifier built to judge a simulated TEE takes its evidence through
// every check it makes of a TDX quote, and says so in what its verdicts are
// scoped to. A verifier that was not built so refuses that evidence, and
// one that was refuses a real TD's: the simulated authority stands in place
// of the vendor's root, never beside it.
func TestSimulatedTEEIsJudgedOnlyByAVerifierBuiltForIt(t *testing.T) {
	s := newSimulated(t)
	env := s.evidence(t, simulatedReportData)
	engine := s.engine()
	res, err := engine.VerifyEvidence(context.Background(), env, simulatedReportData)
	if err != nil {
		t.Fatalf("a simulated quote under its own authority: %v", err)
	}
	finding := CollateralOf(res)
	if finding == nil || !finding.UpToDate() || finding.Stapled || finding.Stale || !finding.Fetched.Equal(s.now) || !res.CollateralVerified {
		t.Fatalf("finding %+v", finding)
	}
	if len(s.vendor.Asked()) != 4 {
		t.Fatalf("the verifier asked for %v", s.vendor.Asked())
	}
	if !strings.Contains(engine.Requirements(), "simulated-tee") {
		t.Fatalf("an engine that judges a simulated TEE says it requires %q", engine.Requirements())
	}
	// Another binding than the quote's is refused, as for any quote.
	var verdict *VerificationError
	if _, err := engine.VerifyEvidence(context.Background(), env, []byte("another binding")); !errors.As(err, &verdict) {
		t.Fatalf("a simulated quote under another binding: %v", err)
	}

	// A verifier as it ships: Intel's root, and no way to be given another.
	shipped := NewEngine(EngineOptions{HandedCollateralOnly: true}).(*dcapEngine)
	if shipped.roots != nil || strings.Contains(shipped.Requirements(), "simulated") {
		t.Fatalf("an engine as it ships holds evidence to another authority than Intel's: %s", shipped.Requirements())
	}
	for name, ctx := range map[string]context.Context{
		"for a verdict that may send a secret":               context.Background(),
		"for one that sends none, with the documents handed": AllowHandedDocuments(WithCollateralSource(context.Background(), func(context.Context) []CollateralDocument { return s.handed(t) })),
		"held to what needs no document":                     offline(context.Background()),
	} {
		if res, err := shipped.VerifyEvidence(ctx, env, simulatedReportData); !errors.As(err, &verdict) || res != nil {
			t.Fatalf("a verifier as it ships, %s, took a simulated quote: %+v, %v", name, res, err)
		}
	}

	// And the other way: a real TD's evidence is nothing to this authority.
	real, reportData := fixture(t)
	if res, err := engine.VerifyEvidence(lenient(), real, reportData); !errors.As(err, &verdict) || res != nil {
		t.Fatalf("a verifier built for a simulated TEE took a real TD's evidence: %+v, %v", res, err)
	}
	// Nor does the authority of one simulation certify another's platform.
	other := newSimulated(t)
	if res, err := other.engine().VerifyEvidence(context.Background(), env, simulatedReportData); !errors.As(err, &verdict) || res != nil {
		t.Fatalf("another simulated authority took the quote: %+v, %v", res, err)
	}
}

// A host relays the vendor's documents with its guest's evidence, and can
// relay those from before the platform's key was revoked: they are still
// within their dates. A verdict that sends nothing secret passes on them,
// and says what it rests on. One that may send a secret asks the vendor
// itself, and finds the revocation.
func TestRelayedDocumentsFromBeforeARevocation(t *testing.T) {
	s := newSimulated(t)
	env := s.evidence(t, simulatedReportData)
	before := s.handed(t)
	// Ten minutes later the vendor revokes the platform's key.
	s.now = s.now.Add(10 * time.Minute)
	s.vendor.Revoke(s.platform.Cert)
	relayed := func(context.Context) []CollateralDocument { return before }

	// A binder with nothing kept checks before it signs a bind.
	engine := s.engine()
	asked := len(s.vendor.Asked())
	res, err := engine.VerifyEvidence(AllowHandedDocuments(WithCollateralSource(context.Background(), relayed)), env, simulatedReportData)
	if err != nil {
		t.Fatalf("a verdict that sends nothing secret, on the documents the host relayed: %v", err)
	}
	finding := CollateralOf(res)
	if !finding.Stapled || !finding.RootCRLStapled || len(s.vendor.Asked()) != asked {
		t.Fatalf("finding %+v after asking the vendor for %v", finding, s.vendor.Asked()[asked:])
	}
	// Nothing secret goes on it.
	if err := standsNot(s.now, stands(s.now, nil, res), nil, res); err == nil {
		t.Fatal("a verdict on relayed documents stands for a release")
	}
	// The verdict to seal on asks the vendor, though the host's documents
	// are at hand, and is a refusal of the guest.
	var verdict *VerificationError
	res, err = engine.VerifyEvidence(WithCollateralSource(context.Background(), relayed), env, simulatedReportData)
	if !errors.As(err, &verdict) || res != nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("a verdict that may send a secret, on a platform revoked ten minutes ago: %+v, %v", res, err)
	}
	if got := len(s.vendor.Asked()) - asked; got != 4 {
		t.Fatalf("the verifier asked the vendor for %d documents, want all four", got)
	}
	// With the vendor out of reach there is no such verdict at all, and no
	// refusal either.
	s.vendor.SetDown(errors.New("no route to the vendor"))
	res, err = s.engine().VerifyEvidence(WithCollateralSource(context.Background(), relayed), env, simulatedReportData)
	if err == nil || errors.As(err, &verdict) || res != nil {
		t.Fatalf("a verdict that may send a secret, with the vendor out of reach: %+v, %v", res, err)
	}
}

// A verifier that judged a guest before its platform was revoked keeps that
// verdict for no more than the hour its documents are reused. It asks the
// vendor again three quarters of an hour after it fetched them, its count of
// documents moves when the newer ones arrive, and the guest's evidence,
// judged again on them, is refused.
func TestVerdictFromBeforeARevocationEndsWithItsDocuments(t *testing.T) {
	s := newSimulated(t)
	env := s.evidence(t, simulatedReportData)
	engine := s.engine()
	ctx := context.Background()
	judged := s.now
	res, err := engine.VerifyEvidence(ctx, env, simulatedReportData)
	if err != nil {
		t.Fatal(err)
	}
	count := engine.Documents()
	until := stands(s.now, nil, res)
	if !until.Equal(judged.Add(collateralTTL)) {
		t.Fatalf("the verdict stands until %s, want an hour after its documents were fetched", until)
	}
	s.vendor.Revoke(s.platform.Cert)

	// Within the hour the verifier judges by what it fetched: the bound the
	// rule accepts.
	s.now = judged.Add(collateralRenewAfter - time.Second)
	asked := len(s.vendor.Asked())
	if err := engine.Renew(ctx); err != nil || len(s.vendor.Asked()) != asked || engine.Documents() != count {
		t.Fatalf("a renewal before anything is due: %v, asked for %v", err, s.vendor.Asked()[asked:])
	}
	if _, err := engine.VerifyEvidence(ctx, env, simulatedReportData); err != nil {
		t.Fatalf("within the hour of its documents: %v", err)
	}
	// At three quarters of an hour the documents are due.
	s.now = judged.Add(collateralRenewAfter)
	if err := engine.Renew(ctx); err != nil {
		t.Fatal(err)
	}
	if got := sorted(s.vendor.Asked()[asked:]); len(got) != 4 {
		t.Fatalf("a renewal asked the vendor for %v", got)
	}
	if engine.Documents() == count {
		t.Fatal("newer documents arrived and the engine's count did not move")
	}
	var verdict *VerificationError
	if res, err := engine.VerifyEvidence(ctx, env, simulatedReportData); !errors.As(err, &verdict) || res != nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("judged again on the newer documents: %+v, %v", res, err)
	}
	// A refusal keeps nothing, so the next judgment asks the vendor again
	// and is refused again: the older list is not gone back to.
	if _, err := engine.VerifyEvidence(ctx, env, simulatedReportData); !errors.As(err, &verdict) {
		t.Fatalf("judged once more: %v", err)
	}
}

// Where a platform stands is the vendor's word, and changes. A platform
// that falls behind is refused under a policy that accepts nothing but the
// current level, by name, and passes under one that names its status. A
// revoked level passes under none.
func TestSimulatedPlatformThatFallsBehind(t *testing.T) {
	for name, tc := range map[string]struct {
		set  func(*simtee.Vendor)
		want string
	}{
		"the platform":        {func(v *simtee.Vendor) { v.SetStatus("OutOfDate", "", "") }, "platform TCB status is OutOfDate"},
		"the TDX module":      {func(v *simtee.Vendor) { v.SetStatus("", "SWHardeningNeeded", "") }, "TDX module TCB status is SWHardeningNeeded"},
		"the quoting enclave": {func(v *simtee.Vendor) { v.SetStatus("", "", "OutOfDate") }, "quoting enclave TCB status is OutOfDate"},
	} {
		s := newSimulated(t)
		env := s.evidence(t, simulatedReportData)
		tc.set(s.vendor)
		var verdict *VerificationError
		if _, err := s.engine().VerifyEvidence(context.Background(), env, simulatedReportData); !errors.As(err, &verdict) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s behind, under a policy that names no status: %v, want a refusal that says %q", name, err, tc.want)
		}
		res, err := s.engine().VerifyEvidence(WithAcceptedTCB(context.Background(), acceptableTCBStatuses), env, simulatedReportData)
		if err != nil {
			t.Errorf("%s behind, under a policy that names its status: %v", name, err)
			continue
		}
		if finding := CollateralOf(res); finding.UpToDate() || !slices.Contains(finding.Advisories, "C8S-SIMULATED-00001") {
			t.Errorf("%s behind: finding %+v", name, finding)
		}
	}
	s := newSimulated(t)
	env := s.evidence(t, simulatedReportData)
	s.vendor.SetStatus("Revoked", "", "")
	var verdict *VerificationError
	if _, err := s.engine().VerifyEvidence(WithAcceptedTCB(context.Background(), acceptableTCBStatuses), env, simulatedReportData); !errors.As(err, &verdict) || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("a revoked level, under a policy that names every status it may: %v", err)
	}
	// A document of an older TCB evaluation than the shipped one is none.
	s = newSimulated(t)
	s.vendor.SetEvaluation(minTCBEvaluation - 1)
	if res, err := s.engine().VerifyEvidence(context.Background(), s.evidence(t, simulatedReportData), simulatedReportData); !isOutage(err) || res != nil {
		t.Fatalf("documents of an evaluation the vendor no longer gives out: %+v, %v", res, err)
	}
}
