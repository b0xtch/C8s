package simtee

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	tdxverify "github.com/google/go-tdx-guest/verify"

	attestationtdx "github.com/confidential-dot-ai/attestation-go/attestation/tdx"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// world is an authority, one platform of it, a boot's quoter and the vendor
// that answers for its documents, on a clock the test moves.
type world struct {
	now       time.Time
	authority *Authority
	platform  *Platform
	quoter    *Quoter
	vendor    *Vendor
	roots     *x509.CertPool
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{now: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	var err error
	if w.authority, err = NewAuthority(w.now); err != nil {
		t.Fatal(err)
	}
	if w.platform, err = w.authority.NewPlatform(w.now); err != nil {
		t.Fatal(err)
	}
	if w.quoter, err = w.platform.NewQuoter(); err != nil {
		t.Fatal(err)
	}
	w.vendor = NewVendor(w.authority, func() time.Time { return w.now })
	w.roots = x509.NewCertPool()
	w.roots.AddCert(w.authority.Root.Cert)
	return w
}

func (w *world) quote(t *testing.T, bound string) *pb.QuoteV4 {
	t.Helper()
	report := &Report{}
	copy(report.MRTD[:], "a TD's first memory")
	copy(report.RTMR[3][:], "what the guest extended")
	copy(report.ReportData[:], bound)
	raw, err := w.quoter.Quote(report)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := abi.QuoteToProto(raw)
	if err != nil {
		t.Fatalf("the quote does not parse: %v", err)
	}
	// What was made is what a verifier reads back.
	again, err := abi.QuoteToAbiBytes(parsed)
	if err != nil || !bytes.Equal(again, raw) {
		t.Fatalf("the quote does not read back as it was made: %v", err)
	}
	return parsed.(*pb.QuoteV4)
}

func (w *world) verify(quote *pb.QuoteV4, roots *x509.CertPool) error {
	at := w.now
	return tdxverify.TdxQuote(quote, &tdxverify.Options{
		GetCollateral: true, CheckRevocations: true, Getter: w.vendor, TrustedRoots: roots,
		Now: &tdxverify.TimeSet{PckCertChain: at, TcbInfo: at, QeIdentity: at, PckCrl: at, RootCaCrl: at},
	})
}

// A simulated quote passes every check a verifier's library makes of a real
// one, the vendor's documents and revocation lists included, under the
// simulated authority, and under no other.
func TestSimulatedQuoteVerifiesUnderItsAuthorityAlone(t *testing.T) {
	w := newWorld(t)
	quote := w.quote(t, "bound")
	if err := w.verify(quote, w.roots); err != nil {
		t.Fatalf("under its own authority: %v", err)
	}
	asked := w.vendor.Asked()
	slices.Sort(asked)
	want := []string{pcs.PckCrlURL("platform"), pcs.QeIdentityURL(), pcs.TcbInfoURL(FMSPC), RootCRLURL}
	slices.Sort(want)
	if !slices.Equal(asked, want) {
		t.Fatalf("the verifier asked for %v, want the four documents %v", asked, want)
	}
	if !bytes.HasPrefix(quote.GetTdQuoteBody().GetReportData(), []byte("bound")) {
		t.Fatal("the quote does not bind what it was given")
	}
	// The checks of a quote's fields and of its binding, which the library
	// that judges evidence for sessions makes before any document is read.
	raw, err := abi.QuoteToAbiBytes(quote)
	if err != nil {
		t.Fatal(err)
	}
	bound := make([]byte, 64)
	copy(bound, "bound")
	opts := attestationtdx.Options{TrustedRoots: w.roots, Now: w.now}
	res, err := attestationtdx.VerifyQuoteBytes(raw, teetypes.VerifyParams{ExpectedReportData: bound}, teetypes.PlatformTDX, opts)
	if err != nil || !res.SignatureValid {
		t.Fatalf("the quote's fields and binding: %v", err)
	}
	if debug, err := res.Claims.DebugEnabled(); err != nil || debug {
		t.Fatalf("the quote says its TD is under debug: %v, %v", debug, err)
	}
	if _, err := attestationtdx.VerifyQuoteBytes(raw, teetypes.VerifyParams{ExpectedReportData: make([]byte, 64)}, teetypes.PlatformTDX, opts); err == nil {
		t.Fatal("the quote passed under another binding than its own")
	}

	// The vendor's root, which a verifier that was told nothing holds
	// evidence to, did not certify this platform.
	if err := w.verify(quote, nil); err == nil {
		t.Fatal("a simulated quote verified under the vendor's own root")
	}
	// Nor did another simulated authority.
	other := newWorld(t)
	if err := w.verify(quote, other.roots); err == nil {
		t.Fatal("a simulated quote verified under another authority")
	}
	// A body that was changed is not the one that was signed.
	bent := w.quote(t, "bound")
	bent.TdQuoteBody.MrTd[0] ^= 1
	if err := w.verify(bent, w.roots); err == nil {
		t.Fatal("a quote whose body was changed verified")
	}
	// Nor is a quote under an attestation key the platform did not certify.
	elsewhere, err := other.platform.NewQuoter()
	if err != nil {
		t.Fatal(err)
	}
	foreign := w.quote(t, "bound")
	foreign.SignedData.EcdsaAttestationKey = elsewhere.public
	if err := w.verify(foreign, w.roots); err == nil {
		t.Fatal("a quote under another attestation key verified")
	}
}

// Every certificate of a simulated authority says what it is, where a
// verifier's library does not look: the common names are the vendor's.
func TestSimulatedCertificatesSayWhatTheyAre(t *testing.T) {
	w := newWorld(t)
	a := w.authority
	names := map[*x509.Certificate]string{
		a.Root.Cert: "Intel SGX Root CA", a.PlatformCA.Cert: "Intel SGX PCK Platform CA",
		a.Signer.Cert: "Intel SGX TCB Signing", w.platform.Cert: "Intel SGX PCK Certificate",
	}
	for cert, name := range names {
		if cert.Subject.CommonName != name {
			t.Errorf("a certificate is named %q, and a verifier's library holds it to %q", cert.Subject.CommonName, name)
		}
		if err := Marked(cert); err != nil || !strings.Contains(cert.Subject.String(), "simulated") {
			t.Errorf("%s does not say it is simulated: %s", name, cert.Subject)
		}
	}
	plain := *w.platform.Cert
	plain.Subject.Organization = []string{"Intel Corporation"}
	if Marked(a.Root.Cert, &plain) == nil {
		t.Fatal("a certificate that does not say it is simulated passed as marked")
	}
	if a.Root.Cert.CRLDistributionPoints[0] != RootCRLURL {
		t.Fatalf("the root says its CRL is at %s", a.Root.Cert.CRLDistributionPoints[0])
	}
	exts, err := pcs.PckCertificateExtensions(w.platform.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if exts.FMSPC != FMSPC || exts.PCEID != PCEID || exts.TCB.PCESvn != PCESVN || !bytes.Equal(exts.TCB.CPUSvnComponents, CPUSVN[:]) || !bytes.Equal(exts.TCB.CPUSvn, CPUSVN[:]) {
		t.Fatalf("the platform's certificate says %+v", exts)
	}
}

// The simulated vendor says what the real one cannot be made to say: that a
// platform's key is revoked, that the CA above it is, and where a platform
// stands. A verifier finds each in the documents it fetches.
func TestSimulatedVendorRevokesAndDowngrades(t *testing.T) {
	t.Run("a platform's key", func(t *testing.T) {
		w := newWorld(t)
		quote := w.quote(t, "bound")
		w.vendor.Revoke(w.platform.Cert)
		if err := w.verify(quote, w.roots); err == nil || !strings.Contains(err.Error(), "PCK Leaf certificate in PCK certificate chain was revoked") {
			t.Fatalf("a quote of a revoked platform: %v", err)
		}
		// Another platform of the authority is none the worse.
		spared, err := w.authority.NewPlatform(w.now)
		if err != nil {
			t.Fatal(err)
		}
		quoter, err := spared.NewQuoter()
		if err != nil {
			t.Fatal(err)
		}
		w.quoter = quoter
		if err := w.verify(w.quote(t, "bound"), w.roots); err != nil {
			t.Fatalf("a quote of a platform that is not revoked: %v", err)
		}
	})
	t.Run("the CA above it", func(t *testing.T) {
		w := newWorld(t)
		quote := w.quote(t, "bound")
		w.vendor.Revoke(w.authority.PlatformCA.Cert)
		if err := w.verify(quote, w.roots); err == nil || !strings.Contains(err.Error(), "intermediate certificate in PCK certificate chain was revoked") {
			t.Fatalf("a quote under a revoked CA: %v", err)
		}
	})
	t.Run("a platform behind the current level", func(t *testing.T) {
		w := newWorld(t)
		quote := w.quote(t, "bound")
		// The quote and the documents stay authentic. What says the platform
		// is behind is the level the vendor's document gives it, which a
		// verifier of sessions judges for itself: see pkg/session.
		w.vendor.SetStatus("OutOfDate", "", "")
		if err := w.verify(quote, w.roots); err != nil && !strings.Contains(err.Error(), "failed TCB status check") {
			t.Fatalf("the quote of a platform that is behind: %v", err)
		}
		_, body, err := w.vendor.Get(pcs.TcbInfoURL(FMSPC))
		if err != nil {
			t.Fatal(err)
		}
		var info pcs.TdxTcbInfo
		if err := json.Unmarshal(body, &info); err != nil {
			t.Fatal(err)
		}
		if first := info.TcbInfo.TcbLevels[0]; first.TcbStatus != pcs.TcbComponentStatusOutOfDate || len(first.AdvisoryIDs) == 0 {
			t.Fatalf("the level the platform meets says %+v", first)
		}
		if info.TcbInfo.TcbEvaluationDataNumber != Evaluation {
			t.Fatalf("the TCB info is of evaluation %d", info.TcbInfo.TcbEvaluationDataNumber)
		}
	})
	t.Run("a TDX module or a quoting enclave behind the current level", func(t *testing.T) {
		for name, set := range map[string]func(*Vendor){
			"the module":          func(v *Vendor) { v.SetStatus("", "OutOfDate", "") },
			"the quoting enclave": func(v *Vendor) { v.SetStatus("", "", "OutOfDate") },
		} {
			w := newWorld(t)
			quote := w.quote(t, "bound")
			set(w.vendor)
			if err := w.verify(quote, w.roots); err == nil || !strings.Contains(err.Error(), "failed TCB status check") {
				t.Fatalf("a quote with %s behind: %v", name, err)
			}
		}
	})
	t.Run("out of reach", func(t *testing.T) {
		w := newWorld(t)
		down := errors.New("no route to the vendor")
		w.vendor.SetDown(down)
		if _, _, err := w.vendor.Get(RootCRLURL); !errors.Is(err, down) {
			t.Fatalf("a vendor that is down answered: %v", err)
		}
		w.vendor.SetDown(nil)
		if _, _, err := w.vendor.Get("https://elsewhere.example/"); err == nil {
			t.Fatal("the vendor answered for a document it does not have")
		}
	})
}

// The vendor signs each document when it is first asked for, answers with
// that one for an hour, and then signs another, as the vendor's service
// does. What a test changes shows at once.
func TestSimulatedVendorSignsAnewEachHour(t *testing.T) {
	w := newWorld(t)
	digest := func() map[string][sha256.Size]byte {
		out := map[string][sha256.Size]byte{}
		for _, url := range []string{pcs.TcbInfoURL(FMSPC), pcs.QeIdentityURL(), pcs.PckCrlURL("platform"), RootCRLURL} {
			_, body, err := w.vendor.Get(url)
			if err != nil {
				t.Fatal(err)
			}
			out[url] = sha256.Sum256(body)
		}
		return out
	}
	first := digest()
	w.now = w.now.Add(time.Hour - time.Second)
	if again := digest(); !sameDigests(first, again) {
		t.Fatal("a document was signed anew within its hour")
	}
	w.now = w.now.Add(time.Second)
	later := digest()
	for url := range first {
		if later[url] == first[url] {
			t.Errorf("%s is the same document an hour later", url)
		}
	}
	w.vendor.SetEvaluation(Evaluation + 1)
	changed := digest()
	for url := range later {
		if changed[url] == later[url] {
			t.Errorf("%s did not change with what the vendor says", url)
		}
	}
	if err := w.verify(w.quote(t, "bound"), w.roots); err != nil {
		t.Fatalf("after the vendor signed anew: %v", err)
	}
}

func sameDigests(a, b map[string][sha256.Size]byte) bool {
	for url, digest := range a {
		if b[url] != digest {
			return false
		}
	}
	return len(a) == len(b)
}
