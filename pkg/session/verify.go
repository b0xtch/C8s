package session

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/google/go-tdx-guest/pcs"
	tdxverify "github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"

	attestationtdx "github.com/confidential-dot-ai/attestation-go/attestation/tdx"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// Policy is what a verifier requires of a guest before trusting it.
type Policy struct {
	// Image pins the guest build; load it from the build's manifest.json.
	Image runtimemeasure.ImageIdentity
	// LaunchKey is the pool's launch public key, the exact PEM bytes the guest
	// measured.
	LaunchKey []byte
	// Launch, when set, is the exact launch.yaml the guest must have measured.
	// Unset accepts any document LaunchKey signed for the pinned image.
	Launch []byte

	// Authority is the owner's authority public key, PEM. The guest must have
	// measured a bind that this key signed and that names this guest. It is
	// unset only in a policy that accepts nothing but a guest nobody has
	// bound: whoever bound a guest, nothing here vouches for them.
	Authority []byte
	// Bind, when set, is the exact bind the guest must have measured.
	Bind []byte
	// Tenant and Session, when set, must equal the bind's.
	Tenant  string
	Session string
	// AllowReady accepts a guest nobody has bound yet. Only the step that
	// binds it has a use for that: an unbound guest is nobody's.
	AllowReady bool
	// AllowBound accepts a guest that has measured its bind but not yet its
	// sandbox image. Release a sandbox's credentials only when false.
	AllowBound bool
	// AllowNoMachine accepts a TD whose launch document lists no machine it
	// may be. Only the step that reads a machine's value from such a guest
	// has a use for that: the guest takes no bind, and no other verifier
	// should take its word. A document that lists machines is held to them
	// either way.
	AllowNoMachine bool
	// AcceptTCBStatus names Intel TCB statuses, besides UpToDate, that the
	// guest's platform, its TDX module or its quoting enclave may have:
	// sorted, each once. Revoked cannot be accepted. The verdict's finding
	// says where each stands: see CollateralOf.
	AcceptTCBStatus []string
}

// judging is ctx as the engine gets it for a verification under this policy.
func (p Policy) judging(ctx context.Context) context.Context {
	return WithAcceptedTCB(ctx, p.AcceptTCBStatus)
}

func (p Policy) validate() error {
	if p.Image == nil {
		return errors.New("policy pins no guest image")
	}
	if _, err := parsePublicKey(string(p.LaunchKey)); err != nil {
		return fmt.Errorf("policy launch key: %w", err)
	}
	if err := ValidateTCBStatuses(p.AcceptTCBStatus); err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	if p.Authority == nil {
		if !p.AllowReady || p.AllowBound || p.Bind != nil || p.Tenant != "" || p.Session != "" {
			return errors.New("a policy that names no authority accepts an unbound guest and nothing else")
		}
		return nil
	}
	if _, err := parsePublicKey(string(p.Authority)); err != nil {
		return fmt.Errorf("policy authority: %w", err)
	}
	if p.Bind == nil && !p.AllowReady && (p.Tenant == "" || p.Session == "") {
		return errors.New("policy must pin the bind, or both tenant and session")
	}
	return nil
}

// VerificationError marks a verdict: evidence was obtained and refused. Every
// other error from this package means no verdict was reached.
type VerificationError struct{ Err error }

func (e *VerificationError) Error() string { return e.Err.Error() }
func (e *VerificationError) Unwrap() error { return e.Err }

func refuse(format string, args ...any) error {
	return &VerificationError{Err: fmt.Errorf(format, args...)}
}

// Engine verifies hardware evidence: signature chain, debug policy and the
// REPORTDATA binding. It returns a result only for evidence that passed all
// three. Tests substitute it; production uses NewEngine.
type Engine interface {
	VerifyEvidence(ctx context.Context, env teetypes.AttestationEvidence, expectedReportData []byte) (*teetypes.VerificationResult, error)
}

// EngineOptions configures the in-process verifier.
type EngineOptions struct {
	// CollateralCacheDir, when set, keeps Intel's collateral in that directory
	// between processes, for as long as an engine reuses it in memory. It
	// saves the fetch and is trusted for nothing: the documents are verified
	// at every use.
	CollateralCacheDir string
	// FreshCollateralOnly refuses to go on with a kept document that is past
	// the reuse period when Intel cannot be asked for a new one. Without it
	// the engine uses the kept document for as long as Intel's own date on
	// it allows, and the finding says so: see CollateralFinding.Stale.
	FreshCollateralOnly bool
	// OwnCollateralOnly takes Intel's documents from Intel's service alone.
	// Without it the engine also takes one that somebody else hands over,
	// within two hours of Intel's own date on it, and the finding says so:
	// see WithCollateralSource and CollateralFinding.Stapled.
	OwnCollateralOnly bool
	// HandedCollateralOnly never asks Intel's service: the engine of a
	// verifier with no road to it, such as a guest. It judges by the
	// documents somebody hands over, and one nobody handed over is a fetch
	// that failed, at once.
	HandedCollateralOnly bool
	// Dial, when set, opens every connection to Intel's service: for a
	// verifier whose only road there is one its host carries, such as a
	// guest with no network device (see VendorServices). The TLS session on
	// it ends at Intel and is held to the system's roots, as on any road.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// noRoad is Intel's service as a verifier with no road to it finds it.
type noRoad struct{}

var errNoRoad = errors.New("this verifier asks Intel's service for nothing, and nobody handed the document over")

func (noRoad) Get(string) (map[string][]string, []byte, error) { return nil, nil, errNoRoad }

type dcapEngine struct {
	cache     *collateralCache
	fetch     trust.HTTPSGetter
	freshOnly bool
	ownOnly   bool
	// chains keeps the outcome of the checks that are the same for every
	// quote of a platform: see chainmemo.go.
	chains chainMemos
}

type offlineKey struct{}

// offline asks an engine for the checks that need none of the vendor's
// documents, and for no others.
func offline(ctx context.Context) context.Context {
	return context.WithValue(ctx, offlineKey{}, true)
}

// Offline reports whether ctx asks an engine to stop at what needs none of
// the vendor's documents: the evidence's signature and its chain to the
// vendor's root, the identity of what signed it, and its binding. An engine
// that is asked so fetches nothing, and says nothing about where the
// platform's TCB stands. Such a result holds a quote to its receipt while a
// document cannot be had (HoldBound). No verdict is kept on it.
func Offline(ctx context.Context) bool {
	asked, _ := ctx.Value(offlineKey{}).(bool)
	return asked
}

// NewEngine returns the in-process verifier, built on attestation-go and
// go-tdx-guest like `c8s verify`. It judges TDX evidence against Intel's
// collateral, always: the TCB info, the quoting enclave's identity and the
// revocation lists. A verdict it cannot fetch the collateral for is no
// verdict. The platform, its TDX module and its quoting enclave must each be
// UpToDate, unless the context names another status: see WithAcceptedTCB.
func NewEngine(opts EngineOptions) Engine {
	getter := pcsGetter{}
	if opts.Dial != nil {
		getter.client = pcsClientOver(opts.Dial, nil)
	}
	var fetch trust.HTTPSGetter = &trust.RetryHTTPSGetter{
		Timeout: 30 * time.Second, MaxRetryDelay: 5 * time.Second, Getter: getter,
	}
	if opts.HandedCollateralOnly {
		fetch = noRoad{}
	}
	return &dcapEngine{
		cache:     newCollateralCache(opts.CollateralCacheDir),
		fetch:     fetch,
		freshOnly: opts.FreshCollateralOnly,
		ownOnly:   opts.OwnCollateralOnly,
	}
}

// Prefetcher is an engine that can fetch, ahead of the verification that
// needs it, what nobody can hand it: see Prefetch.
type Prefetcher interface {
	Prefetch()
}

// Prefetch has engine start fetching, behind the caller, the one document of
// Intel's that a verdict which releases a secret takes from Intel alone: the
// root CA CRL. A verifier that calls this when it starts finds the document
// there, or on its way, when its first such verdict is due. An engine that
// fetches nothing ignores it.
func Prefetch(engine Engine) {
	if p, ok := engine.(Prefetcher); ok {
		p.Prefetch()
	}
}

// Prefetch implements Prefetcher.
func (e *dcapEngine) Prefetch() {
	if url, err := rootCRLURL(); err == nil {
		e.cache.prefetch(e.fetch, url)
	}
}

// Refetcher is an engine that fetches the root CA CRL anew when asked, for
// the next verification to take in place of the one it holds: see
// Client.Renew.
type Refetcher interface {
	Refetch(ctx context.Context) error
}

// Refetch implements Refetcher. It returns once the CRL is here, and waits
// for a fetch of it already on its way in place of starting another.
func (e *dcapEngine) Refetch(ctx context.Context) error {
	url, err := rootCRLURL()
	if err != nil {
		return err
	}
	f := e.cache.fly(ctx, e.fetch, url, true)
	select {
	case <-f.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	if f.err != nil {
		return f.err
	}
	// A flight a verification started keeps nothing ahead.
	e.cache.keepAhead(url, f.entry)
	return nil
}

// Requirements names what decides this engine's verdicts: whether it goes on
// with collateral past its reuse period, and whether it takes Intel's
// documents from Intel alone. Where the collateral is kept decides nothing.
func (e *dcapEngine) Requirements() string {
	return fmt.Sprintf("dcap fresh-only=%t own-only=%t", e.freshOnly, e.ownOnly)
}

func (e *dcapEngine) VerifyEvidence(ctx context.Context, env teetypes.AttestationEvidence, expectedReportData []byte) (*teetypes.VerificationResult, error) {
	if len(expectedReportData) == 0 {
		return nil, errors.New("refusing to verify evidence without an expected REPORTDATA")
	}
	params := teetypes.VerifyParams{ExpectedReportData: expectedReportData}
	var res *teetypes.VerificationResult
	var err error
	// The bare-metal tags only. A cloud overlay tag would move the REPORTDATA
	// binding to a vTPM key that the attester names.
	switch env.Platform {
	case teetypes.PlatformTDX:
		if res, err = e.verifyTDX(ctx, env, params); err != nil {
			return nil, err
		}
	case teetypes.PlatformSNP:
		// localverify fetches the VCEK from AMD KDS when the report carries none.
		res, err = localverify.Verify(ctx, string(env.Platform), env.Evidence, localverify.Params{VerifyParams: params})
		var collateral *localverify.CollateralError
		if errors.As(err, &collateral) {
			return nil, err
		}
		if err != nil {
			return nil, &VerificationError{Err: err}
		}
	default:
		return nil, refuse("unsupported platform %q", env.Platform)
	}
	if err := res.Check(); err != nil {
		return nil, &VerificationError{Err: err}
	}
	if res.ReportDataMatch == nil || !*res.ReportDataMatch {
		return nil, refuse("REPORTDATA does not match the expected binding")
	}
	return res, nil
}

// CollateralClaim is where the engine records what a result rests on in the
// result's claims.
const CollateralClaim = "c8s_collateral"

// CollateralOf returns the finding of a result verified with collateral, or nil.
func CollateralOf(res *teetypes.VerificationResult) *CollateralFinding {
	if res == nil || res.Claims.PlatformData == nil {
		return nil
	}
	finding, _ := res.Claims.PlatformData[CollateralClaim].(*CollateralFinding)
	return finding
}

// verifyTDX judges the quote offline first: signature, PCK chain, binding and
// the quoting enclave's identity. Only a quote that passed is worth a fetch,
// and a failure before this point must read as a verdict on the evidence. The
// second pass holds the same quote to Intel's collateral, which names the
// quoting enclave, lists what Intel has revoked, and states where the
// platform, its TDX module and its quoting enclave stand.
func (e *dcapEngine) verifyTDX(ctx context.Context, env teetypes.AttestationEvidence, params teetypes.VerifyParams) (*teetypes.VerificationResult, error) {
	// The envelope is decoded once, here. The engine verifies those bytes,
	// and everything below reads the quote parsed from the same ones.
	raw, err := tdQuoteBytes(env.Evidence)
	if err != nil {
		return nil, &VerificationError{Err: err}
	}
	if len(params.ExpectedReportData) > 64 {
		return nil, &VerificationError{Err: fmt.Errorf("expected report data is %d bytes, and a TD's is 64", len(params.ExpectedReportData))}
	}
	res, err := attestationtdx.VerifyQuoteBytes(raw, params, teetypes.PlatformTDX, attestationtdx.Options{})
	if err != nil {
		return nil, &VerificationError{Err: err}
	}
	quote, err := parseVerifiedTDQuote(raw)
	if err != nil {
		return nil, &VerificationError{Err: err}
	}
	if err := checkTDQuoteOrigin(quote); err != nil {
		return nil, &VerificationError{Err: err}
	}
	// What needed none of Intel's documents is done: see Offline.
	if Offline(ctx) {
		return res, nil
	}

	// go-tdx-guest authenticates the collateral (Intel's signing chains, the
	// validity windows, the CRLs) and checks the PCK chain against the CRLs.
	// Its own TCB verdict is not used: see evaluateTDXTCB. That pass depends
	// on the platform and the documents, and on nothing in the quote's body
	// that is not checked here as well, so its outcome is kept for a short
	// while: see chainmemo.go.
	roots, err := intelRoots()
	if err != nil {
		return nil, err
	}
	platform, onePlatform := platformOfTDQuote(raw)
	fetches, err := e.withCollateral(ctx, func(fetches *fetchRecorder) error {
		// One clock for how old a kept document is and for Intel's dates on it.
		now := e.cache.now()
		if onePlatform && e.chains.stands(platform, now, fetches) {
			return nil
		}
		err := tdxverify.TdxQuoteContext(ctx, quote, &tdxverify.Options{
			GetCollateral: true, CheckRevocations: true, Getter: fetches, TrustedRoots: roots, Now: allAt(now),
		})
		if onePlatform && (err == nil || authenticCollateral(err)) {
			e.chains.keep(platform, now, fetches)
		}
		return err
	})
	// Intel PCS being unreachable says nothing about the evidence.
	if fetches.caused(err) {
		return nil, fmt.Errorf("TDX collateral unavailable: %w", err)
	}
	if err != nil && !authenticCollateral(err) {
		return nil, &VerificationError{Err: err}
	}
	finding, err := fetches.finding()
	if err != nil {
		return nil, &VerificationError{Err: err}
	}
	chain, err := tdxverify.ExtractChainFromQuote(quote)
	if err != nil {
		return nil, &VerificationError{Err: err}
	}
	exts, err := pcs.PckCertificateExtensions(chain.PCKCertificate)
	if err != nil {
		return nil, &VerificationError{Err: err}
	}
	tcbInfo, haveTCB := fetches.body(pcs.TcbInfoURL(exts.FMSPC))
	qeIdentity, haveQE := fetches.body(pcs.QeIdentityURL())
	if !haveTCB || !haveQE {
		return nil, errors.New("TDX collateral was verified but its documents are not at hand")
	}
	tcb, err := evaluateTDXTCB(quote, tcbInfo, qeIdentity)
	if err != nil {
		return nil, &VerificationError{Err: err}
	}
	if err := tcb.judge(AcceptedTCB(ctx)); err != nil {
		return nil, err
	}
	finding.TCBFinding = *tcb
	// Only collateral that carried a verification to success is worth keeping.
	fetches.commit()
	res.CollateralVerified = true
	if res.Claims.PlatformData == nil {
		res.Claims.PlatformData = map[string]any{}
	}
	res.Claims.PlatformData[CollateralClaim] = finding
	return res, nil
}

// allAt is the time at which every certificate and document of a
// verification is checked for validity.
func allAt(now time.Time) *tdxverify.TimeSet {
	return &tdxverify.TimeSet{PckCertChain: now, TcbInfo: now, QeIdentity: now, PckCrl: now, RootCaCrl: now}
}

// authenticCollateral reports whether a failed collateral check still found
// the documents authentic. The TCB status check is the last thing go-tdx-guest
// does with each document, so a failure there means exactly that. What it
// leaves undone after the first such failure, holding the quoting enclave to
// Intel's identity document, checkTDQuoteOrigin and evaluateTDXTCB do.
func authenticCollateral(err error) bool {
	return strings.Contains(err.Error(), "failed TCB status check")
}

// withCollateral runs check with collateral from the cache where the cache
// has it, and from whoever ctx names to hand it over where it has not.
// Collateral that Intel was not asked for and that does not pass says nothing
// about the evidence: a file can be damaged, a document handed over can be
// anything, and either can be older than what the quote needs. The check then
// runs once more with everything fetched anew, and that run's verdict stands.
// It returns the recorder of the run whose result it returns.
func (e *dcapEngine) withCollateral(ctx context.Context, check func(*fetchRecorder) error) (*fetchRecorder, error) {
	fetches := &fetchRecorder{ctx: ctx, cache: e.cache, inner: e.fetch, freshOnly: e.freshOnly, only: intelDocument}
	if !e.ownOnly {
		fetches.source, _ = ctx.Value(collateralSourceKey{}).(CollateralSource)
		fetches.stapledRoot = ctx.Value(stapledRootKey{}) != nil
	}
	err := check(fetches)
	if err == nil || authenticCollateral(err) || fetches.caused(err) || !fetches.fromCache() {
		return fetches, err
	}
	fetches = &fetchRecorder{ctx: ctx, cache: e.cache, inner: e.fetch, anew: true, only: intelDocument}
	return fetches, check(fetches)
}

// Attestation is a verified fresh attestation of one guest.
type Attestation struct {
	Document *Document
	// Launch is the exact launch.yaml the guest measured.
	Launch []byte
	// Bind is the bind a bound guest measured, or nil.
	Bind *SignedBind
	// Tenant and Session are whose the guest is: the bind's. Both are empty
	// for a guest nobody has bound.
	Tenant  string
	Session string
	Events  []string
	Phase   Phase
	Result  *teetypes.VerificationResult
	// InstanceKey is the PKIX DER of the guest-generated key the evidence binds.
	InstanceKey []byte
	// Held says the evidence was held to what needs none of the vendor's
	// documents and was not judged: see HoldBound. No verdict is kept on such
	// an attestation, and nothing is released on it.
	Held bool
}

// Egress is where the guest's sandbox may connect. ok is false for a guest
// that runs no sandbox image, to which no egress rule applies. A nil policy
// with ok true is a sandbox its bind does not restrict: it reaches any public
// destination, and no private one.
func (a *Attestation) Egress() (policy *Egress, ok bool) {
	if a.Bind == nil {
		return nil, false
	}
	return a.Bind.Doc.Policy.Egress, a.Bind.Doc.Policy.Sandbox != nil
}

// Forward is what the guest opens to streams from outside: the ports of its
// sandbox, and the keys that may open a stream to them, each as sha256:<hex>
// of its PKIX encoding. A nil area opens nothing to anyone.
func (a *Attestation) Forward() (area *Forward, keys []string) {
	if a.Bind == nil || a.Bind.Doc.Policy.Forward == nil {
		return nil, nil
	}
	for _, key := range a.Bind.Doc.Policy.Access.ForwardKeys() {
		if digest, err := InstanceKeyDigest(key); err == nil {
			keys = append(keys, digest)
		}
	}
	return a.Bind.Doc.Policy.Forward, keys
}

// Credential returns the declaration for name in the guest's bind.
func (a *Attestation) Credential(name string) (Credential, bool) {
	if a.Bind == nil {
		return Credential{}, false
	}
	return a.Bind.Doc.Policy.Credential(name)
}

// VerifyAttestation is the trust gate. It accepts resp only if hardware
// evidence proves, for the guest holding instanceKey: the pinned image booted,
// it was launched for policy.LaunchKey, it measured exactly the launch
// document, the bind and the sandbox the policy expects, and the evidence is
// fresh for nonce.
func VerifyAttestation(ctx context.Context, policy Policy, engine Engine, instanceKey crypto.PublicKey, nonce []byte, resp *AttestResponse) (*Attestation, error) {
	if err := policy.validate(); err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, refuse("no attestation response")
	}
	if len(resp.Events) == 0 || len(resp.Events) > 8 {
		return nil, refuse("attestation reports %d measured events", len(resp.Events))
	}
	doc, err := VerifySigned(policy.LaunchKey, resp.Launch, resp.Signature)
	if err != nil {
		return nil, &VerificationError{Err: err}
	}
	if policy.Launch != nil && !bytes.Equal(policy.Launch, resp.Launch) {
		return nil, refuse("guest measured launch document %s, policy pins %s", DocumentDigest(resp.Launch), DocumentDigest(policy.Launch))
	}
	bind, err := checkBinding(policy, instanceKey, resp)
	if err != nil {
		return nil, err
	}
	tenant, name := "", ""
	if bind != nil {
		tenant, name = bind.Doc.Tenant, bind.Doc.Session
		if policy.Tenant != "" && tenant != policy.Tenant {
			return nil, refuse("guest belongs to tenant %q, policy pins %q", tenant, policy.Tenant)
		}
		if policy.Session != "" && name != policy.Session {
			return nil, refuse("guest is session %q, policy pins %q", name, policy.Session)
		}
	}
	if err := imageMatchesDocument(policy.Image, doc.Image); err != nil {
		return nil, &VerificationError{Err: err}
	}
	if resp.Phase == PhaseBound && !policy.AllowBound {
		return nil, refuse("guest has not admitted its sandbox yet (phase %s)", resp.Phase)
	}
	// Events are derived from the signed documents, never taken from the guest.
	events, err := ExpectedEvents(resp.Launch, bind, resp.Phase)
	if err != nil {
		return nil, &VerificationError{Err: err}
	}
	if !slices.Equal(events, resp.Events) {
		return nil, refuse("guest reports events %v, its documents imply %v", resp.Events, events)
	}
	reportData, err := ReportData(instanceKey, nonce, events)
	if err != nil {
		return nil, err
	}
	res, err := engine.VerifyEvidence(policy.judging(ctx), resp.Evidence, reportData)
	if err != nil {
		return nil, err
	}
	if err := checkMeasuredIdentity(policy, res, [][]string{events}); err != nil {
		return nil, err
	}
	if err := checkMachine(policy, doc, res); err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(instanceKey)
	if err != nil {
		return nil, fmt.Errorf("encode instance key: %w", err)
	}
	return &Attestation{
		Document: doc, Launch: resp.Launch, Bind: bind, Tenant: tenant, Session: name,
		Events: events, Phase: resp.Phase, Result: res, InstanceKey: der,
	}, nil
}

// checkBinding judges whose guest this is. A guest nobody has bound passes
// only a policy that allows one. A bound guest passes only under the
// authority the policy pins, for a bind that names this very guest.
func checkBinding(policy Policy, instanceKey crypto.PublicKey, resp *AttestResponse) (*SignedBind, error) {
	if resp.Phase == PhaseReady {
		if !policy.AllowReady {
			return nil, refuse("guest is one that nobody has bound")
		}
		if len(resp.Bind) > 0 {
			return nil, refuse("guest reports a bind in phase %s", PhaseReady)
		}
		return nil, nil
	}
	if policy.Authority == nil {
		return nil, refuse("guest is bound, and this policy names no authority that could have bound it")
	}
	bind, err := VerifyBind(resp.Bind, resp.BindSignature)
	if err != nil {
		return nil, &VerificationError{Err: err}
	}
	if !bind.SignedBy(policy.Authority) {
		return nil, refuse("guest was bound by another authority than the one this policy pins")
	}
	if policy.Bind != nil && !bytes.Equal(policy.Bind, resp.Bind) {
		return nil, refuse("guest measured bind %s, policy pins %s", DocumentDigest(resp.Bind), DocumentDigest(policy.Bind))
	}
	// The authority signed for one guest. Its signature on a bind for another
	// instance key says nothing about this one.
	if err := bind.Doc.Targets(instanceKey); err != nil {
		return nil, &VerificationError{Err: err}
	}
	return bind, nil
}

// VerifyServingCert is the handshake gate: the leaf must be self-signed under
// its own attested key, and that key must have been generated inside a guest
// of the pinned image launched for policy.LaunchKey. It is not a freshness
// proof and does not replace VerifyAttestation.
func VerifyServingCert(ctx context.Context, policy Policy, engine Engine, leaf *x509.Certificate, now time.Time) error {
	if err := policy.validate(); err != nil {
		return err
	}
	doc, chains, err := handshakeChains(policy)
	if err != nil {
		return err
	}
	return verifyServingCert(ctx, policy, engine, leaf, now, doc, chains)
}

// judgeServingCert is VerifyServingCert that also returns what the engine
// found, which says how long the verdict may stand.
func judgeServingCert(ctx context.Context, policy Policy, engine Engine, leaf *x509.Certificate, now time.Time) (*teetypes.VerificationResult, error) {
	if err := policy.validate(); err != nil {
		return nil, err
	}
	doc, chains, err := handshakeChains(policy)
	if err != nil {
		return nil, err
	}
	return servingCertResult(ctx, policy, engine, leaf, now, doc, chains)
}

// verifyServingCert checks a serving certificate's evidence against the image
// pin, against the machines of the launch document if doc is known, and,
// unless chains is nil, against the event chains it may carry.
func verifyServingCert(ctx context.Context, policy Policy, engine Engine, leaf *x509.Certificate, now time.Time, doc *Document, chains [][]string) error {
	_, err := servingCertResult(ctx, policy, engine, leaf, now, doc, chains)
	return err
}

func servingCertResult(ctx context.Context, policy Policy, engine Engine, leaf *x509.Certificate, now time.Time, doc *Document, chains [][]string) (*teetypes.VerificationResult, error) {
	body, err := certutil.AuthenticateLeafBody(leaf, now)
	if err != nil {
		return nil, &VerificationError{Err: err}
	}
	if body != certutil.BodySelfSigned {
		return nil, refuse("agent serving certificate is not self-signed, so nothing authenticates its body")
	}
	att, err := ratls.ExtractAttestation(leaf)
	if err != nil {
		return nil, &VerificationError{Err: err}
	}
	env, err := att.Envelope()
	if err != nil {
		return nil, &VerificationError{Err: err}
	}
	// A certificate from before the guest's bind carries its one-time keys,
	// and its quote binds them with the certificate's key.
	rd, _, err := certificateReportData(leaf)
	if err != nil {
		return nil, &VerificationError{Err: err}
	}
	res, err := engine.VerifyEvidence(policy.judging(ctx), env, rd)
	if err != nil {
		return nil, err
	}
	if err := checkMeasuredIdentity(policy, res, chains); err != nil {
		return nil, err
	}
	// Without the document the machine waits for the fresh attestation, which
	// brings the document, as the event chain does.
	if doc != nil {
		if err := checkMachine(policy, doc, res); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// checkMachine holds signature-verified claims to the machines the guest's
// launch document lists: the register the firmware extended with what the
// host handed it must hold one of the listed values.
func checkMachine(policy Policy, doc *Document, res *teetypes.VerificationResult) error {
	if doc.Machine == nil {
		// A TD has a register for the machine its host built, and a document
		// that lists no value for it leaves the host free to build any.
		if doc.Image.HasMachineRegister() && !policy.AllowNoMachine {
			return refuse("the guest's launch document lists no machine the guest may be")
		}
		return nil
	}
	rtmr0, err := res.Claims.RTMR(0)
	if err != nil {
		return &VerificationError{Err: fmt.Errorf("the launch document pins the guest's machine, and the evidence carries no RTMR[0]: %w", err)}
	}
	if !doc.Machine.Allows(rtmr0) {
		return refuse("the guest's machine (RTMR[0] %x) is none of the %d its launch document lists", rtmr0, len(doc.Machine.RTMR0))
	}
	return nil
}

// handshakeChains returns the pinned launch document, if the policy pins one,
// and the event chains a serving certificate's quote may carry. The quote can
// predate a bind or the sandbox's admission, so every phase the pinned
// documents allow is acceptable. When the documents are not all pinned the
// chain is unknown until a fresh attestation supplies it, and nil skips the
// comparison.
func handshakeChains(policy Policy) (*Document, [][]string, error) {
	if policy.Launch == nil {
		return nil, nil, nil
	}
	doc, err := Parse(policy.Launch)
	if err != nil {
		return nil, nil, fmt.Errorf("policy launch document: %w", err)
	}
	if policy.Bind == nil {
		// Unbound, the launch document is the whole chain. A policy that also
		// takes a bound guest does not know the bind's digest yet.
		if policy.Authority == nil {
			ready, err := ExpectedEvents(policy.Launch, nil, PhaseReady)
			if err != nil {
				return nil, nil, err
			}
			return doc, [][]string{ready}, nil
		}
		return doc, nil, nil
	}
	parsed, err := ParseBind(policy.Bind)
	if err != nil {
		return nil, nil, fmt.Errorf("policy bind: %w", err)
	}
	bind := &SignedBind{Raw: policy.Bind, Doc: parsed}
	var chains [][]string
	if events, err := ExpectedEvents(policy.Launch, nil, PhaseReady); err == nil {
		chains = append(chains, events)
	}
	for _, phase := range []Phase{PhaseBound, PhaseRunning} {
		if events, err := ExpectedEvents(policy.Launch, bind, phase); err == nil {
			chains = append(chains, events)
		}
	}
	return doc, chains, nil
}

// checkMeasuredIdentity enforces the image pin and the launch binding on
// signature-verified claims. chains lists the acceptable event chains; nil
// skips the binding, which only the handshake gate may do.
func checkMeasuredIdentity(policy Policy, res *teetypes.VerificationResult, chains [][]string) error {
	if res.Platform.Family() != policy.Image.Family() {
		return refuse("guest platform is %q, policy pins a %s image", res.Platform, policy.Image.Family())
	}
	// The engine already refuses debug guests; a claim that says otherwise, or
	// says nothing, must not read as a pass.
	if debug, err := res.Claims.DebugEnabled(); err != nil || debug {
		return refuse("guest debug state is not provably off (debug=%v, %v)", debug, err)
	}
	if res.Platform.Family() == teetypes.FamilyTDX {
		if err := checkTDAttributes(res); err != nil {
			return err
		}
	}
	if err := policy.Image.Verify(res); err != nil {
		return &VerificationError{Err: err}
	}
	if chains == nil {
		return nil
	}
	var last error
	for _, events := range chains {
		// SEV-SNP has no runtime register: HOSTDATA binds the launch key and the
		// evidence transcript binds the events.
		digests := events
		if !res.Platform.HasRegisters() {
			digests = nil
		}
		if last = runtimemeasure.VerifyBinding(res, policy.LaunchKey, digests); last == nil {
			return nil
		}
	}
	return &VerificationError{Err: last}
}

// TD attributes that hand a TD's host a way into it.
const (
	// tdAttrUnderDebug is the group a TD under debug or profiling sets.
	tdAttrUnderDebug uint64 = 0xff
	// tdAttrMigratable lets a migration TD of the host's choosing export it.
	tdAttrMigratable uint64 = 1 << 29
)

// checkTDAttributes refuses a TD that its host can debug, profile or migrate.
// The engine itself refuses the debug bit alone.
func checkTDAttributes(res *teetypes.VerificationResult) error {
	text, _ := res.Claims.PlatformData["td_attributes"].(string)
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != 8 {
		return refuse("the TD's attributes are not in its claims as eight bytes (%q)", text)
	}
	if attributes := binary.LittleEndian.Uint64(raw); attributes&(tdAttrUnderDebug|tdAttrMigratable) != 0 {
		return refuse("the TD's attributes %#x let its host debug, profile or migrate it", attributes)
	}
	return nil
}

// imageMatchesDocument requires the signed document to name the pinned image,
// so a document signed for one build cannot vouch for a guest of another.
func imageMatchesDocument(identity runtimemeasure.ImageIdentity, image Image) error {
	if identity.Family() != image.Family() {
		return fmt.Errorf("launch document is for a %s image, policy pins %s", image.Family(), identity.Family())
	}
	found := false
	for _, variant := range identity.LaunchDigests() {
		found = found || hex.EncodeToString(variant.Digest[:]) == image.Measurement
	}
	if !found {
		return fmt.Errorf("launch document names image measurement %s, which the policy does not pin", image.Measurement)
	}
	pinned := identity.RTMRs()
	if len(pinned) != len(image.RTMRs) {
		return fmt.Errorf("launch document pins %d registers, policy pins %d", len(image.RTMRs), len(pinned))
	}
	for idx, value := range pinned {
		if image.RTMRs[idx] != hex.EncodeToString(value[:]) {
			return fmt.Errorf("launch document RTMR[%d] does not match the pinned image", idx)
		}
	}
	return nil
}
