package podcvm

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/go-tdx-guest/pcs"
	tdxverify "github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/teeverify"
	agratls "github.com/confidential-dot-ai/attestation-go/ratls"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// Policy is what a verifier requires of a pod CVM before trusting it.
type Policy struct {
	// Image pins the guest build; load it from the build's manifest.json.
	Image runtimemeasure.ImageIdentity
	// LaunchKey is the launch public key, the exact PEM bytes the guest measured.
	LaunchKey []byte
	// Launch, when set, is the exact launch.yaml the guest must have measured.
	// Unset accepts any document LaunchKey signed that matches Tenant and Sandbox.
	Launch []byte
	// Tenant and Sandbox, when set, must equal the measured document's.
	Tenant  string
	Sandbox string
	// AllowStaged accepts a guest that has measured its launch document but not
	// yet its workload image. Release workload credentials only when false.
	AllowStaged bool
}

func (p Policy) validate() error {
	if p.Image == nil {
		return errors.New("policy pins no guest image")
	}
	if _, err := parsePublicKey(string(p.LaunchKey)); err != nil {
		return fmt.Errorf("policy launch key: %w", err)
	}
	if p.Launch == nil && (p.Tenant == "" || p.Sandbox == "") {
		return errors.New("policy must pin the launch document, or both tenant and sandbox")
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

// Collateral selects how much of the platform's TCB state the engine checks.
type Collateral string

const (
	// CollateralRequired fetches Intel's TCB info, QE identity and CRLs and
	// judges the platform, the TDX module and the quoting enclave against
	// them. Each must be UpToDate unless the options accept another status.
	CollateralRequired Collateral = "required"
	// CollateralSkip verifies the quote signature and PCK chain against the
	// pinned Intel root, and the quoting enclave against Intel's pinned
	// identity. The TCB level, the quoting enclave's version and revocation go
	// unchecked.
	CollateralSkip Collateral = "skip"
)

// EngineOptions configures the in-process verifier.
type EngineOptions struct {
	Collateral Collateral
	// AcceptTCBStatus names Intel TCB statuses, besides UpToDate, that the
	// platform, its TDX module or its quoting enclave may have. It applies with
	// CollateralRequired only. Revoked cannot be accepted.
	AcceptTCBStatus []string
}

type dcapEngine struct {
	collateral Collateral
	accept     map[string]bool
	cache      *collateralCache
	fetch      trust.HTTPSGetter
}

// NewEngine returns the in-process verifier, built on attestation-go and
// go-tdx-guest like `c8s verify`.
func NewEngine(opts EngineOptions) (Engine, error) {
	switch opts.Collateral {
	case CollateralRequired, CollateralSkip:
	default:
		return nil, fmt.Errorf("collateral mode must be %q or %q", CollateralRequired, CollateralSkip)
	}
	accept := map[string]bool{}
	for _, status := range opts.AcceptTCBStatus {
		if !slices.Contains(acceptableTCBStatuses, status) {
			return nil, fmt.Errorf("TCB status %q cannot be accepted: choose from %s", status, strings.Join(acceptableTCBStatuses, ", "))
		}
		accept[status] = true
	}
	if len(accept) > 0 && opts.Collateral != CollateralRequired {
		return nil, errors.New("accepting a TCB status needs collateral: without it no status is known")
	}
	return &dcapEngine{
		collateral: opts.Collateral,
		accept:     accept,
		cache:      newCollateralCache(),
		fetch: &trust.RetryHTTPSGetter{
			Timeout: 30 * time.Second, MaxRetryDelay: 5 * time.Second, Getter: &trust.SimpleHTTPSGetter{},
		},
	}, nil
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

// tcbClaim is where the engine records the TCB finding in a result's claims.
const tcbClaim = "c8s_tcb"

// TCBOf returns the TCB finding of a result verified with collateral, or nil.
func TCBOf(res *teetypes.VerificationResult) *TCBFinding {
	if res == nil || res.Claims.PlatformData == nil {
		return nil
	}
	finding, _ := res.Claims.PlatformData[tcbClaim].(*TCBFinding)
	return finding
}

// verifyTDX judges the quote offline first: signature, PCK chain, binding and
// the quoting enclave's identity. Only a quote that passed is worth a fetch,
// because the collateral lookup is keyed on fields of the PCK certificate, and
// a failure before this point must read as a verdict on the evidence.
func (e *dcapEngine) verifyTDX(ctx context.Context, env teetypes.AttestationEvidence, params teetypes.VerifyParams) (*teetypes.VerificationResult, error) {
	res, err := teeverify.VerifyEnvelope(ctx, env, params, teeverify.Options{})
	if err != nil {
		return nil, &VerificationError{Err: err}
	}
	quote, err := parseTDQuote(env.Evidence)
	if err != nil {
		return nil, &VerificationError{Err: err}
	}
	if err := checkTDQuoteOrigin(quote); err != nil {
		return nil, &VerificationError{Err: err}
	}
	if e.collateral != CollateralRequired {
		return res, nil
	}

	// go-tdx-guest authenticates the collateral (Intel's signing chains, the
	// validity windows, the CRLs) and checks the PCK chain against the CRLs.
	// Its own TCB verdict is not used: see evaluateTDXTCB.
	fetches := &fetchRecorder{cache: e.cache, inner: e.fetch}
	err = tdxverify.TdxQuoteContext(ctx, quote, &tdxverify.Options{GetCollateral: true, CheckRevocations: true, Getter: fetches})
	// Intel PCS being unreachable says nothing about the evidence.
	if fetches.caused(err) {
		return nil, fmt.Errorf("TDX collateral unavailable: %w", err)
	}
	// The TCB status check is the last thing go-tdx-guest does with each
	// document, so a failure there still means the documents are authentic.
	if err != nil && !strings.Contains(err.Error(), "failed TCB status check") {
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
	finding, err := evaluateTDXTCB(quote, tcbInfo, qeIdentity)
	if err != nil {
		return nil, &VerificationError{Err: err}
	}
	for _, c := range finding.components() {
		switch {
		case c.status == TCBUpToDate:
		case c.status == TCBRevoked:
			return nil, refuse("%s TCB level is revoked", c.name)
		case !e.accept[c.status]:
			return nil, refuse("%s TCB status is %s, which this policy does not accept (advisories: %s)",
				c.name, c.status, strings.Join(finding.Advisories, ", "))
		}
	}
	// Only collateral that carried a verification to success is worth keeping.
	fetches.commit()
	res.CollateralVerified = true
	if res.Claims.PlatformData == nil {
		res.Claims.PlatformData = map[string]any{}
	}
	res.Claims.PlatformData[tcbClaim] = finding
	return res, nil
}

// Attestation is a verified fresh attestation of one pod CVM.
type Attestation struct {
	Document *Document
	// Launch is the exact launch.yaml the guest measured.
	Launch []byte
	Events []string
	Phase  Phase
	Result *teetypes.VerificationResult
	// InstanceKey is the PKIX DER of the guest-generated key the evidence binds.
	InstanceKey []byte
}

// VerifyAttestation is the trust gate. It accepts resp only if hardware
// evidence proves, for the guest holding instanceKey: the pinned image booted,
// it was launched for policy.LaunchKey, it measured exactly the launch document
// and workload the policy expects, and the evidence is fresh for nonce.
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
		return nil, refuse("guest measured launch document %s, policy pins %s", LaunchDigest(resp.Launch), LaunchDigest(policy.Launch))
	}
	if policy.Tenant != "" && doc.Tenant != policy.Tenant {
		return nil, refuse("guest belongs to tenant %q, policy pins %q", doc.Tenant, policy.Tenant)
	}
	if policy.Sandbox != "" && doc.Sandbox != policy.Sandbox {
		return nil, refuse("guest is sandbox %q, policy pins %q", doc.Sandbox, policy.Sandbox)
	}
	if err := imageMatchesDocument(policy.Image, doc.Image); err != nil {
		return nil, &VerificationError{Err: err}
	}
	if resp.Phase == PhaseStaged && !policy.AllowStaged {
		return nil, refuse("guest has not admitted its workload yet (phase %s)", resp.Phase)
	}
	// Events are derived from the signed document, never taken from the guest.
	events, err := ExpectedEvents(resp.Launch, doc, resp.Phase)
	if err != nil {
		return nil, &VerificationError{Err: err}
	}
	if !slices.Equal(events, resp.Events) {
		return nil, refuse("guest reports events %v, the launch document implies %v", resp.Events, events)
	}
	reportData, err := ReportData(instanceKey, nonce, events)
	if err != nil {
		return nil, err
	}
	res, err := engine.VerifyEvidence(ctx, resp.Evidence, reportData)
	if err != nil {
		return nil, err
	}
	if err := checkMeasuredIdentity(policy, res, [][]string{events}); err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(instanceKey)
	if err != nil {
		return nil, fmt.Errorf("encode instance key: %w", err)
	}
	return &Attestation{Document: doc, Launch: resp.Launch, Events: events, Phase: resp.Phase, Result: res, InstanceKey: der}, nil
}

// VerifyServingCert is the handshake gate: the leaf must be self-signed under
// its own attested key, and that key must have been generated inside a guest
// of the pinned image launched for policy.LaunchKey. It is not a freshness
// proof and does not replace VerifyAttestation.
func VerifyServingCert(ctx context.Context, policy Policy, engine Engine, leaf *x509.Certificate, now time.Time) error {
	if err := policy.validate(); err != nil {
		return err
	}
	body, err := certutil.AuthenticateLeafBody(leaf, now)
	if err != nil {
		return &VerificationError{Err: err}
	}
	if body != certutil.BodySelfSigned {
		return refuse("agent serving certificate is not self-signed, so nothing authenticates its body")
	}
	att, err := ratls.ExtractAttestation(leaf)
	if err != nil {
		return &VerificationError{Err: err}
	}
	env, err := att.Envelope()
	if err != nil {
		return &VerificationError{Err: err}
	}
	rd, err := agratls.ReportDataForKey(leaf.PublicKey, nil)
	if err != nil {
		return &VerificationError{Err: err}
	}
	res, err := engine.VerifyEvidence(ctx, env, rd[:sha512.Size384])
	if err != nil {
		return err
	}
	// The certificate quote may predate workload admission, so either chain of
	// a pinned document is acceptable here. Without a pinned document the
	// chain is unknown until the fresh attestation supplies it.
	var chains [][]string
	if policy.Launch != nil {
		doc, err := Parse(policy.Launch)
		if err != nil {
			return fmt.Errorf("policy launch document: %w", err)
		}
		for _, phase := range []Phase{PhaseStaged, PhaseRunning} {
			if events, err := ExpectedEvents(policy.Launch, doc, phase); err == nil {
				chains = append(chains, events)
			}
		}
	}
	return checkMeasuredIdentity(policy, res, chains)
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
	if err := policy.Image.Verify(res); err != nil {
		return &VerificationError{Err: err}
	}
	if chains == nil {
		return nil
	}
	var last error
	for _, events := range chains {
		// SEV-SNP has no runtime register: HOSTDATA binds the launch key and the
		// session transcript binds the events.
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
