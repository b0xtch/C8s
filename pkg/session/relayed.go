package session

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// Relayed is what a guest says of itself, handed on by a host that is
// outside the trust boundary: the daemon's Evidence. Nothing in it is trusted
// until VerifyReady or VerifyBound has judged it.
type Relayed struct {
	// Certificate is the guest's serving certificate, DER.
	Certificate []byte
	// Phase, Launch, Signature, Events, Bind and BindSignature are what the
	// guest answers a state or an attestation request with.
	Phase         Phase
	Launch        []byte
	Signature     string
	Events        []string
	Bind          []byte
	BindSignature string
	// Evidence is the platform's evidence over the bind's nonce in the
	// guest's encoding, once a bound guest has taken it.
	Evidence []byte
	// BindQuote is where the guest says the quote over its bind's nonce
	// stands: BindQuoteTrying, BindQuoteTaken or BindQuoteGivenUp.
	BindQuote string
	// Receipt is the guest's receipt for its bind, in an answer to a bind:
	// see VerifyBoundReceipt.
	Receipt *SignedReceipt
	// ReadyCertificate is the last certificate a bound guest issued before
	// its bind, DER: its quote binds the key the receipt is signed under.
	ReadyCertificate []byte
	// Collateral is a CollateralResponse: the vendor's documents as the
	// guest's host handed them in.
	Collateral []byte
}

// source hands the engine the relayed vendor documents. The engine holds each
// to the vendor's signature and date, so a host gains nothing by changing one.
func (r *Relayed) source(context.Context) []CollateralDocument {
	if len(r.Collateral) == 0 || len(r.Collateral) > MaxCollateralBytes {
		return nil
	}
	var answer CollateralResponse
	if json.Unmarshal(r.Collateral, &answer) != nil || len(answer.Documents) > maxStapledDocuments {
		return nil
	}
	return answer.Documents
}

// VerifyReady proves, from relayed evidence, that the guest holding the
// certificate's key is the pinned image, launched under the pinned launch
// key, and had measured nothing beyond its launch document when the
// certificate was issued.
//
// It proves neither freshness nor that the key is live. That is enough to
// sign a bind for the key, which is not secret: only the guest holding the
// key can take the bind, and VerifyBound judges its answer. So the verdict
// may rest on the vendor's documents as the guest's host relayed them. It is
// not enough to seal anything to the guest with that bind: see
// VerifyReadyToRelease.
func VerifyReady(ctx context.Context, policy Policy, engine Engine, r *Relayed, now time.Time) (*ReadyTD, error) {
	if err := policy.validate(); err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(r.Certificate)
	if err != nil {
		return nil, refuse("the relayed certificate does not parse: %v", err)
	}
	state := &StateResponse{Phase: r.Phase, Launch: r.Launch, Signature: r.Signature, Events: r.Events, Bind: r.Bind}
	// Nothing secret is sent on this verdict.
	return verifyReady(AllowHandedDocuments(WithCollateralSource(ctx, r.source)), policy, engine, leaf, state, now, false)
}

// VerifyReadyToRelease is VerifyReady for a verifier whose verdict lets a
// secret go to the guest, as a key service's does and a binder's that seals a
// command or credentials with its bind (SealWithBind). The verdict rests on
// the vendor's documents as this verifier fetched them from the vendor itself
// within the last hour, and on none that was relayed: a host can relay one
// from before a key was revoked, while it is still within its dates. A
// verifier that cannot reach the vendor for longer gets ErrStaleDocuments,
// and sends nothing.
func VerifyReadyToRelease(ctx context.Context, policy Policy, engine Engine, r *Relayed, now time.Time) (*ReadyTD, error) {
	if err := policy.validate(); err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(r.Certificate)
	if err != nil {
		return nil, refuse("the relayed certificate does not parse: %v", err)
	}
	state := &StateResponse{Phase: r.Phase, Launch: r.Launch, Signature: r.Signature, Events: r.Events, Bind: r.Bind}
	return verifyReady(ctx, policy, engine, leaf, state, now, true)
}

// verifyReady judges a guest's state and serving certificate as those of a
// guest nobody has bound. The verdict says until when a secret may be sealed
// to the guest on it, and that none may when it does not stand as one for a
// release (standsNot). With release such a verdict is none.
func verifyReady(ctx context.Context, policy Policy, engine Engine, leaf *x509.Certificate, state *StateResponse, now time.Time, release bool) (*ReadyTD, error) {
	doc, err := VerifySigned(policy.LaunchKey, state.Launch, state.Signature)
	if err != nil {
		return nil, &VerificationError{Err: err}
	}
	if err := imageMatchesDocument(policy.Image, doc.Image); err != nil {
		return nil, &VerificationError{Err: err}
	}
	events := []string{DocumentDigest(state.Launch)}
	if state.Phase != PhaseReady || len(state.Bind) > 0 || !slices.Equal(state.Events, events) {
		return nil, refuse("guest is bound already, or on its way to be (phase %s, events %v)", state.Phase, state.Events)
	}
	res, err := servingCertResult(ctx, policy, engine, leaf, now, doc, [][]string{events})
	if err != nil {
		return nil, err
	}
	// The quote just passed under report data made from these keys, so it
	// binds them to the guest that holds the certificate's key.
	oneTime, err := oneTimeKeysOf(leaf)
	if err != nil {
		return nil, &VerificationError{Err: err}
	}
	if oneTime == nil {
		return nil, refuse("the guest's evidence binds no one-time keys: a receipt for its bind could not be told from one its session signed")
	}
	ready := &ReadyTD{Document: doc, Launch: state.Launch, Signature: state.Signature, InstanceKey: leaf.PublicKey, OneTime: oneTime}
	// A document that was handed over may hide a newer one. That is enough
	// for a bind, which is not secret, and for nothing sealed with it.
	until := stands(now, leaf, res)
	switch err := standsNot(now, until, leaf, res); {
	case err == nil:
		ready.Until = until
	case release:
		return nil, err
	}
	// Evidence of a TEE with no such register has no machine to report.
	if machine, err := res.Claims.RTMR(0); err == nil {
		ready.Machine = machine
	}
	return ready, nil
}

// VerifyBound judges a guest's relayed answer to a bind: evidence that must
// be fresh for the bind's nonce and bound to instanceKey, the key VerifyReady
// found. policy is the policy for the bound guest and pins the bind.
func VerifyBound(ctx context.Context, policy Policy, engine Engine, instanceKey crypto.PublicKey, bind *SignedBind, r *Relayed) (*Attestation, error) {
	if !bytes.Equal(policy.Bind, bind.Raw) {
		return nil, errors.New("the policy for the bound guest must pin the bind that was sent")
	}
	if len(r.Evidence) == 0 {
		return nil, refuse("the answer to the bind carries no evidence")
	}
	var evidence teetypes.AttestationEvidence
	if err := json.Unmarshal(r.Evidence, &evidence); err != nil {
		return nil, refuse("the relayed evidence does not parse: %v", err)
	}
	resp := &AttestResponse{
		Evidence: evidence, Launch: r.Launch, Signature: r.Signature, Events: r.Events, Phase: r.Phase,
		Bind: r.Bind, BindSignature: r.BindSignature,
	}
	// A binder goes on to send the guest secrets on this verdict, so it rests
	// on the vendor's documents as the binder fetched them itself.
	return VerifyAttestation(ctx, policy, engine, instanceKey, bind.Doc.EvidenceNonce(), resp)
}

// ErrNoBindQuote is a guest that says it gave up on the quote over its
// bind's nonce. Its binder asks it for an attestation itself, and ends the
// session if none comes.
var ErrNoBindQuote = errors.New("the guest gave up on the quote over its bind's nonce")

// HoldBound holds the quote a guest took over its bind's nonce to everything
// that needs none of the vendor's documents: its signature chains to the
// vendor's root, its report data binds the bind's nonce and instanceKey, and
// its register replays from the events it carries, under the pinned image
// and bind. It is for a binder whose engine could not judge the quote for
// want of a document: VerifyBound failed, and with no refusal. A quote that
// passes leaves the session running until the document comes, held to its
// receipt with BindReceipt.Confirmed. One that fails ends the session.
//
// The attestation is held and stays unjudged: it says nothing of where the
// platform's TCB stands, no verdict is kept on it, and nothing is released
// on it.
func HoldBound(ctx context.Context, policy Policy, engine Engine, instanceKey crypto.PublicKey, bind *SignedBind, r *Relayed) (*Attestation, error) {
	att, err := VerifyBound(offline(ctx), policy, engine, instanceKey, bind, r)
	if err != nil {
		return nil, err
	}
	att.Held = true
	return att, nil
}

// VerifyBoundReceipt judges a guest's relayed answer to a bind by its
// receipt: the word of the one-time key that VerifyReady found bound to the
// guest, fresh for the bind's nonce, that the guest took this bind, extended
// what the bind's documents imply and reached its phase. policy is the policy
// for the bound guest and pins the bind.
//
// A binder may go on with a receipt at once. It still gets the quote over
// the bind's nonce, from the same answer or from the guest's evidence a
// moment later, judges it with VerifyBound and holds it to the receipt with
// BindReceipt.Confirmed: a guest whose quote disagrees is ended. No verdict
// is kept on a receipt.
func VerifyBoundReceipt(policy Policy, ready *ReadyTD, bind *SignedBind, r *Relayed) (*BindReceipt, error) {
	if !bytes.Equal(policy.Bind, bind.Raw) {
		return nil, errors.New("the policy for the bound guest must pin the bind that was sent")
	}
	if err := policy.validate(); err != nil {
		return nil, err
	}
	if policy.Launch != nil && !bytes.Equal(policy.Launch, ready.Launch) {
		return nil, refuse("the guest that was verified measured launch document %s, policy pins %s", DocumentDigest(ready.Launch), DocumentDigest(policy.Launch))
	}
	return VerifyBindReceipt(policy, ready.InstanceKey, ready.OneTime, bind, r.Receipt)
}

// VerdictOn is the verdict a verifier may keep on att, which it judged at now
// under policy with engine, for the owner's next process: see Kept. leaf is
// the certificate that carried the key, or nil. A nil verdict with no error
// is an engine that does not say what it requires. An error is a judgment
// that does not stand even now.
func VerdictOn(policy Policy, engine Engine, att *Attestation, leaf *x509.Certificate, now time.Time) (*Verdict, error) {
	if att.Held {
		return nil, errors.New("no verdict is kept on evidence that was held and never judged")
	}
	until := stands(now, leaf, att.Result)
	if err := standsNot(now, until, leaf, att.Result); err != nil {
		return nil, err
	}
	scope := scopeOf(policy, engine)
	if scope == "" {
		return nil, nil
	}
	// The wall clock alone, as a file carries it.
	return &Verdict{SchemaVersion: VerdictSchema, InstanceKey: att.InstanceKey, Scope: scope, Until: until.UTC().Round(0)}, nil
}
