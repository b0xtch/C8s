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
	// Receipt is the guest's receipt for its bind, in an answer to a bind:
	// see VerifyBoundReceipt.
	Receipt *SignedReceipt
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
// key can take the bind, and VerifyBound judges its answer.
func VerifyReady(ctx context.Context, policy Policy, engine Engine, r *Relayed, now time.Time) (*ReadyTD, error) {
	if err := policy.validate(); err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(r.Certificate)
	if err != nil {
		return nil, refuse("the relayed certificate does not parse: %v", err)
	}
	state := &StateResponse{Phase: r.Phase, Launch: r.Launch, Signature: r.Signature, Events: r.Events, Bind: r.Bind}
	// Nothing is released on this verdict, so the root CA CRL may be relayed.
	return verifyReady(withStapledRoot(WithCollateralSource(ctx, r.source)), policy, engine, leaf, state, now)
}

// VerifyReadyToRelease is VerifyReady for a verifier whose verdict lets a
// secret go to the guest later, as a key service's does: the root CA CRL
// under it is one the verifier fetched itself.
func VerifyReadyToRelease(ctx context.Context, policy Policy, engine Engine, r *Relayed, now time.Time) (*ReadyTD, error) {
	if err := policy.validate(); err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(r.Certificate)
	if err != nil {
		return nil, refuse("the relayed certificate does not parse: %v", err)
	}
	state := &StateResponse{Phase: r.Phase, Launch: r.Launch, Signature: r.Signature, Events: r.Events, Bind: r.Bind}
	return verifyReady(WithCollateralSource(ctx, r.source), policy, engine, leaf, state, now)
}

// verifyReady judges a guest's state and serving certificate as those of a
// guest nobody has bound.
func verifyReady(ctx context.Context, policy Policy, engine Engine, leaf *x509.Certificate, state *StateResponse, now time.Time) (*ReadyTD, error) {
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
	ready := &ReadyTD{Document: doc, Launch: state.Launch, Signature: state.Signature, InstanceKey: leaf.PublicKey}
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
	// The root CA CRL under this verdict is one the verifier fetched itself.
	return VerifyAttestation(WithCollateralSource(ctx, r.source), policy, engine, instanceKey, bind.Doc.EvidenceNonce(), resp)
}

// VerifyBoundReceipt judges a guest's relayed answer to a bind by its
// receipt: the word of the instance key that VerifyReady found, fresh for the
// bind's nonce, that the guest took this bind, extended what the bind's
// documents imply and reached its phase. policy is the policy for the bound
// guest and pins the bind.
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
	return VerifyBindReceipt(policy, ready.InstanceKey, bind, r.Receipt)
}

// VerdictOn is the verdict a verifier may keep on att, which it judged at now
// under policy with engine, for the owner's next process: see Kept. leaf is
// the certificate that carried the key, or nil. A nil verdict with no error
// is an engine that does not say what it requires. An error is a judgment
// that does not stand even now.
func VerdictOn(policy Policy, engine Engine, att *Attestation, leaf *x509.Certificate, now time.Time) (*Verdict, error) {
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
