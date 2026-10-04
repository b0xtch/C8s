package session

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

func receiptKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// receiptBind is a bind for the guest that holds instance, with or without a
// sandbox image.
func receiptBind(t *testing.T, instance crypto.PublicKey, sandbox bool) *SignedBind {
	t.Helper()
	policy := BindPolicy{}
	if sandbox {
		policy.Sandbox = &Sandbox{Image: "registry.example/agent@sha256:" + strings.Repeat("ab", 32)}
	}
	bind, err := NewBind(BindOptions{
		Authority: receiptKey(t), InstanceKey: instance, Tenant: "acme", Session: "sbx-1", NotAfter: time.Now().Add(time.Minute), Policy: policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	return bind
}

// signedReceipt signs whatever a guest might say in a receipt's place.
func signedReceipt(t *testing.T, key *ecdsa.PrivateKey, domain string, raw []byte) *SignedReceipt {
	t.Helper()
	signature, err := operatorauth.SignDetached(key, append([]byte(domain), raw...))
	if err != nil {
		t.Fatal(err)
	}
	return &SignedReceipt{Receipt: raw, Signature: signature}
}

func marshalReceipt(t *testing.T, receipt any) []byte {
	t.Helper()
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func refusedByVerdict(err error) bool {
	var refused *VerificationError
	return errors.As(err, &refused)
}

// A receipt is the instance key's word on one bind: the bind's digest and
// nonce, what the guest extended after its launch document, and the phase.
func TestBindReceiptSaysWhatTheGuestExtended(t *testing.T) {
	key := receiptKey(t)
	for name, tc := range map[string]struct {
		sandbox bool
		phase   Phase
		policy  Policy
		events  int
	}{
		"running, with a sandbox":            {sandbox: true, phase: PhaseRunning, events: 2},
		"running, without one":               {phase: PhaseRunning, events: 1},
		"bound and no more, where permitted": {sandbox: true, phase: PhaseBound, policy: Policy{AllowBound: true}, events: 1},
	} {
		bind := receiptBind(t, &key.PublicKey, tc.sandbox)
		events, err := ExpectedEvents(nil, bind, tc.phase)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := NewBindReceipt(key, bind, events[1:], tc.phase)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		receipt, err := VerifyBindReceipt(tc.policy, &key.PublicKey, bind, signed)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if receipt.SchemaVersion != BindReceiptSchema || receipt.Bind != DocumentDigest(bind.Raw) || receipt.Nonce != bind.Doc.Nonce ||
			receipt.Phase != tc.phase || len(receipt.Events) != tc.events || receipt.Events[0] != DocumentDigest(bind.Raw) {
			t.Fatalf("%s: the receipt says %+v", name, receipt)
		}
	}
}

func TestBindReceiptIsRefused(t *testing.T) {
	key, other := receiptKey(t), receiptKey(t)
	bind := receiptBind(t, &key.PublicKey, true)
	events, err := ExpectedEvents(nil, bind, PhaseRunning)
	if err != nil {
		t.Fatal(err)
	}
	extended := events[1:]
	good := BindReceipt{SchemaVersion: BindReceiptSchema, Bind: DocumentDigest(bind.Raw), Nonce: bind.Doc.Nonce, Events: extended, Phase: PhaseRunning}
	said := func(change func(*BindReceipt)) *SignedReceipt {
		receipt := good
		receipt.Events = slices.Clone(good.Events)
		change(&receipt)
		return signedReceipt(t, key, receiptDomain, marshalReceipt(t, receipt))
	}
	genuine, err := NewBindReceipt(key, bind, extended, PhaseRunning)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBindReceipt(Policy{}, &key.PublicKey, bind, genuine); err != nil {
		t.Fatalf("the genuine receipt: %v", err)
	}
	otherBind := receiptBind(t, &key.PublicKey, true)
	forOther, err := NewBindReceipt(key, otherBind, extended, PhaseRunning)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	withField := marshalReceipt(t, map[string]any{
		"schemaVersion": BindReceiptSchema, "bind": good.Bind, "nonce": good.Nonce, "events": good.Events, "phase": good.Phase, "note": "more",
	})
	for name, tc := range map[string]struct {
		signed *SignedReceipt
		key    crypto.PublicKey
		policy Policy
	}{
		"no receipt":       {signed: nil},
		"an empty receipt": {signed: &SignedReceipt{}},
		"a receipt signed by another key": {
			signed: signedReceipt(t, other, receiptDomain, genuine.Receipt),
		},
		"a receipt held to a key the bind does not name": {
			signed: signedReceipt(t, other, receiptDomain, genuine.Receipt), key: &other.PublicKey,
		},
		"a key that signs no receipt": {signed: genuine, key: edKey.Public()},
		"a receipt changed after it was signed": {
			signed: &SignedReceipt{Receipt: marshalReceipt(t, BindReceipt{
				SchemaVersion: BindReceiptSchema, Bind: good.Bind, Nonce: good.Nonce, Events: good.Events[:1], Phase: PhaseRunning,
			}), Signature: genuine.Signature},
		},
		"a signature the key made over the receipt alone": {signed: signedReceipt(t, key, "", genuine.Receipt)},
		"a signature the key made as something else":      {signed: signedReceipt(t, key, "c8s-bind/v1 signature\x00", genuine.Receipt)},
		"no signature":                  {signed: &SignedReceipt{Receipt: genuine.Receipt}},
		"a signature that is no base64": {signed: &SignedReceipt{Receipt: genuine.Receipt, Signature: "not a signature"}},
		"a receipt for another bind":    {signed: forOther},
		"a receipt for another nonce":   {signed: said(func(r *BindReceipt) { r.Nonce = otherBind.Doc.Nonce })},
		"a receipt of another version":  {signed: said(func(r *BindReceipt) { r.SchemaVersion = "c8s-bind-receipt/v2" })},
		"a guest that says it is ready": {
			signed: said(func(r *BindReceipt) { r.Phase, r.Events = PhaseReady, nil }), policy: Policy{AllowBound: true},
		},
		"a guest that is bound and no more, where that is not permitted": {
			signed: said(func(r *BindReceipt) { r.Phase, r.Events = PhaseBound, r.Events[:1] }),
		},
		"a phase nobody knows": {signed: said(func(r *BindReceipt) { r.Phase = "sealed" }), policy: Policy{AllowBound: true}},
		"a running guest that did not extend its image": {
			signed: said(func(r *BindReceipt) { r.Events = r.Events[:1] }),
		},
		"a guest that extended something more": {
			signed: said(func(r *BindReceipt) { r.Events = append(r.Events, r.Events[1]) }),
		},
		"a guest that extended the image before the bind": {
			signed: said(func(r *BindReceipt) { r.Events[0], r.Events[1] = r.Events[1], r.Events[0] }),
		},
		"a guest that extended nothing": {signed: said(func(r *BindReceipt) { r.Events = nil })},
		"a bound guest that says it extended its image": {
			signed: said(func(r *BindReceipt) { r.Phase = PhaseBound }), policy: Policy{AllowBound: true},
		},
		"a receipt with a field no receipt has": {signed: signedReceipt(t, key, receiptDomain, withField)},
		"a receipt with something after it": {
			signed: signedReceipt(t, key, receiptDomain, append(slices.Clone(genuine.Receipt), []byte(` {}`)...)),
		},
		"a receipt that is no document": {signed: signedReceipt(t, key, receiptDomain, []byte(`"running"`))},
		// Both would pass but for their size: a decoder takes blanks after a
		// document, and a signature is read with the blanks around it cut.
		"a receipt larger than one is": {
			signed: signedReceipt(t, key, receiptDomain, append(slices.Clone(genuine.Receipt), []byte(strings.Repeat(" ", MaxReceiptBytes))...)),
		},
		"a signature larger than one is": {
			signed: &SignedReceipt{Receipt: genuine.Receipt, Signature: genuine.Signature + strings.Repeat(" ", maxSignatureSize)},
		},
		"a receipt that names another bind beside this bind's nonce and events": {
			signed: said(func(r *BindReceipt) { r.Bind = DocumentDigest(otherBind.Raw) }),
		},
	} {
		instance := tc.key
		if instance == nil {
			instance = &key.PublicKey
		}
		if receipt, err := VerifyBindReceipt(tc.policy, instance, bind, tc.signed); !refusedByVerdict(err) {
			t.Errorf("%s passed as the guest's receipt for the bind: %+v, %v", name, receipt, err)
		}
	}
}

// The quote that follows a receipt confirms it only if it shows the same
// guest: bound by the receipt's bind, in its phase, with a register that
// holds the launch document and then exactly what the receipt lists.
func TestQuoteConfirmsItsReceipt(t *testing.T) {
	key := receiptKey(t)
	bind := receiptBind(t, &key.PublicKey, true)
	launch := []byte("launch document")
	events, err := ExpectedEvents(launch, bind, PhaseRunning)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := NewBindReceipt(key, bind, events[1:], PhaseRunning)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := VerifyBindReceipt(Policy{}, &key.PublicKey, bind, signed)
	if err != nil {
		t.Fatal(err)
	}
	quoted := func(change func(*Attestation)) *Attestation {
		att := &Attestation{Launch: launch, Bind: bind, Events: slices.Clone(events), Phase: PhaseRunning}
		if change != nil {
			change(att)
		}
		return att
	}
	if err := receipt.Confirmed(quoted(nil)); err != nil {
		t.Fatalf("the quote of the guest the receipt describes: %v", err)
	}
	if err := receipt.Confirmed(nil); !refusedByVerdict(err) {
		t.Errorf("no quote confirmed the receipt: %v", err)
	}
	for name, change := range map[string]func(*Attestation){
		"a guest nobody bound":                        func(a *Attestation) { a.Bind = nil },
		"a guest bound by another bind":               func(a *Attestation) { a.Bind = receiptBind(t, &key.PublicKey, true) },
		"a guest in another phase":                    func(a *Attestation) { a.Phase = PhaseBound },
		"a register without the image":                func(a *Attestation) { a.Events = a.Events[:2] },
		"a register with one event more":              func(a *Attestation) { a.Events = append(a.Events, a.Events[2]) },
		"a register with another image":               func(a *Attestation) { a.Events[2] = a.Events[1] },
		"a register that holds no launch document":    func(a *Attestation) { a.Events = a.Events[1:] },
		"a register with the bind and image reversed": func(a *Attestation) { a.Events[1], a.Events[2] = a.Events[2], a.Events[1] },
		"an empty register":                           func(a *Attestation) { a.Events = nil },
	} {
		if err := receipt.Confirmed(quoted(change)); !refusedByVerdict(err) {
			t.Errorf("the quote of %s confirmed the receipt: %v", name, err)
		}
	}
}

// A receipt kept with a bind is held to a later attestation of the guest:
// the word of the key that attestation binds, for the bind the guest
// measured, with a register that still begins with what the receipt lists.
func TestKeptReceiptIsHeldToALaterAttestation(t *testing.T) {
	key, other := receiptKey(t), receiptKey(t)
	bind := receiptBind(t, &key.PublicKey, true)
	launch := []byte("launch document")
	events, err := ExpectedEvents(launch, bind, PhaseRunning)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := NewBindReceipt(key, bind, events[1:], PhaseRunning)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	attested := func(change func(*Attestation)) *Attestation {
		att := &Attestation{Launch: launch, Bind: bind, Events: slices.Clone(events), Phase: PhaseRunning, InstanceKey: slices.Clone(der)}
		if change != nil {
			change(att)
		}
		return att
	}
	dir := t.TempDir()
	if kept, err := LoadReceipt(dir); kept != nil || err != nil {
		t.Fatalf("a directory with no receipt gave %+v, %v", kept, err)
	}
	if err := WriteReceipt(dir, signed); err != nil {
		t.Fatal(err)
	}
	kept, err := LoadReceipt(dir)
	if err != nil || kept == nil || !bytes.Equal(kept.Receipt, signed.Receipt) || kept.Signature != signed.Signature {
		t.Fatalf("the kept receipt: %+v, %v", kept, err)
	}
	if _, err := ConfirmReceipt(kept, attested(nil)); err != nil {
		t.Fatalf("the guest the receipt is from: %v", err)
	}
	// A register only grows: what the guest extended since does not undo
	// what it said then.
	if _, err := ConfirmReceipt(kept, attested(func(a *Attestation) { a.Events = append(a.Events, a.Events[1]) })); err != nil {
		t.Fatalf("the same guest after it extended more: %v", err)
	}
	otherDER, err := x509.MarshalPKIXPublicKey(&other.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	otherBind := receiptBind(t, &key.PublicKey, true)
	for name, change := range map[string]func(*Attestation){
		"a guest under another instance key":     func(a *Attestation) { a.InstanceKey = otherDER },
		"an attestation with no usable key":      func(a *Attestation) { a.InstanceKey = []byte("no key") },
		"a guest nobody bound":                   func(a *Attestation) { a.Bind = nil },
		"a guest bound by another bind":          func(a *Attestation) { a.Bind = otherBind },
		"a register that never held the image":   func(a *Attestation) { a.Events = a.Events[:2] },
		"a register that holds another image":    func(a *Attestation) { a.Events[2] = a.Events[1] },
		"a register with something before these": func(a *Attestation) { a.Events = slices.Insert(a.Events, 1, a.Events[0]) },
		"a register that holds nothing":          func(a *Attestation) { a.Events = nil },
	} {
		if receipt, err := ConfirmReceipt(kept, attested(change)); !refusedByVerdict(err) {
			t.Errorf("the kept receipt was held by %s: %+v, %v", name, receipt, err)
		}
	}
	if _, err := ConfirmReceipt(kept, nil); !refusedByVerdict(err) {
		t.Errorf("the kept receipt was held by no attestation: %v", err)
	}
	// The receipt's own word on which bind it is for, apart from the key.
	receipt, err := ConfirmReceipt(kept, attested(nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.HeldBy(attested(func(a *Attestation) { a.Bind = otherBind })); !refusedByVerdict(err) {
		t.Errorf("a receipt was held by a guest of another bind: %v", err)
	}
	if err := receipt.HeldBy(nil); !refusedByVerdict(err) {
		t.Errorf("a receipt was held by no attestation: %v", err)
	}
	if _, err := ConfirmReceipt(signedReceipt(t, other, receiptDomain, signed.Receipt), attested(nil)); !refusedByVerdict(err) {
		t.Errorf("a receipt another key signed was held by the guest: %v", err)
	}

	// A file that is no receipt is an error, and one too large is not read.
	if err := os.WriteFile(filepath.Join(dir, ReceiptFile), []byte(`{"receipt":"e30=","signature":"x","more":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReceipt(dir); err == nil {
		t.Error("a kept receipt with a field no receipt has was read")
	}
	if err := os.WriteFile(filepath.Join(dir, ReceiptFile), bytes.Repeat([]byte(" "), maxReceiptFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReceipt(dir); err == nil {
		t.Error("a kept receipt larger than one is was read")
	}
}
