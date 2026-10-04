package session

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// BindReceiptSchema is the one version of a guest's receipt for its bind.
const BindReceiptSchema = "c8s-bind-receipt/v1"

// receiptDomain separates the instance key's signature over a receipt from
// everything else that key signs.
const receiptDomain = BindReceiptSchema + " signature\x00"

// MaxReceiptBytes bounds a receipt as it travels.
const MaxReceiptBytes = 8 << 10

// BindReceipt is a guest's own word on the bind it took, given at once: which
// bind, for which nonce, what the guest extended into its runtime register
// since it was ready, and the phase it reached.
//
// The guest's instance key signs it, and the bind's nonce makes it fresh for
// the binder that drew the nonce. It is worth what that key is worth: the
// binder verified the quote that binds the key to the measured guest before
// it signed the bind. What a receipt says of the register is the measured
// agent's word until a quote over the same nonce says the same with the
// hardware's: the guest takes that quote while it answers, and serves it once
// it has it. A verdict that is kept is made from the quote, never from a
// receipt.
type BindReceipt struct {
	SchemaVersion string `json:"schemaVersion"`
	// Bind is the digest of the bind the guest took.
	Bind string `json:"bind"`
	// Nonce is the bind's nonce, as the bind writes it.
	Nonce string `json:"nonce"`
	// Events are the digests the guest extended after its launch document, in
	// order: what the quote in a certificate from before the bind does not
	// hold. Replayed onto that quote's register, they give the value the
	// quote over the bind's nonce must show.
	Events []string `json:"events"`
	// Phase is the phase the guest reached.
	Phase Phase `json:"phase"`
}

// SignedReceipt is a receipt as it travels: the bytes the guest signed, and
// its instance key's signature over them.
type SignedReceipt struct {
	Receipt   []byte `json:"receipt"`
	Signature string `json:"signature"`
}

// NewBindReceipt renders and signs a guest's receipt for bind: events are
// what the guest extended after its launch document, and phase what it
// reached.
func NewBindReceipt(instance *ecdsa.PrivateKey, bind *SignedBind, events []string, phase Phase) (*SignedReceipt, error) {
	raw, err := json.Marshal(BindReceipt{
		SchemaVersion: BindReceiptSchema, Bind: DocumentDigest(bind.Raw), Nonce: bind.Doc.Nonce, Events: events, Phase: phase,
	})
	if err != nil {
		return nil, err
	}
	signature, err := operatorauth.SignDetached(instance, append([]byte(receiptDomain), raw...))
	if err != nil {
		return nil, fmt.Errorf("sign the bind's receipt: %w", err)
	}
	return &SignedReceipt{Receipt: raw, Signature: signature}, nil
}

// VerifyBindReceipt holds a guest's receipt to the bind it answers. The
// receipt must be signed by instanceKey, which is the key the binder verified
// and the bind names; it must be for this bind and its nonce; and it must say
// the guest extended exactly what the bind implies for the phase it names,
// which is the running phase unless policy allows a guest that is bound and
// no more.
//
// A receipt that passes lets its binder go on at once. The quote that follows
// must agree with it: see BindReceipt.Confirmed.
func VerifyBindReceipt(policy Policy, instanceKey crypto.PublicKey, bind *SignedBind, signed *SignedReceipt) (*BindReceipt, error) {
	if signed == nil || len(signed.Receipt) == 0 {
		return nil, refuse("the answer to the bind carries no receipt")
	}
	if len(signed.Receipt) > MaxReceiptBytes || len(signed.Signature) > maxSignatureSize {
		return nil, refuse("the bind's receipt is larger than a receipt is")
	}
	key, ok := instanceKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, refuse("the guest's instance key is a %T, which signs no receipt", instanceKey)
	}
	if err := bind.Doc.Targets(key); err != nil {
		return nil, &VerificationError{Err: err}
	}
	if err := operatorauth.VerifyDetached([]*ecdsa.PublicKey{key}, append([]byte(receiptDomain), signed.Receipt...), signed.Signature); err != nil {
		return nil, refuse("the bind's receipt is not signed by the guest's instance key: %v", err)
	}
	var receipt BindReceipt
	dec := json.NewDecoder(bytes.NewReader(signed.Receipt))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&receipt); err != nil {
		return nil, refuse("the bind's receipt does not parse: %v", err)
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, refuse("the bind's receipt carries more than a receipt")
	}
	switch {
	case receipt.SchemaVersion != BindReceiptSchema:
		return nil, refuse("the bind's receipt is a %q, want %s", receipt.SchemaVersion, BindReceiptSchema)
	case receipt.Bind != DocumentDigest(bind.Raw):
		return nil, refuse("the receipt is for bind %s, and the bind that was sent is %s", receipt.Bind, DocumentDigest(bind.Raw))
	case receipt.Nonce != bind.Doc.Nonce:
		return nil, refuse("the receipt is for another nonce than the bind's")
	case receipt.Phase != PhaseRunning && (receipt.Phase != PhaseBound || !policy.AllowBound):
		return nil, refuse("the receipt says the guest is %s", receipt.Phase)
	}
	// What the guest extended is derived from the signed bind, never taken
	// from the guest. The first event is the launch document, which the quote
	// from before the bind already holds and a receipt does not list.
	events, err := ExpectedEvents(nil, bind, receipt.Phase)
	if err != nil {
		return nil, &VerificationError{Err: err}
	}
	if !slices.Equal(events[1:], receipt.Events) {
		return nil, refuse("the receipt says the guest extended %v, and its documents imply %v", receipt.Events, events[1:])
	}
	return &receipt, nil
}

// Confirmed holds the attestation that followed a receipt to it: verified
// evidence over the bind's nonce, of a guest in the phase the receipt names
// whose register holds the launch document and then exactly what the receipt
// lists. A binder that gets an error here ends the session: its guest said
// one thing under its key and its hardware says another.
func (r *BindReceipt) Confirmed(att *Attestation) error {
	if att == nil || att.Bind == nil || DocumentDigest(att.Bind.Raw) != r.Bind {
		return refuse("the quote that followed the receipt is not of a guest bound by the receipt's bind")
	}
	if att.Phase != r.Phase {
		return refuse("the receipt says the guest is %s, and the quote that followed says %s", r.Phase, att.Phase)
	}
	if len(att.Events) != len(r.Events)+1 || !slices.Equal(att.Events[1:], r.Events) {
		return refuse("the receipt says the guest extended %v, and the quote that followed holds %v", r.Events, att.Events)
	}
	return nil
}

// HeldBy holds a later attestation of the guest to the receipt: the guest is
// bound by the receipt's bind, and its register holds the launch document,
// then what the receipt lists, then whatever it has extended since. A
// register only grows, so one that does not begin so is another guest's.
func (r *BindReceipt) HeldBy(att *Attestation) error {
	if att == nil || att.Bind == nil || DocumentDigest(att.Bind.Raw) != r.Bind {
		return refuse("the attestation is not of a guest bound by the receipt's bind")
	}
	if len(att.Events) < len(r.Events)+1 || !slices.Equal(att.Events[1:len(r.Events)+1], r.Events) {
		return refuse("the receipt says the guest extended %v, and its register now holds %v", r.Events, att.Events)
	}
	return nil
}

// ReceiptFile is the name of the guest's receipt for its bind in a binding
// directory.
const ReceiptFile = "receipt.json"

// maxReceiptFileBytes bounds a kept receipt: its bytes in base64, and its
// signature.
const maxReceiptFileBytes = 2*MaxReceiptBytes + maxSignatureSize

// WriteReceipt keeps a guest's receipt for its bind in dir, beside the bind
// it answers. It is the guest's own signed word that it took the bind, and
// nothing is trusted on it: whoever reads it back holds it to the instance
// key and to a quote, as its first reader did.
func WriteReceipt(dir string, signed *SignedReceipt) error {
	data, err := json.Marshal(signed)
	if err != nil {
		return err
	}
	if err := keepFile(dir, ReceiptFile, append(data, '\n')); err != nil {
		return fmt.Errorf("keep the bind's receipt: %w", err)
	}
	return nil
}

// LoadReceipt reads the receipt kept in dir. A directory with none gives nil
// and no error.
func LoadReceipt(dir string) (*SignedReceipt, error) {
	path := filepath.Join(dir, ReceiptFile)
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	data, err := ReadBounded(path, maxReceiptFileBytes)
	if err != nil {
		return nil, err
	}
	var signed SignedReceipt
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&signed); err != nil {
		return nil, fmt.Errorf("kept receipt: %w", err)
	}
	return &signed, nil
}

// ConfirmReceipt holds a receipt that was kept with a bind to an attestation
// of the bound guest, judged just now: the receipt is the word of the
// instance key the attestation binds, for the bind the guest measured, and
// the guest's register still begins with what the receipt lists.
func ConfirmReceipt(signed *SignedReceipt, att *Attestation) (*BindReceipt, error) {
	if att == nil || att.Bind == nil {
		return nil, refuse("a receipt is held to the attestation of a bound guest")
	}
	key, err := x509.ParsePKIXPublicKey(att.InstanceKey)
	if err != nil {
		return nil, refuse("the attestation carries no usable instance key: %v", err)
	}
	// A receipt of a guest that was bound and no more is its word too.
	receipt, err := VerifyBindReceipt(Policy{AllowBound: true}, key, att.Bind, signed)
	if err != nil {
		return nil, err
	}
	if err := receipt.HeldBy(att); err != nil {
		return nil, err
	}
	return receipt, nil
}
