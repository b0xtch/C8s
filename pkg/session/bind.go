package session

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

const (
	// BindSchemaVersion names the strict bind schema.
	BindSchemaVersion = "c8s-bind/v1"

	// MaxBindSize bounds bind.json. Like the launch document it is measured,
	// so every byte is one a verifier must fetch and hash.
	MaxBindSize = 256 * 1024

	// PurposeStart binds a TD to a session that starts in it. It is the one
	// purpose this agent takes: a bind that restores or forks is refused.
	PurposeStart = "start"

	// DefaultBindTTL is how long a new bind stays applicable.
	DefaultBindTTL = time.Minute

	// bindTimeLayout is NotAfter's one accepted form: UTC, to the second.
	bindTimeLayout = "2006-01-02T15:04:05Z"
)

// Bind is the document that makes a guest one session's. A TD boots from
// a launch document that names nobody and grants nothing. The first bind it
// accepts supplies the tenant, the session, the sandbox and the keys that may
// drive it, and is extended into RTMR[3] before any of it takes effect.
//
// It is canonical JSON (RFC 8785), signed over its exact bytes, so a verifier
// in any language reads the same document the guest measured. A guest refuses
// a bind with a member it does not know.
type Bind struct {
	SchemaVersion string `json:"schemaVersion"`
	// InstanceKey is the TD's instance key, as sha256:<hex> of its PKIX
	// encoding. Another TD of the same pool has another key, and this bind is
	// of no use to it.
	InstanceKey string `json:"instanceKey"`
	// Authority is the owner's authority public key, PEM, which signs this
	// document. A guest accepts any authority: whoever relies on the guest
	// reads this one from its evidence and checks that it is the right one.
	Authority string `json:"authority"`
	// Tenant and Session name the session, in the authority's own scope.
	Tenant  string `json:"tenant"`
	Session string `json:"session"`
	// Purpose is PurposeStart.
	Purpose string `json:"purpose"`
	// Nonce is the binder's, 32 bytes in hex. The guest answers the bind with
	// evidence that is fresh for it.
	Nonce string `json:"nonce"`
	// NotAfter bounds how long an unused bind can still be applied. The guest's
	// clock starts from a host-supplied value, so this binds an honest host only.
	NotAfter string     `json:"notAfter"`
	Policy   BindPolicy `json:"policy"`
	// KeyService, when set, pins the key service the session trusts: the one
	// the guest takes the policy's stored credentials from.
	KeyService *KeyService `json:"keyService,omitempty"`
}

// BindPolicy is what the owner decides about its TD, one area to a member.
// The agent enforces every area: present means enforced. A rule it could not
// enforce is not in the schema, so a bind that carries one is refused instead
// of being measured and then ignored, and an area the schema lacks is not
// restricted at all.
type BindPolicy struct {
	Sandbox     *Sandbox     `json:"sandbox,omitempty"`
	Access      Access       `json:"access"`
	Credentials []Credential `json:"credentials,omitempty"`
	// Egress, when set, names every destination the sandbox may connect to.
	// Unset, it may connect to any public destination. See Egress.
	Egress *Egress `json:"egress,omitempty"`
	// Forward, when set, opens ports of the sandbox to streams from outside
	// the guest. Unset, nothing outside connects to the sandbox. See Forward.
	Forward *Forward `json:"forward,omitempty"`
}

var (
	instanceKeyRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	bindNonceRE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ParseBind strictly validates bind.json bytes. It authenticates nothing:
// VerifyBind checks the signature.
func ParseBind(data []byte) (*Bind, error) {
	if len(data) == 0 || len(data) > MaxBindSize {
		return nil, fmt.Errorf("bind must contain 1..%d bytes", MaxBindSize)
	}
	if !utf8.Valid(data) {
		return nil, errors.New("bind is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var b Bind
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("decode bind: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, errors.New("bind must contain exactly one JSON value")
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	// Go's decoder forgives what a second parser might read differently:
	// duplicate members, member names in another case, explicit nulls. None of
	// them survives a canonical rendering, so requiring the input to be its own
	// canonical form refuses them all.
	canonical, err := b.Canonical()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, errors.New("bind is not in canonical form (RFC 8785)")
	}
	return &b, nil
}

// Canonical renders the document as the exact bytes that are signed and measured.
func (b *Bind) Canonical() ([]byte, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("render bind: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, fmt.Errorf("render bind: %w", err)
	}
	out, err := canonicalJSON(tree)
	if err != nil {
		return nil, fmt.Errorf("render bind: %w", err)
	}
	return out, nil
}

// Validate checks every field. A document that passes is safe to enforce.
func (b *Bind) Validate() error {
	if b.SchemaVersion != BindSchemaVersion {
		return fmt.Errorf("schemaVersion must be %s", BindSchemaVersion)
	}
	if !instanceKeyRE.MatchString(b.InstanceKey) {
		return errors.New("instanceKey must be sha256:<64 lowercase hex>")
	}
	if _, err := parsePublicKey(b.Authority); err != nil {
		return fmt.Errorf("authority: %w", err)
	}
	if errs := validation.IsDNS1123Subdomain(b.Tenant); len(errs) > 0 {
		return errors.New("tenant must be an RFC1123 subdomain")
	}
	if errs := validation.IsDNS1123Label(b.Session); len(errs) > 0 {
		return errors.New("session must be an RFC1123 label")
	}
	if !slices.Contains(BindPurposes, b.Purpose) {
		return fmt.Errorf("purpose must be one of %q", BindPurposes)
	}
	if !bindNonceRE.MatchString(b.Nonce) {
		return errors.New("nonce must be 64 lowercase hex characters")
	}
	if t, err := time.Parse(bindTimeLayout, b.NotAfter); err != nil || t.Format(bindTimeLayout) != b.NotAfter {
		return errors.New("notAfter must be a UTC time to the second, as 2006-01-02T15:04:05Z")
	}
	if b.Policy.Sandbox != nil {
		if err := b.Policy.Sandbox.validate(); err != nil {
			return fmt.Errorf("policy.sandbox: %w", err)
		}
	}
	if err := validateEgress("policy.egress", b.Policy.Egress, b.Policy.Sandbox); err != nil {
		return err
	}
	if err := validateForward("policy.", b.Policy.Forward, b.Policy.Sandbox, b.Policy.Access.Forward); err != nil {
		return err
	}
	if err := validateAccess("policy.", b.Policy.Access, b.Policy.Credentials); err != nil {
		return err
	}
	if b.KeyService != nil {
		if err := b.KeyService.validate(); err != nil {
			return fmt.Errorf("keyService: %w", err)
		}
	}
	for _, c := range b.Policy.Credentials {
		if c.Source == SourceKeyService && b.KeyService == nil {
			return fmt.Errorf("credential %q comes from a key service and the bind names none", c.Name)
		}
	}
	return nil
}

// Expiry is NotAfter as a time. Validate has established that it parses.
func (b *Bind) Expiry() time.Time {
	t, _ := time.Parse(bindTimeLayout, b.NotAfter)
	return t
}

// EvidenceNonce is Nonce as the bytes a fresh attestation is taken over.
// Validate has established that it decodes.
func (b *Bind) EvidenceNonce() []byte {
	nonce, _ := hex.DecodeString(b.Nonce)
	return nonce
}

// InstanceKeyDigest names an instance key the way a bind does.
func InstanceKeyDigest(key crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("encode instance key: %w", err)
	}
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// SignedBind is a bind together with what authenticates it.
type SignedBind struct {
	// Raw is the exact bind.json: what was signed and what the guest measures.
	Raw       []byte
	Signature string
	Doc       *Bind
}

// MalformedBindError is VerifyBind's error for bytes that are no bind, where
// any other is a bind whose signature is not its authority's.
type MalformedBindError struct{ Err error }

func (e *MalformedBindError) Error() string { return e.Err.Error() }
func (e *MalformedBindError) Unwrap() error { return e.Err }

// VerifyBind parses a bind and checks its signature under the authority it
// names. That alone says nothing about whose authority it is: see SignedBy.
//
// The parser sees the bytes before any signature is checked, because the key
// is inside them. Nothing is lost by that: a signature under a key of the
// sender's own choosing would authenticate nothing either.
func VerifyBind(data []byte, signature string) (*SignedBind, error) {
	doc, err := ParseBind(data)
	if err != nil {
		return nil, &MalformedBindError{Err: err}
	}
	if len(signature) > maxSignatureSize {
		return nil, errors.New("bind signature is too large")
	}
	key, err := parsePublicKey(doc.Authority)
	if err != nil {
		return nil, fmt.Errorf("authority: %w", err)
	}
	if err := operatorauth.VerifyDetached([]*ecdsa.PublicKey{key}, data, signature); err != nil {
		return nil, fmt.Errorf("bind signature: %w", err)
	}
	return &SignedBind{Raw: data, Signature: strings.TrimSpace(signature), Doc: doc}, nil
}

// SignedBy reports whether the bind's authority is the key in authorityPEM.
func (s *SignedBind) SignedBy(authorityPEM []byte) bool {
	want, err := parsePublicKey(string(authorityPEM))
	if err != nil {
		return false
	}
	got, err := parsePublicKey(s.Doc.Authority)
	return err == nil && got.Equal(want)
}

// AuthorityDigest names the bind's authority as a pool's configuration names
// one: sha256:<hex> of the key's PKIX encoding.
func (s *SignedBind) AuthorityDigest() (string, error) {
	key, err := parsePublicKey(s.Doc.Authority)
	if err != nil {
		return "", err
	}
	return InstanceKeyDigest(key)
}

// Targets checks that the bind was written for the guest that holds this
// instance key.
func (b *Bind) Targets(instanceKey crypto.PublicKey) error {
	digest, err := InstanceKeyDigest(instanceKey)
	if err != nil {
		return err
	}
	if b.InstanceKey != digest {
		return fmt.Errorf("bind is for instance key %s, this guest holds %s", b.InstanceKey, digest)
	}
	return nil
}

// BindOptions describes a new bind.
type BindOptions struct {
	// Authority signs the document.
	Authority *ecdsa.PrivateKey
	// InstanceKey names the one TD the bind is for, as its verified evidence
	// reported it.
	InstanceKey crypto.PublicKey
	Tenant      string
	Session     string
	// Nonce is what the guest's answer must be fresh for: NonceSize bytes.
	// Nil draws one.
	Nonce []byte
	// NotAfter is when the bind stops being applicable. Zero is DefaultBindTTL
	// from now.
	NotAfter time.Time
	Policy   BindPolicy
	// KeyService is the key service the session trusts, or nil.
	KeyService *KeyService
}

// NewBind renders and signs a bind.
func NewBind(opts BindOptions) (*SignedBind, error) {
	if opts.Authority == nil || opts.InstanceKey == nil {
		return nil, errors.New("a bind needs the authority's key and the guest's instance key")
	}
	authority, err := PublicKeyPEM(&opts.Authority.PublicKey)
	if err != nil {
		return nil, err
	}
	instance, err := InstanceKeyDigest(opts.InstanceKey)
	if err != nil {
		return nil, err
	}
	nonce := opts.Nonce
	if nonce == nil {
		nonce = make([]byte, NonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("nonce: %w", err)
		}
	}
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("a bind's nonce is %d bytes", NonceSize)
	}
	notAfter := opts.NotAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(DefaultBindTTL)
	}
	doc := &Bind{
		SchemaVersion: BindSchemaVersion,
		InstanceKey:   instance,
		Authority:     string(authority),
		Tenant:        opts.Tenant,
		Session:       opts.Session,
		Purpose:       PurposeStart,
		Nonce:         hex.EncodeToString(nonce),
		NotAfter:      notAfter.UTC().Format(bindTimeLayout),
		Policy:        opts.Policy,
		KeyService:    opts.KeyService,
	}
	if err := doc.Validate(); err != nil {
		return nil, err
	}
	raw, err := doc.Canonical()
	if err != nil {
		return nil, err
	}
	// Prove the rendering parses under the rules the guest applies.
	if _, err := ParseBind(raw); err != nil {
		return nil, fmt.Errorf("rendered bind: %w", err)
	}
	signature, err := operatorauth.SignDetached(opts.Authority, raw)
	if err != nil {
		return nil, err
	}
	return &SignedBind{Raw: raw, Signature: signature, Doc: doc}, nil
}
