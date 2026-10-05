package keyservice

import (
	"crypto/ecdsa"
	"crypto/hpke"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// A key service serves these over RA-TLS on Port. PathState answers anyone
// with what the key service measured. PathOpen and PathAcquire are a guest's:
// the caller presents its attested serving certificate as its client
// certificate, and the handshake proves it holds that key. The routes under
// PathTenants are an owner's, each under a token the tenant's authority key
// signed for this key service.
const (
	Port = 8443

	PathHealth  = "/healthz"
	PathState   = "/v1/state"
	PathOpen    = "/v1/open"
	PathAcquire = "/v1/acquire"
	PathTenants = "/v1/tenants/"

	// MaxRequestBytes bounds one request's body.
	MaxRequestBytes = 1 << 20
	// MaxCredentialsPerTenant bounds the credentials a tenant stores.
	MaxCredentialsPerTenant = 64
)

// AuthorityPath and CredentialPath are a tenant's routes.
func AuthorityPath(tenant string) string { return PathTenants + tenant + "/authority" }
func CredentialPath(tenant, name string) string {
	return PathTenants + tenant + "/credentials/" + name
}

// StateResponse is what a key service says of itself to anyone: the launch
// document it measured, which is its policy, and the signature on it. A
// verifier checks that signature under the pinned launch key and holds the
// key service's evidence to the document's digest.
type StateResponse struct {
	Launch    []byte `json:"launch"`
	Signature string `json:"signature"`
}

// OpenRequest opens a guest's session with the key service, at boot and
// before the guest is anybody's: the launch document the guest measured. The
// key service judges the evidence in the caller's certificate against it and
// keeps the verdict by the guest's instance key, so that the bind that
// follows costs no quote.
type OpenRequest struct {
	Launch    []byte `json:"launch"`
	Signature string `json:"signature"`
}

// AcquireRequest is a bound guest taking what its bind allows.
type AcquireRequest struct {
	// Bind and BindSignature are the bind the guest took, exactly as it
	// measured it.
	Bind          []byte `json:"bind"`
	BindSignature string `json:"bind_signature"`
	// Receipt is the guest's receipt for that bind, signed under the one-time
	// key its evidence bound when it opened its session. Only the guest's
	// agent, as it took the bind, could sign it: the key is erased before
	// anything of the tenant runs, while the instance key and this channel
	// live on where a session that broke out of its sandbox could use them.
	Receipt *session.SignedReceipt `json:"receipt"`
	// EncryptionKey is the guest's HPKE public key, and EncryptionKeySignature
	// its instance key's signature over it: see SignEncryptionKey. Every
	// release is sealed to it.
	EncryptionKey          []byte `json:"encryption_key"`
	EncryptionKeySignature string `json:"encryption_key_signature"`
	// Credentials names the stored credentials asked for. Each must be one
	// the bind declares as the key service's.
	Credentials []string `json:"credentials,omitempty"`
}

// AcquireResponse carries what was released, each sealed to the guest.
type AcquireResponse struct {
	Credentials []Sealed `json:"credentials,omitempty"`
}

// Sealed is one released value: see Seal.
type Sealed struct {
	Name       string `json:"name"`
	Ciphertext []byte `json:"ciphertext"`
}

// AuthorityRequest registers a tenant's authority key, PEM. The request's
// token is signed by that key: the first registration of a tenant is trust on
// first use, and proves only that the registrant holds the key.
type AuthorityRequest struct {
	Authority string `json:"authority"`
}

// CredentialRequest stores one credential of a tenant.
type CredentialRequest struct {
	Value []byte `json:"value"`
}

// encryptionKeyDomain separates the instance key's signature over an
// encryption key from every other signature that key makes.
const encryptionKeyDomain = "c8s-key-service/v1 encryption key\x00"

// releaseDomain starts the HPKE info of a release.
const releaseDomain = "c8s-key-service/v1 release\x00"

// EncryptionKey is a guest's key for what a key service releases to it: an
// HPKE key pair under the hybrid KEM of ML-KEM-768 and X25519, so that a
// release recorded today stays closed to a quantum computer later. It lives
// in the guest's memory and nowhere else.
type EncryptionKey struct {
	private hpke.PrivateKey
}

// NewEncryptionKey makes a key pair.
func NewEncryptionKey() (*EncryptionKey, error) {
	private, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate encryption key: %w", err)
	}
	return &EncryptionKey{private: private}, nil
}

// Public is the public half, as it travels.
func (k *EncryptionKey) Public() []byte { return k.private.PublicKey().Bytes() }

// SignEncryptionKey is the instance key's word that public is its guest's
// encryption key.
func SignEncryptionKey(instance *ecdsa.PrivateKey, public []byte) (string, error) {
	return operatorauth.SignDetached(instance, append([]byte(encryptionKeyDomain), public...))
}

// VerifyEncryptionKey checks that word.
func VerifyEncryptionKey(instance *ecdsa.PublicKey, public []byte, signature string) error {
	if _, err := hpke.MLKEM768X25519().NewPublicKey(public); err != nil {
		return fmt.Errorf("encryption key: %w", err)
	}
	if err := operatorauth.VerifyDetached([]*ecdsa.PublicKey{instance}, append([]byte(encryptionKeyDomain), public...), signature); err != nil {
		return fmt.Errorf("encryption key signature: %w", err)
	}
	return nil
}

// releaseInfo binds a release to the guest it is for, the bind it was
// released under and its name, so that a ciphertext moved to another of
// those opens nowhere.
func releaseInfo(instanceKey, bind, name string) []byte {
	sum := sha256.New()
	for _, part := range []string{releaseDomain, instanceKey, bind, name} {
		fmt.Fprintf(sum, "%d:%s", len(part), part)
	}
	return sum.Sum(nil)
}

// Seal encrypts value to the guest's encryption key. instanceKey and bind
// are the digests of the guest's instance key and of its bind.
func Seal(public []byte, instanceKey, bind, name string, value []byte) ([]byte, error) {
	key, err := hpke.MLKEM768X25519().NewPublicKey(public)
	if err != nil {
		return nil, fmt.Errorf("encryption key: %w", err)
	}
	return hpke.Seal(key, hpke.HKDFSHA256(), hpke.AES256GCM(), releaseInfo(instanceKey, bind, name), value)
}

// Open decrypts what Seal made for this key, guest, bind and name.
func (k *EncryptionKey) Open(instanceKey, bind, name string, sealed []byte) ([]byte, error) {
	value, err := hpke.Open(k.private, hpke.HKDFSHA256(), hpke.AES256GCM(), releaseInfo(instanceKey, bind, name), sealed)
	if err != nil {
		return nil, errors.New("the release does not open: it was sealed for another guest, bind or name, or changed on the way")
	}
	return value, nil
}
