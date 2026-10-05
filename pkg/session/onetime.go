package session

import (
	"crypto"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"

	agratls "github.com/confidential-dot-ai/attestation-go/ratls"
)

// OneTimeKeys are the public halves of the two keys a pooled guest makes for
// its one bind, beside its instance key. It signs its receipt for the bind
// with the first, and a binder seals the session's first command to the
// second. The guest erases both private halves before anything of the tenant
// runs.
//
// The instance key cannot do either job. It outlives the bind, so code that
// broke out of a session's sandbox could read it, while the guest's host
// still holds the evidence the guest gave when it was ready and can show it
// to another binder. A receipt or a sealed command that rested on the
// instance key would rest on that code.
//
// The keys travel in every certificate a guest issues before its bind, and
// the quote in such a certificate binds them: its report data is the binding
// of the certificate's key over Binding. A verifier takes them from a
// certificate whose quote it has held to that, never on the word of the
// instance key that signed the certificate.
type OneTimeKeys struct {
	// Signing is the Ed25519 public key the guest signs its receipt under.
	Signing []byte
	// KEM is the public key of the hybrid KEM, ML-KEM-768 with X25519, that
	// a binder seals the session's first command to.
	KEM []byte
}

// OIDOneTimeKeys identifies the certificate extension that carries a pooled
// guest's one-time keys: SEQUENCE { signing OCTET STRING, kem OCTET STRING }.
var OIDOneTimeKeys = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66378, 1, 6}

// oneTimeDomain starts the digest of a guest's one-time keys.
const oneTimeDomain = "c8s-session-one-time/v1\x00"

// oneTimeKEM is the KEM of a guest's one-time KEM key.
func oneTimeKEM() hpke.KEM { return hpke.MLKEM768X25519() }

type oneTimeEncoding struct {
	Signing []byte
	KEM     []byte
}

// Validate checks that the keys are of the two kinds a guest makes.
func (k *OneTimeKeys) Validate() error {
	if k == nil {
		return errors.New("no one-time keys")
	}
	if len(k.Signing) != ed25519.PublicKeySize {
		return fmt.Errorf("the one-time signing key is %d bytes, and an Ed25519 key is %d", len(k.Signing), ed25519.PublicKeySize)
	}
	if _, err := oneTimeKEM().NewPublicKey(k.KEM); err != nil {
		return fmt.Errorf("the one-time KEM key: %w", err)
	}
	return nil
}

// Binding is the digest of the keys that every quote a guest takes before
// its bind carries in its report data, beside the instance key.
func (k *OneTimeKeys) Binding() []byte {
	h := sha256.New()
	h.Write([]byte(oneTimeDomain))
	for _, key := range [][]byte{k.Signing, k.KEM} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(key)))
		h.Write(n[:])
		h.Write(key)
	}
	return h.Sum(nil)
}

// Extension renders the keys as the certificate extension a guest's
// certificates carry until its bind.
func (k *OneTimeKeys) Extension() (pkix.Extension, error) {
	if err := k.Validate(); err != nil {
		return pkix.Extension{}, err
	}
	value, err := asn1.Marshal(oneTimeEncoding{Signing: k.Signing, KEM: k.KEM})
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{Id: OIDOneTimeKeys, Value: value}, nil
}

// oneTimeKeysOf reads the one-time keys a certificate carries. Nil with no
// error is a certificate that carries none: one a guest issued after its
// bind, or one of something that is no pooled guest. What it returns is what
// the certificate says, and nothing more until a quote binds it: see
// CertificateReportData.
func oneTimeKeysOf(leaf *x509.Certificate) (*OneTimeKeys, error) {
	var found *OneTimeKeys
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(OIDOneTimeKeys) {
			continue
		}
		if found != nil {
			return nil, errors.New("the certificate carries its one-time keys twice")
		}
		var encoded oneTimeEncoding
		rest, err := asn1.Unmarshal(ext.Value, &encoded)
		if err != nil || len(rest) != 0 {
			return nil, errors.New("the certificate's one-time keys do not parse")
		}
		found = &OneTimeKeys{Signing: encoded.Signing, KEM: encoded.KEM}
		if err := found.Validate(); err != nil {
			return nil, err
		}
	}
	return found, nil
}

// CertificateReportData is the report data the quote in a guest's
// certificate carries: the binding of the certificate's key, over the
// binding of the guest's one-time keys while it has them. oneTime is nil for
// a certificate issued after the bind, and for one of something that makes
// no such keys. The first 48 bytes are the digest; hardware zero-pads the
// rest.
func CertificateReportData(key crypto.PublicKey, oneTime *OneTimeKeys) ([]byte, error) {
	var over []byte
	if oneTime != nil {
		if err := oneTime.Validate(); err != nil {
			return nil, err
		}
		over = oneTime.Binding()
	}
	rd, err := agratls.ReportDataForKey(key, over)
	if err != nil {
		return nil, err
	}
	return rd[:sha512.Size384], nil
}

// certificateReportData is CertificateReportData for a certificate as it was
// served: its key, and the one-time keys it carries. A quote that matches
// what it returns binds both.
func certificateReportData(leaf *x509.Certificate) (rd []byte, oneTime *OneTimeKeys, err error) {
	if oneTime, err = oneTimeKeysOf(leaf); err != nil {
		return nil, nil, err
	}
	if rd, err = CertificateReportData(leaf.PublicKey, oneTime); err != nil {
		return nil, nil, err
	}
	return rd, oneTime, nil
}

// sameKey reports whether two public keys are one key.
func sameKey(a, b crypto.PublicKey) bool {
	one, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && one.Equal(b)
}
