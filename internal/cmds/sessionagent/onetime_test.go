package sessionagent

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// A guest's one-time signing key signs once, and is gone from where it was
// kept when it has.
func TestOneTimeSigningKeySignsOnce(t *testing.T) {
	keys, err := newOneTime()
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.public.Validate(); err != nil {
		t.Fatalf("the public halves: %v", err)
	}
	// The places the private halves are kept, as they are before a bind.
	signing, kem := keys.signing, keys.kem
	if len(signing) != ed25519.PrivateKeySize || len(kem) != kemSeedSize || allZero(signing) || allZero(kem) {
		t.Fatalf("the private halves are kept as %d and %d bytes", len(signing), len(kem))
	}
	if keys.gone() {
		t.Fatal("the keys are gone before any bind")
	}
	message := []byte("a receipt")
	signature, err := keys.sign(message)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(keys.public.Signing, message, signature) {
		t.Fatal("the signature is not the one-time key's")
	}
	if !allZero(signing) {
		t.Fatal("the signing key is still where it was kept after it signed")
	}
	if again, err := keys.sign([]byte("another receipt")); err == nil {
		t.Fatalf("the one-time signing key signed again: %x", again)
	}
	// The KEM key is another key, and goes when it is told to.
	if keys.gone() || allZero(kem) {
		t.Fatal("the KEM key went with the signing key")
	}
	keys.eraseKEM()
	if !allZero(kem) || !keys.gone() {
		t.Fatal("the KEM key is still where it was kept after it was erased")
	}
	keys.eraseKEM()

	// Two guests make different keys.
	other, err := newOneTime()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(other.public.Signing, keys.public.Signing) || bytes.Equal(other.public.KEM, keys.public.KEM) {
		t.Fatal("two guests made the same one-time keys")
	}
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
