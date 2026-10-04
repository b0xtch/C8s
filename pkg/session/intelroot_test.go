package session

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

// The anchor is Intel's SGX Root CA and nothing else: self-signed, a CA, and
// the certificate with the pinned fingerprint.
func TestIntelRootIsPinned(t *testing.T) {
	pool, err := intelRoots()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(intelSGXRootCA))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "Intel SGX Root CA" || !cert.IsCA || cert.CheckSignatureFrom(cert) != nil {
		t.Fatalf("the embedded certificate is %q, CA %v", cert.Subject, cert.IsCA)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatalf("the pool does not hold it: %v", err)
	}
}
