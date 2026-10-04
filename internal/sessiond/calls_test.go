package sessiond

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// A claim relays the certificate its kept connection was made under only
// while that certificate is good for a while yet. One about to run out, or
// bytes that are no certificate, have the claim fetch the guest's again.
func TestClaimRelaysOnlyACertificateThatLasts(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	issue := func(notAfter time.Time) []byte {
		template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "guest"}, NotBefore: now.Add(-time.Hour), NotAfter: notAfter}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	for name, tc := range map[string]struct {
		leaf []byte
		want bool
	}{
		"good for a day":           {issue(now.Add(24 * time.Hour)), true},
		"good for the margin only": {issue(now.Add(certMargin)), false},
		"about to run out":         {issue(now.Add(time.Minute)), false},
		"run out":                  {issue(now.Add(-time.Minute)), false},
		"no certificate":           {[]byte("not a certificate"), false},
		"none":                     {nil, false},
	} {
		if got := lasts(tc.leaf, now); got != tc.want {
			t.Errorf("%s: lasts = %v, want %v", name, got, tc.want)
		}
	}
}
