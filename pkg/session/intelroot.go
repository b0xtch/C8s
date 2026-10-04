package session

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sync"
)

// intelSGXRootCA is Intel's SGX Root CA, the anchor of every PCK certificate
// chain and of the collateral Intel signs. It is pinned here, by content and
// by fingerprint, so the anchor is this package's own and none a library
// falls back to. A constant, since the repository keeps no .pem file.
const intelSGXRootCA = `-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
-----END CERTIFICATE-----
`

// intelSGXRootCASHA256 is the SHA-256 of the certificate's DER.
const intelSGXRootCASHA256 = "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3"

var intelRoot = sync.OnceValues(func() (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(intelSGXRootCA))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return nil, fmt.Errorf("the embedded Intel SGX root is not one PEM certificate")
	}
	if sum := sha256.Sum256(block.Bytes); hex.EncodeToString(sum[:]) != intelSGXRootCASHA256 {
		return nil, fmt.Errorf("the embedded Intel SGX root has fingerprint %x, not the pinned one", sum)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the embedded Intel SGX root: %w", err)
	}
	return cert, nil
})

var intelRoots = sync.OnceValues(func() (*x509.CertPool, error) {
	cert, err := intelRoot()
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, nil
})

// rootCRLURL is where the pinned root says its CRL is: the one of Intel's
// documents a verifier can name before it has seen any evidence.
func rootCRLURL() (string, error) {
	cert, err := intelRoot()
	if err != nil {
		return "", err
	}
	if len(cert.CRLDistributionPoints) == 0 {
		return "", fmt.Errorf("the embedded Intel SGX root names no CRL")
	}
	return cert.CRLDistributionPoints[0], nil
}
