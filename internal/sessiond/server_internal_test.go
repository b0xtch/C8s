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

// An orchestrator's certificate chains to the orchestrators' authority, as a
// client's, at the time of the call. The daemon checks that once for a
// certificate and remembers the outcome until the chain's first certificate
// ends, and no longer.
func TestOrchestratorChainIsRememberedUntilItEnds(t *testing.T) {
	start := time.Now()
	serial := int64(0)
	issue := func(name string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, ends time.Time, usage x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serial++
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: start.Add(-time.Hour), NotAfter: ends,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		}
		if parent == nil {
			template.IsCA, template.BasicConstraintsValid, template.KeyUsage, template.ExtKeyUsage = true, true, x509.KeyUsageCertSign, nil
			parent, parentKey = template, key
		} else if name == "intermediate" {
			template.IsCA, template.BasicConstraintsValid, template.KeyUsage, template.ExtKeyUsage = true, true, x509.KeyUsageCertSign, nil
		}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert, key
	}
	ca, caKey := issue("authority", nil, nil, start.Add(48*time.Hour), 0)
	// The intermediate ends before the leaf does: the chain ends with it.
	middle, middleKey := issue("intermediate", ca, caKey, start.Add(2*time.Hour), 0)
	leaf, _ := issue("orchestrator", middle, middleKey, start.Add(24*time.Hour), x509.ExtKeyUsageClientAuth)
	direct, _ := issue("orchestrator", ca, caKey, start.Add(time.Hour), x509.ExtKeyUsageClientAuth)
	server, _ := issue("daemon", ca, caKey, start.Add(time.Hour), x509.ExtKeyUsageServerAuth)
	stranger, strangerKey := issue("another authority", nil, nil, start.Add(48*time.Hour), 0)
	outsider, _ := issue("orchestrator", stranger, strangerKey, start.Add(time.Hour), x509.ExtKeyUsageClientAuth)

	now := start
	d := &Daemon{now: func() time.Time { return now }, orchestrators: x509.NewCertPool()}
	d.orchestrators.AddCert(ca)
	known := func() int {
		d.chains.mu.Lock()
		defer d.chains.mu.Unlock()
		return len(d.chains.until)
	}

	for name, certs := range map[string][]*x509.Certificate{
		"a certificate of another authority":         {outsider},
		"another authority's, with ours beside it":   {outsider, ca},
		"an authority that signed itself":            {stranger},
		"a certificate for a server, not a client":   {server},
		"a certificate whose intermediate is absent": {leaf},
	} {
		if d.chained(certs) {
			t.Errorf("%s was taken as an orchestrator's", name)
		}
	}
	if known() != 0 {
		t.Fatalf("%d refused certificates are remembered", known())
	}
	if !d.chained([]*x509.Certificate{direct}) || !d.chained([]*x509.Certificate{leaf, middle}) || known() != 2 {
		t.Fatalf("the orchestrators' certificates were not taken, or not remembered: %d known", known())
	}
	// Remembered, a certificate is taken without its chain: the outcome is
	// its own, by its digest.
	if !d.chained([]*x509.Certificate{leaf}) {
		t.Fatal("a certificate whose chain was verified is verified again")
	}
	// Each outcome ends with the first certificate of its chain to end.
	now = start.Add(time.Hour - time.Second)
	if !d.chained([]*x509.Certificate{direct}) {
		t.Fatal("a certificate was refused a second before its end")
	}
	now = start.Add(time.Hour + time.Second)
	if d.chained([]*x509.Certificate{direct}) {
		t.Fatal("a certificate was taken past its end")
	}
	if !d.chained([]*x509.Certificate{leaf}) {
		t.Fatal("a chain that still stands was dropped with another")
	}
	now = start.Add(2*time.Hour + time.Second)
	if d.chained([]*x509.Certificate{leaf}) || d.chained([]*x509.Certificate{leaf, middle}) {
		t.Fatal("a certificate was taken past the end of its intermediate")
	}
	// What is remembered is bounded.
	now = start
	for range maxChains + 8 {
		other, _ := issue("orchestrator", ca, caKey, start.Add(time.Hour), x509.ExtKeyUsageClientAuth)
		if !d.chained([]*x509.Certificate{other}) {
			t.Fatal("one more orchestrator's certificate was refused")
		}
	}
	if known() > maxChains {
		t.Fatalf("%d chains are remembered, and %d is the bound", known(), maxChains)
	}
}
