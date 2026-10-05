package session

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/verify/trust"
)

// The services a verifier of TDX evidence asks are Intel's two: the one that
// answers for a platform, and the one that keeps the root CA's revocation
// list. They are read off the addresses the engine fetches from, so a host
// that carries a verifier there carries it wherever it asks.
func TestVendorServicesAreWhereTheEngineAsks(t *testing.T) {
	services, err := VendorServices("tdx")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(services, []string{"api.trustedservices.intel.com:443", "certificates.trustedservices.intel.com:443"}) {
		t.Fatalf("the vendor's services for TDX: %v", services)
	}
	urls, err := CollateralPlatform{FMSPC: "00806f050000", CA: "platform"}.URLs()
	if err != nil {
		t.Fatal(err)
	}
	for _, document := range urls {
		host := strings.TrimPrefix(document, "https://")
		host = host[:strings.IndexByte(host, '/')] + ":443"
		if !slices.Contains(services, host) {
			t.Errorf("the engine asks %s, which is none of the vendor's services %v", document, services)
		}
	}
	// Each is a name a host's file may give a road to.
	ports := map[string]uint32{}
	for i, service := range services {
		ports[service] = uint32(1024 + i)
	}
	if err := (&HostConfig{VendorPorts: ports}).Validate(); err != nil {
		t.Fatalf("a host's roads to the vendor's services: %v", err)
	}
	if _, err := VendorServices("snp"); err == nil {
		t.Fatal("a platform with no vendor service known gave some")
	}
}

func TestHostConfigVendorPorts(t *testing.T) {
	for name, ports := range map[string]map[string]uint32{
		"a port that is any port": {"api.trustedservices.intel.com:443": 1<<32 - 1},
		"no port":                 {"api.trustedservices.intel.com:443": 0},
		"an address":              {"10.0.2.2:443": 1024},
		"an IPv6 address":         {"[fe80::1]:443": 1024},
		"a name with no port":     {"api.trustedservices.intel.com": 1024},
		"a port of zero":          {"api.trustedservices.intel.com:0": 1024},
		"a port past the last":    {"api.trustedservices.intel.com:65536": 1024},
		"a name in capitals":      {"Api.trustedservices.intel.com:443": 1024},
		"a name with a newline":   {"api.trustedservices.intel.com\n:443": 1024},
		"a name with an at sign":  {"user@api.trustedservices.intel.com:443": 1024},
		"a single label":          {"localhost:443": 1024},
		"an empty name":           {":443": 1024},
		"more than a host names": {
			"a.example.com:443": 1, "b.example.com:443": 2, "c.example.com:443": 3, "d.example.com:443": 4, "e.example.com:443": 5,
			"f.example.com:443": 6, "g.example.com:443": 7, "h.example.com:443": 8, "i.example.com:443": 9,
		},
	} {
		if err := (&HostConfig{VendorPorts: ports}).Validate(); err == nil {
			t.Errorf("%s was taken", name)
		}
	}
	parsed, err := ParseHostConfig([]byte(`{"vendor_ports":{"api.trustedservices.intel.com:443":70125,"certificates.trustedservices.intel.com:443":70126}}`))
	if err != nil || parsed.VendorPorts["certificates.trustedservices.intel.com:443"] != 70126 {
		t.Fatalf("a host's roads: %+v, %v", parsed, err)
	}
}

// vendorCertificate is a self-signed certificate for names, and the pool
// that trusts it.
func vendorCertificate(t *testing.T, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// A verifier whose road to Intel's service is one somebody carries asks over
// that road and no other, and holds whatever answers at its far end to the
// name it asked for: the carrier can keep a document from it, and can give
// it none.
func TestEngineAsksTheVendorOverTheRoadItIsGiven(t *testing.T) {
	const vendor = "api.trustedservices.intel.com"
	serve := func(certificate tls.Certificate, handler http.Handler) string {
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
		go func() { _ = srv.Serve(ln) }()
		t.Cleanup(func() { _ = srv.Close() })
		return ln.Addr().String()
	}
	document := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/moved" {
			http.Redirect(w, r, "https://"+vendor+"/document", http.StatusFound)
			return
		}
		w.Header().Set("Tcb-Info-Issuer-Chain", "chain")
		_, _ = w.Write([]byte("a document of Intel's"))
	})
	genuine, roots := vendorCertificate(t, vendor)
	impostor, _ := vendorCertificate(t, vendor)
	other, otherRoots := vendorCertificate(t, "pcs.example.com")
	roads := map[string]string{
		"genuine":  serve(genuine, document),
		"impostor": serve(impostor, document),
		"other":    serve(other, document),
	}
	var mu sync.Mutex
	var asked []string
	over := func(road string) vendorDialer {
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			asked = append(asked, addr)
			mu.Unlock()
			return (&net.Dialer{}).DialContext(ctx, network, roads[road])
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	getter := pcsGetter{client: pcsClientOver(over("genuine"), &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12})}
	header, body, err := getter.GetContext(ctx, "https://"+vendor+"/document")
	if err != nil || string(body) != "a document of Intel's" || header["Tcb-Info-Issuer-Chain"][0] != "chain" {
		t.Fatalf("a document over the road: %q, %v, %v", body, header, err)
	}
	mu.Lock()
	if len(asked) != 1 || asked[0] != vendor+":443" {
		t.Fatalf("the road was asked for %v, want the vendor's service once", asked)
	}
	mu.Unlock()
	// An answer from somewhere else is none.
	if _, _, err := getter.GetContext(ctx, "https://"+vendor+"/moved"); err == nil {
		t.Fatal("a redirect was followed")
	}

	// The carrier ends the session itself: under a certificate of its own
	// for the vendor's name, or under a certificate for a name of its own
	// that the verifier's roots would even vouch for.
	for name, tc := range map[string]struct {
		road  string
		roots *x509.CertPool
	}{
		"a certificate nobody the verifier trusts signed": {"impostor", roots},
		"a certificate for another name":                  {"other", otherRoots},
	} {
		getter := pcsGetter{client: pcsClientOver(over(tc.road), &tls.Config{RootCAs: tc.roots, MinVersion: tls.VersionTLS12})}
		if _, body, err := getter.GetContext(ctx, "https://"+vendor+"/document"); err == nil {
			t.Errorf("%s: the carrier's answer was taken: %q", name, body)
		}
	}

	// A road that reaches nothing is a fetch that failed.
	nowhere := pcsGetter{client: pcsClientOver(func(context.Context, string, string) (net.Conn, error) {
		return nil, net.ErrClosed
	}, nil)}
	if _, _, err := nowhere.GetContext(ctx, "https://"+vendor+"/document"); err == nil {
		t.Fatal("a document came over a road that reaches nothing")
	}

	// An engine that is given a road asks over it, and one that is given
	// none asks over this process's own.
	inner := func(opts EngineOptions) pcsGetter {
		t.Helper()
		engine, ok := NewEngine(opts).(*dcapEngine)
		if !ok {
			t.Fatal("the engine is not the in-process one")
		}
		retrying, ok := engine.fetch.(*trust.RetryHTTPSGetter)
		if !ok {
			t.Fatalf("the engine fetches with a %T", engine.fetch)
		}
		getter, ok := retrying.Getter.(pcsGetter)
		if !ok {
			t.Fatalf("the engine asks Intel's service with a %T", retrying.Getter)
		}
		return getter
	}
	if getter := inner(EngineOptions{}); getter.client != nil {
		t.Fatal("an engine with no road given has a client of its own")
	}
	given := inner(EngineOptions{Dial: over("genuine")})
	transport, ok := given.client.Transport.(*http.Transport)
	if !ok || transport.DialContext == nil || transport.Proxy != nil {
		t.Fatalf("an engine with a road given asks through %+v", given.client.Transport)
	}
	mu.Lock()
	before := len(asked)
	mu.Unlock()
	if conn, err := transport.DialContext(ctx, "tcp", vendor+":443"); err == nil {
		_ = conn.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	if len(asked) != before+1 {
		t.Fatal("the engine's client does not dial over the road it was given")
	}
}
