package sessiontest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// ConnectRequest is one CONNECT a ConnectProxy was sent.
type ConnectRequest struct {
	Authority string
	Header    http.Header
}

// ConnectProxy is an HTTP CONNECT proxy that relays every tunnel to one
// target, whatever authority it was asked for, as a router that picks the
// guest from a header does. It reads nothing a tunnel carries.
type ConnectProxy struct {
	// URL is where the proxy listens.
	URL string
	// Roots verifies the proxy when it serves TLS, and RootsPEM is the same
	// certificate as a file would hold it.
	Roots    *x509.CertPool
	RootsPEM []byte

	// Refuse, when set, decides each CONNECT: a non-zero status refuses it
	// with that status and body.
	Refuse func(ConnectRequest) (status int, body string)
	// Hold, when set, delays the answer to each CONNECT until it is closed.
	Hold <-chan struct{}
	// Greeting is sent down each tunnel right behind the answer, as a server
	// that speaks first would.
	Greeting []byte

	target string
	mu     sync.Mutex
	seen   []ConnectRequest
}

// NewConnectProxy serves a proxy to target in the clear.
func NewConnectProxy(t testing.TB, target string) *ConnectProxy {
	t.Helper()
	p := &ConnectProxy{target: target}
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	p.URL = srv.URL
	return p
}

// NewTLSConnectProxy serves a proxy to target over TLS, under a certificate
// for "localhost" that only Roots vouches for.
func NewTLSConnectProxy(t testing.TB, target string) *ConnectProxy {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test proxy"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	p := &ConnectProxy{
		target:   target,
		Roots:    x509.NewCertPool(),
		RootsPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
	p.Roots.AddCert(cert)

	srv := httptest.NewUnstartedServer(p)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p.URL = "https://localhost:" + port
	return p
}

// Requests returns every CONNECT the proxy has been sent.
func (p *ConnectProxy) Requests() []ConnectRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]ConnectRequest(nil), p.seen...)
}

func (p *ConnectProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
		return
	}
	req := ConnectRequest{Authority: r.Host, Header: r.Header.Clone()}
	p.mu.Lock()
	p.seen = append(p.seen, req)
	p.mu.Unlock()

	if p.Refuse != nil {
		if status, body := p.Refuse(req); status != 0 {
			http.Error(w, body, status)
			return
		}
	}
	if p.Hold != nil {
		select {
		case <-p.Hold:
		case <-r.Context().Done():
			return
		}
	}
	upstream, err := net.Dial("tcp", p.target)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	client, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if _, err := rw.Write(p.Greeting); err != nil {
		return
	}
	if err := rw.Flush(); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, rw); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}
