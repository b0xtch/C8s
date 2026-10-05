package keyservice_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/keyservice"
	"github.com/confidential-dot-ai/c8s/pkg/session/sessionsim"
)

// stranger is a TLS server under a certificate of its own making, which
// answers nothing: it keeps what each connection sent it after the
// handshake.
type stranger struct {
	addr string
	// key is its certificate's key, as a bind would name it.
	key  string
	sent chan []byte
}

func newStranger(t *testing.T) *stranger {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "a stranger"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := &stranger{addr: ln.Addr().String(), sent: make(chan []byte, 8)}
	if s.key, err = session.InstanceKeyDigest(&key.PublicKey); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				// The handshake, and then whatever the client says until
				// it leaves, or for a moment: a client waits for an answer
				// that never comes.
				if err := conn.(*tls.Conn).HandshakeContext(context.Background()); err != nil {
					s.sent <- nil
					return
				}
				_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
				data, _ := io.ReadAll(conn)
				s.sent <- data
			}()
		}
	}()
	return s
}

// A client that is held to replicas sends a far end of another key nothing
// at all: the handshake proves which key the far end holds, and the client
// leaves before its first request. A client held to nobody asks that far end
// for its launch document, as any caller may.
func TestHeldClientSendsNothingToAKeyItIsNotHeldTo(t *testing.T) {
	far := newStranger(t)
	pin := &session.KeyService{URL: "https://" + far.addr}
	client, err := keyservice.NewClient(keyservice.Options{Pin: pin, Engine: sessionsim.Engine()})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	said := func() []byte {
		t.Helper()
		select {
		case data := <-far.sent:
			return data
		case <-ctx.Done():
			t.Fatal("the far end saw no connection end")
			return nil
		}
	}

	// Not held: the far end is asked what anyone may ask, and nothing after
	// it, since it answers nothing.
	if _, err := client.Open(ctx, []byte("launch"), "signature"); err == nil {
		t.Fatal("a far end that answers nothing opened a session")
	}
	if got := string(said()); !strings.HasPrefix(got, "GET "+keyservice.PathState+" ") || strings.Contains(got, keyservice.PathOpen) {
		t.Fatalf("a client held to nobody sent %q", got)
	}

	// Held to another key: the handshake ends the connection.
	client.Hold([]string{"sha256:" + strings.Repeat("0", 64)})
	var other *keyservice.NotMemberError
	if _, err := client.Open(ctx, []byte("launch"), "signature"); !errors.As(err, &other) || other.Replica != far.key {
		t.Fatalf("a connection that ended at a key the client is not held to: %v", err)
	}
	if got := said(); len(got) != 0 {
		t.Fatalf("a client sent %q to a key it is not held to", got)
	}
	// Held to the far end's key, it goes on to ask for the launch document.
	client.Hold([]string{far.key})
	if _, err := client.Open(ctx, []byte("launch"), "signature"); err == nil || errors.As(err, &other) {
		t.Fatalf("a connection that ended at the key the client is held to: %v", err)
	}
	if got := string(said()); !strings.HasPrefix(got, "GET "+keyservice.PathState+" ") {
		t.Fatalf("a client held to the far end's key sent %q", got)
	}
	// Held to nobody at all, it reaches for nobody twice.
	client.Hold(nil)
	if _, err := client.Open(ctx, []byte("launch"), "signature"); !errors.As(err, &other) {
		t.Fatalf("a client held to nobody: %v", err)
	}
	if got := said(); len(got) != 0 {
		t.Fatalf("a client held to nobody sent %q", got)
	}
}
