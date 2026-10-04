package streamend_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/streamend"
)

func serverConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "peer"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

// lump is a connection that, once armed, hands over everything its peer still
// sends in one read together with the end, as a reader is free to do.
type lump struct {
	net.Conn
	armed atomic.Bool
}

func (l *lump) Read(p []byte) (int, error) {
	if !l.armed.Load() {
		return l.Conn.Read(p)
	}
	n := 0
	for n < len(p) {
		m, err := l.Conn.Read(p[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// session is a TLS session over loopback TCP. The client's side runs on a
// watched transport. server is the peer's session and wire its connection.
type session struct {
	client    *tls.Conn
	transport *streamend.Transport
	lump      *lump
	server    *tls.Conn
	wire      net.Conn
}

func newSession(t *testing.T) *session {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := ln.Accept()
		accepted <- conn
	}()
	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	wire := <-accepted
	if wire == nil {
		t.Fatal("no connection was accepted")
	}
	s := &session{lump: &lump{Conn: dialed}, wire: wire}
	s.transport = streamend.Watch(s.lump)
	s.server = tls.Server(wire, serverConfig(t))
	s.client = tls.Client(s.transport, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}) //nolint:gosec // the test's own peer
	t.Cleanup(func() { _ = dialed.Close(); _ = wire.Close() })
	deadline := time.Now().Add(10 * time.Second)
	_ = dialed.SetDeadline(deadline)
	_ = wire.SetDeadline(deadline)
	shook := make(chan error, 1)
	go func() { shook <- s.server.Handshake() }()
	if err := s.client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-shook; err != nil {
		t.Fatal(err)
	}
	return s
}

// readToEnd reads the client's side until the session reports an end.
func (s *session) readToEnd(t *testing.T) (string, error) {
	t.Helper()
	var got []byte
	buf := make([]byte, 64)
	for {
		n, err := s.client.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			return string(got), err
		}
	}
}

// The peer's own end of its stream and a connection that ends between two
// records read the same from crypto/tls. The transport tells them apart.
func TestTransportTellsAPeersEndFromACut(t *testing.T) {
	t.Run("the peer ends its stream", func(t *testing.T) {
		s := newSession(t)
		if _, err := s.server.Write([]byte("all of it")); err != nil {
			t.Fatal(err)
		}
		if err := s.server.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		got, err := s.readToEnd(t)
		if got != "all of it" || !errors.Is(err, io.EOF) {
			t.Fatalf("read %q, %v", got, err)
		}
		if s.transport.Ended() {
			t.Fatal("the peer's close_notify was taken for the end of the connection")
		}
		// The connection closing afterwards changes nothing about that.
		_ = s.wire.Close()
		if _, err := s.client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) || s.transport.Ended() {
			t.Fatalf("after the connection closed: %v, ended %v", err, s.transport.Ended())
		}
	})

	t.Run("the connection ends between two records", func(t *testing.T) {
		s := newSession(t)
		if _, err := s.server.Write([]byte("part of it")); err != nil {
			t.Fatal(err)
		}
		// The connection is closed under the session: no close_notify is sent.
		if err := s.wire.Close(); err != nil {
			t.Fatal(err)
		}
		got, err := s.readToEnd(t)
		// This is what makes the transport necessary: the session says io.EOF.
		if got != "part of it" || !errors.Is(err, io.EOF) {
			t.Fatalf("read %q, %v", got, err)
		}
		if !s.transport.Ended() {
			t.Fatal("a connection that ended with no close_notify was taken for the peer's end")
		}
	})

	t.Run("the peer's end arrives in one read with the connection's", func(t *testing.T) {
		s := newSession(t)
		s.lump.armed.Store(true)
		if _, err := s.server.Write([]byte("all of it")); err != nil {
			t.Fatal(err)
		}
		if err := s.server.Close(); err != nil {
			t.Fatal(err)
		}
		got, err := s.readToEnd(t)
		if got != "all of it" || !errors.Is(err, io.EOF) {
			t.Fatalf("read %q, %v", got, err)
		}
		if s.transport.Ended() {
			t.Fatal("a close_notify that arrived with the connection's end was taken for a cut")
		}
	})

	t.Run("a cut arrives in one read with the last record", func(t *testing.T) {
		s := newSession(t)
		s.lump.armed.Store(true)
		if _, err := s.server.Write([]byte("part of it")); err != nil {
			t.Fatal(err)
		}
		if err := s.wire.Close(); err != nil {
			t.Fatal(err)
		}
		got, err := s.readToEnd(t)
		if got != "part of it" || !errors.Is(err, io.EOF) {
			t.Fatalf("read %q, %v", got, err)
		}
		if !s.transport.Ended() {
			t.Fatal("a cut that arrived with the last record was taken for the peer's end")
		}
	})
}

// A reset reads as a failure at the other end, where a close reads as the end
// of the stream.
func TestResetReadsAsAFailure(t *testing.T) {
	pair := func() (near, far net.Conn) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		accepted := make(chan net.Conn, 1)
		go func() {
			conn, _ := ln.Accept()
			accepted <- conn
		}()
		near, err = net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		far = <-accepted
		t.Cleanup(func() { _ = near.Close(); _ = far.Close() })
		_ = near.SetDeadline(time.Now().Add(10 * time.Second))
		return near, far
	}

	near, far := pair()
	if err := streamend.Reset(far); err != nil {
		t.Fatal(err)
	}
	if n, err := near.Read(make([]byte, 1)); n != 0 || err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("after a reset the other end read %d bytes, %v", n, err)
	}

	near, far = pair()
	if err := far.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := near.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("control: after a close the other end read %d bytes, %v", n, err)
	}
}
