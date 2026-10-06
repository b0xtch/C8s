//go:build linux

package vsock

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// pair is a stream over the kernel's loopback transport, which a guest image
// has built in and a development machine may not.
func pair(t *testing.T) (dialed, accepted *Conn) {
	t.Helper()
	ln, err := Listen(AnyPort, 4)
	if err != nil {
		t.Skipf("no vsock here: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if ln.Port() == AnyPort || ln.Port() == 0 {
		t.Fatalf("the listener holds port %d", ln.Port())
	}
	dialed, err = Dial(LocalCID, ln.Port())
	if err != nil {
		t.Skipf("no vsock loopback transport here: %v", err)
	}
	t.Cleanup(func() { _ = dialed.Close() })
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	accepted = conn.(*Conn)
	t.Cleanup(func() { _ = accepted.Close() })
	return dialed, accepted
}

func TestStreamCarriesBothWays(t *testing.T) {
	dialed, accepted := pair(t)
	if accepted.Peer() != LocalCID {
		t.Errorf("the peer is context id %d, want the loopback's", accepted.Peer())
	}
	if got := dialed.RemoteAddr().(Addr); got.CID != LocalCID || got.Port != accepted.LocalAddr().(Addr).Port {
		t.Errorf("dialed %v, accepted on %v", got, accepted.LocalAddr())
	}
	for _, way := range []struct{ from, to net.Conn }{{dialed, accepted}, {accepted, dialed}} {
		if _, err := way.from.Write([]byte("over")); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 4)
		if _, err := io.ReadFull(way.to, got); err != nil || string(got) != "over" {
			t.Fatalf("read %q, %v", got, err)
		}
	}
	// The far end's close is this end's end of stream.
	_ = dialed.Close()
	if n, err := accepted.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("read %d bytes, %v after the far end closed", n, err)
	}
}

// An end that stopped writing still reads: the far end reads what was
// written and then its end, and answers.
func TestEndThatStoppedWritingStillReads(t *testing.T) {
	dialed, accepted := pair(t)
	if _, err := dialed.Write([]byte("a word")); err != nil {
		t.Fatal(err)
	}
	if err := dialed.CloseWrite(); err != nil {
		t.Fatalf("the stream cannot end its writing: %v", err)
	}
	_ = accepted.SetDeadline(time.Now().Add(5 * time.Second))
	if got, err := io.ReadAll(accepted); err != nil || string(got) != "a word" {
		t.Fatalf("the far end read %q, %v", got, err)
	}
	if _, err := accepted.Write([]byte("taken")); err != nil {
		t.Fatalf("the far end's answer: %v", err)
	}
	_ = accepted.Close()
	_ = dialed.SetDeadline(time.Now().Add(5 * time.Second))
	if got, err := io.ReadAll(dialed); err != nil || string(got) != "taken" {
		t.Fatalf("the end that stopped writing read %q, %v", got, err)
	}
	if _, err := dialed.Write([]byte("more")); err == nil {
		t.Error("an end that stopped writing wrote")
	}
}

func TestDeadlineEndsARead(t *testing.T) {
	dialed, _ := pair(t)
	if err := dialed.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("the stream takes no deadline: %v", err)
	}
	began := time.Now()
	_, err := dialed.Read(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read: %v, want the deadline", err)
	}
	if waited := time.Since(began); waited > 2*time.Second {
		t.Fatalf("the read waited %s", waited)
	}
}

// A deadline that passed is a timeout, as a network connection reports one,
// and the stream goes on after it. A TLS session ends for good on a read
// error that does not say it is temporary, and an HTTP server interrupts an
// idle connection's read with a deadline after every request it answers.
func TestDeadlineIsATimeoutTheStreamOutlives(t *testing.T) {
	dialed, accepted := pair(t)
	if err := dialed.SetReadDeadline(time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	_, err := dialed.Read(make([]byte, 1))
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("a read past its deadline: %v (%T), want a network timeout", err, err)
	}
	if temporary, ok := err.(interface{ Temporary() bool }); !ok || !temporary.Temporary() {
		t.Fatalf("a read past its deadline: %v (%T) does not say the stream goes on", err, err)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a read past its deadline: %v", err)
	}
	if err := dialed.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := accepted.Write([]byte("on")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 2)
	if _, err := io.ReadFull(dialed, got); err != nil || string(got) != "on" {
		t.Fatalf("the stream after a deadline passed: %q, %v", got, err)
	}
	// A closed stream says so, in the words every reader of a connection
	// checks for.
	_ = dialed.Close()
	if _, err := dialed.Read(make([]byte, 1)); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("a read on a closed stream: %v", err)
	}
	if _, err := dialed.Write([]byte("x")); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("a write on a closed stream: %v", err)
	}
}

// An HTTP server over TLS keeps a vsock connection for the next request, as
// it keeps any other: the second request on one connection is answered.
func TestServerKeepsAConnectionBetweenRequests(t *testing.T) {
	ln, err := Listen(AnyPort, 4)
	if err != nil {
		t.Skipf("no vsock here: %v", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.URL.Path)
	}))
	server.Listener = ln
	server.StartTLS()
	defer server.Close()
	raw, err := Dial(LocalCID, ln.Port())
	if err != nil {
		t.Skipf("no vsock loopback transport here: %v", err)
	}
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // a test's own server
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	reader := bufio.NewReader(conn)
	for _, path := range []string{"/first", "/second", "/third"} {
		req, err := http.NewRequest(http.MethodGet, "https://replica"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := req.Write(conn); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		resp, err := http.ReadResponse(reader, req)
		if err != nil {
			t.Fatalf("%s on the kept connection: %v", path, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil || string(body) != path {
			t.Fatalf("%s answered %q, %v", path, body, err)
		}
		// Long enough for the server to have gone back to waiting.
		time.Sleep(20 * time.Millisecond)
	}
}

func TestCloseEndsAReadThatWaits(t *testing.T) {
	dialed, _ := pair(t)
	done := make(chan error, 1)
	go func() {
		_, err := dialed.Read(make([]byte, 1))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	_ = dialed.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the read returned no error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close left the read waiting")
	}
}

func TestCloseEndsAnAcceptThatWaits(t *testing.T) {
	ln, err := Listen(AnyPort, 4)
	if err != nil {
		t.Skipf("no vsock here: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	_ = ln.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("accept returned a connection")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close left accept waiting")
	}
}

func TestDialToNoListenerFails(t *testing.T) {
	ln, err := Listen(AnyPort, 1)
	if err != nil {
		t.Skipf("no vsock here: %v", err)
	}
	port := ln.Port()
	_ = ln.Close()
	began := time.Now()
	if conn, err := Dial(LocalCID, port); err == nil {
		_ = conn.Close()
		t.Fatal("dialed a port nothing listens on")
	}
	if waited := time.Since(began); waited > 5*time.Second {
		t.Fatalf("the dial waited %s", waited)
	}
}
