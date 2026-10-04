//go:build linux

package vsock

import (
	"errors"
	"io"
	"net"
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
