package sessionlauncher

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// echoService stands in for a key service: it sends back what it is sent,
// and counts the connections it took.
func echoService(t *testing.T) (addr string, taken *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	taken = new(atomic.Int32)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			taken.Add(1)
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String(), taken
}

// startRelay runs a relay on a loopback port for the length of the test.
func startRelay(t *testing.T, own func(net.Conn) bool, dial func(context.Context) (net.Conn, error)) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	r := &relay{name: "test", ln: ln, own: own, dial: dial, slots: relayed, log: quiet}
	go func() {
		defer close(done)
		r.run(ctx)
	}()
	stop = func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the relay did not end with its context")
		}
	}
	t.Cleanup(stop)
	return ln.Addr().String(), stop
}

func dialTo(addr string) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
}

func anyone(net.Conn) bool { return true }

func connect(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn
}

// carried reports whether conn reaches the echo service: what it writes
// comes back.
func carried(conn net.Conn) bool {
	if _, err := conn.Write([]byte("ping")); err != nil {
		return false
	}
	got := make([]byte, 4)
	_, err := io.ReadFull(conn, got)
	return err == nil && string(got) == "ping"
}

// ended reports whether the far end closed conn with nothing sent.
func ended(conn net.Conn) bool {
	n, err := conn.Read(make([]byte, 1))
	if n != 0 || err == nil {
		return false
	}
	var timeout net.Error
	return !errors.As(err, &timeout) || !timeout.Timeout()
}

func TestRelayCarriesBothWaysUntilEitherEndCloses(t *testing.T) {
	service, taken := echoService(t)
	addr, _ := startRelay(t, anyone, dialTo(service))
	conn := connect(t, addr)
	if !carried(conn) {
		t.Fatal("nothing came back through the relay")
	}
	if taken.Load() != 1 {
		t.Fatalf("the service took %d connections, want 1", taken.Load())
	}

	// The service's end closing is the guest's end of stream.
	gone := make(chan net.Conn, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			gone <- c
		}
	}()
	addr, _ = startRelay(t, anyone, dialTo(ln.Addr().String()))
	conn = connect(t, addr)
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	far := <-gone
	_ = far.Close()
	if !ended(conn) {
		t.Fatal("the guest's connection outlived the service's")
	}
}

func TestRelayTakesItsOwnGuestOnly(t *testing.T) {
	service, taken := echoService(t)
	addr, _ := startRelay(t, func(net.Conn) bool { return false }, dialTo(service))
	if conn := connect(t, addr); !ended(conn) {
		t.Fatal("a stranger's connection was not closed")
	}
	if taken.Load() != 0 {
		t.Fatal("a stranger's connection reached the key service")
	}
}

func TestRelayBoundsAGuestsConnections(t *testing.T) {
	service, _ := echoService(t)
	addr, _ := startRelay(t, anyone, dialTo(service))
	var held []net.Conn
	for range relayed {
		conn := connect(t, addr)
		if !carried(conn) {
			t.Fatalf("connection %d was not carried", len(held)+1)
		}
		held = append(held, conn)
	}
	if conn := connect(t, addr); !ended(conn) {
		t.Fatal("one connection more than the bound was carried")
	}
	// A place frees when a connection ends.
	_ = held[0].Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn := connect(t, addr)
		if carried(conn) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no place freed after a connection ended")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRelayWithNoKeyServiceEndsTheConnection(t *testing.T) {
	addr, _ := startRelay(t, anyone, func(context.Context) (net.Conn, error) {
		return nil, errors.New("no road")
	})
	began := time.Now()
	if conn := connect(t, addr); !ended(conn) {
		t.Fatal("the guest's connection stayed open with no key service behind it")
	}
	if waited := time.Since(began); waited > 5*time.Second {
		t.Fatalf("the guest waited %s to learn it", waited)
	}
}

func TestRelayEndsItsConnectionsWithItsContext(t *testing.T) {
	service, _ := echoService(t)
	addr, stop := startRelay(t, anyone, dialTo(service))
	conn := connect(t, addr)
	if !carried(conn) {
		t.Fatal("the connection was not carried")
	}
	stop()
	if !ended(conn) {
		t.Fatal("a carried connection outlived the relay")
	}
	if late, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		_ = late.Close()
		t.Fatal("the relay still listens")
	}
}
