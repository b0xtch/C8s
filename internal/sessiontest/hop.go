package sessiontest

import (
	"io"
	"net"
	"sync"
	"testing"
)

// Hop is something on the road between a client and a guest: it relays every
// connection to one address, counts them, and ends them when told to.
type Hop struct {
	// URL is where a client reaches the guest through the hop.
	URL string

	mu       sync.Mutex
	conns    []net.Conn
	accepted int
}

// NewHop relays to target, a host:port.
func NewHop(t *testing.T, target string) *Hop {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	h := &Hop{URL: "https://" + ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			h.mu.Lock()
			h.accepted++
			h.mu.Unlock()
			backend, err := net.Dial("tcp", target)
			if err != nil {
				_ = conn.Close()
				continue
			}
			h.mu.Lock()
			h.conns = append(h.conns, conn, backend)
			h.mu.Unlock()
			go func() { _, _ = io.Copy(backend, conn); _ = backend.Close() }()
			go func() { _, _ = io.Copy(conn, backend); _ = conn.Close() }()
		}
	}()
	return h
}

// Cut closes both sides of every connection relayed so far, as a hop that
// drops connections does, and returns how many connections there were. With
// nothing in flight each side reads the end of its connection between two
// TLS records.
func (h *Hop) Cut() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, conn := range h.conns {
		_ = conn.Close()
	}
	h.conns = nil
	return h.accepted
}

// Accepted is how many connections the hop has taken.
func (h *Hop) Accepted() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.accepted
}
