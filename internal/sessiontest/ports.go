package sessiontest

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"syscall"
	"testing"
)

// Ports stands in for the ports of a sandbox: each open one is a listener of
// the test's own, and a runner's Dial is answered from here. A port nobody
// opened refuses the connection, as a loopback with no listener does.
type Ports struct {
	mu    sync.Mutex
	open  map[int]string
	asked []int
}

// Open serves port: each connection to it is handed to serve, which owns it.
func (p *Ports) Open(t *testing.T, port int, serve func(net.Conn)) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(conn)
		}
	}()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.open == nil {
		p.open = map[int]string{}
	}
	p.open[port] = ln.Addr().String()
}

// Dial connects to port, or is refused when the test opened none there.
func (p *Ports) Dial(ctx context.Context, port int) (net.Conn, error) {
	p.mu.Lock()
	p.asked = append(p.asked, port)
	addr, ok := p.open[port]
	p.mu.Unlock()
	if !ok {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
}

// Asked returns every port a connection was asked for, in order.
func (p *Ports) Asked() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.asked)
}

// Echo answers a connection with what it is sent, and ends its answer when
// its input ends.
func Echo(conn net.Conn) {
	defer conn.Close()
	_, _ = io.Copy(conn, conn)
}

// Ending is how one connection to a sandbox's port ended, as the sandbox
// read it.
type Ending struct {
	// Read is what the sandbox read before the end.
	Read string
	// Err is nil when its input ended in order, and the failure otherwise.
	Err error
}

// EchoRecording is Echo that reports each connection's Ending.
func EchoRecording(endings chan<- Ending) func(net.Conn) {
	return func(conn net.Conn) {
		defer conn.Close()
		var read []byte
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			read = append(read, buf[:n]...)
			if n > 0 {
				if _, werr := conn.Write(buf[:n]); werr != nil && err == nil {
					err = werr
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					err = nil
				}
				endings <- Ending{Read: string(read), Err: err}
				return
			}
		}
	}
}
