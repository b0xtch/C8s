//go:build linux

package vsock

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// Conn is a vsock stream. Its deadlines work, and Close ends a Read or a
// Write that waits. Its errors are a network connection's: a deadline that
// passed is a timeout the stream outlives, which is what a TLS session and
// an HTTP server on it take one for.
type Conn struct {
	*os.File
	local, remote Addr
}

var _ net.Conn = (*Conn)(nil)

// Read reads from the stream.
func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.File.Read(b)
	return n, c.failure("read", err)
}

// Write writes to the stream.
func (c *Conn) Write(b []byte) (int, error) {
	n, err := c.File.Write(b)
	return n, c.failure("write", err)
}

// failure gives a failed read or write the form a network connection's has.
// The file under the stream reports one as a failure of a path, which no
// reader of a connection's errors takes for a timeout: crypto/tls ends a
// session on any read error that does not say it is temporary, and an HTTP
// server ends a connection whose interrupted read is no timeout.
func (c *Conn) failure(op string, err error) error {
	if err == nil || err == io.EOF {
		return err
	}
	var path *fs.PathError
	if errors.As(err, &path) {
		err = path.Err
	}
	return &net.OpError{Op: op, Net: "vsock", Source: c.local, Addr: c.remote, Err: err}
}

// LocalAddr is this end of the stream.
func (c *Conn) LocalAddr() net.Addr { return c.local }

// RemoteAddr is the far end, as the kernel filled it in.
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

// Peer is the context id of the far end. The kernel fills it in from the
// device a connection came through, so no guest picks its own.
func (c *Conn) Peer() uint32 { return c.remote.CID }

// newConn wraps a connected descriptor, which it owns from here on.
func newConn(fd int, remote Addr) (*Conn, error) {
	// A descriptor that does not block is one the runtime polls: that is
	// what gives the stream its deadlines.
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("vsock: %w", err)
	}
	var local Addr
	if sa, err := unix.Getsockname(fd); err == nil {
		if vm, ok := sa.(*unix.SockaddrVM); ok {
			local = Addr{CID: vm.CID, Port: vm.Port}
		}
	}
	return &Conn{File: os.NewFile(uintptr(fd), "vsock"), local: local, remote: remote}, nil
}

// connectAttempts bounds how often a connect a signal interrupted is made
// again.
const connectAttempts = 8

// Dial connects to a port of the context id. The kernel bounds the wait: two
// seconds, unless the far end refuses sooner.
func Dial(cid, port uint32) (*Conn, error) {
	var last error
	for range connectAttempts {
		fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return nil, fmt.Errorf("vsock socket: %w", err)
		}
		// A signal ends a connect that waits, and the kernel gives the
		// attempt up with it: the next one starts over on a new socket.
		if last = unix.Connect(fd, &unix.SockaddrVM{CID: cid, Port: port}); last == nil {
			return newConn(fd, Addr{CID: cid, Port: port})
		}
		_ = unix.Close(fd)
		if last != unix.EINTR {
			break
		}
	}
	return nil, fmt.Errorf("vsock connect to %d port %d: %w", cid, port, last)
}

// Listener takes vsock connections on one port.
type Listener struct {
	file *os.File
	addr Addr
}

var _ net.Listener = (*Listener)(nil)

// AnyPort asks Listen for a port nothing else on this side holds.
const AnyPort uint32 = unix.VMADDR_PORT_ANY

// Listen takes connections on a port from every context id: Accept's caller
// holds each to the peer it expects.
func Listen(port uint32, backlog int) (*Listener, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock socket: %w", err)
	}
	fail := func(err error) (*Listener, error) {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}); err != nil {
		return fail(fmt.Errorf("bind a vsock port: %w", err))
	}
	if err := unix.Listen(fd, backlog); err != nil {
		return fail(fmt.Errorf("listen on a vsock port: %w", err))
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return fail(fmt.Errorf("vsock: %w", err))
	}
	vm, ok := sa.(*unix.SockaddrVM)
	if !ok {
		return fail(fmt.Errorf("vsock: the socket has a %T address", sa))
	}
	return &Listener{file: os.NewFile(uintptr(fd), "vsock-listener"), addr: Addr{CID: vm.CID, Port: vm.Port}}, nil
}

// Port is the port the listener holds.
func (l *Listener) Port() uint32 { return l.addr.Port }

// Addr is where the listener listens.
func (l *Listener) Addr() net.Addr { return l.addr }

// Accept returns the next connection, a *Conn. Close ends its wait.
func (l *Listener) Accept() (net.Conn, error) {
	raw, err := l.file.SyscallConn()
	if err != nil {
		return nil, err
	}
	var (
		fd      int
		peer    unix.Sockaddr
		failure error
	)
	if err := raw.Read(func(listening uintptr) bool {
		for {
			fd, peer, failure = unix.Accept4(int(listening), unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK)
			switch failure {
			case unix.EINTR, unix.ECONNABORTED:
				continue
			case unix.EAGAIN:
				return false
			}
			return true
		}
	}); err != nil {
		return nil, err
	}
	if failure != nil {
		return nil, fmt.Errorf("vsock accept: %w", failure)
	}
	vm, ok := peer.(*unix.SockaddrVM)
	if !ok {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("vsock accept: the peer has a %T address", peer)
	}
	return newConn(fd, Addr{CID: vm.CID, Port: vm.Port})
}

// Close ends the listener and any Accept that waits on it.
func (l *Listener) Close() error { return l.file.Close() }
