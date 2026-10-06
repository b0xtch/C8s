//go:build !linux

package vsock

import (
	"errors"
	"net"
)

// errNeedsLinux is what every call returns here.
var errNeedsLinux = errors.New("vsock needs Linux")

// Conn is a vsock stream.
type Conn struct{ net.Conn }

// Peer is the context id of the far end.
func (*Conn) Peer() uint32 { return 0 }

// CloseWrite ends this end's writing.
func (*Conn) CloseWrite() error { return errNeedsLinux }

// Dial connects to a port of the context id.
func Dial(uint32, uint32) (*Conn, error) { return nil, errNeedsLinux }

// Listener takes vsock connections on one port.
type Listener struct{ net.Listener }

// AnyPort asks Listen for a port nothing else on this side holds.
const AnyPort uint32 = 0xffffffff

// Listen takes connections on a port.
func Listen(uint32, int) (*Listener, error) { return nil, errNeedsLinux }

// Port is the port the listener holds.
func (*Listener) Port() uint32 { return 0 }
