// Package streamend keeps apart the two ways a stream inside a TLS session
// can end: its sender ended it, or it was cut on the way.
package streamend

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
)

// Transport is the connection under a TLS session, watched for its end.
//
// crypto/tls answers a peer's close_notify with io.EOF, and answers a
// connection that ends between two records the same way. Only the first is
// the peer's word: anyone on the path can end the connection, at a record
// boundary of their choosing. Ended tells the two apart, so that code which
// passes the end of a stream on passes on an authenticated one only.
type Transport struct {
	net.Conn
	// held is an end the connection reported along with its last bytes.
	held  error
	ended atomic.Bool
}

// Watch wraps the connection a TLS session is about to run on.
func Watch(conn net.Conn) *Transport { return &Transport{Conn: conn} }

// Read is the session's read. An end that arrives with bytes is held back for
// the next read: those bytes may complete the peer's close_notify, after
// which the session reads no more and is never handed the connection's end.
func (t *Transport) Read(p []byte) (int, error) {
	if t.held != nil {
		t.ended.Store(true)
		return 0, t.held
	}
	n, err := t.Conn.Read(p)
	if errors.Is(err, io.EOF) {
		if n > 0 {
			t.held = err
			return n, nil
		}
		t.ended.Store(true)
	}
	return n, err
}

// Ended reports whether the session was handed the end of its connection. An
// io.EOF the session returns after that is the connection's end and says
// nothing of the peer. One it returns before is the peer's close_notify.
func (t *Transport) Ended() bool { return t.ended.Load() }

// Reset closes conn as a failure: its peer reads a reset where Close would
// have it read the end of the stream, and bytes not yet sent are dropped. A
// connection that cannot be reset is closed.
func Reset(conn net.Conn) error {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	return conn.Close()
}
