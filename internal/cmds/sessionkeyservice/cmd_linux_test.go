//go:build linux

package sessionkeyservice

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/vsock"
)

// handed is a listener that hands out the connections a test gives it.
type handed struct {
	conns chan net.Conn
}

func (h *handed) Accept() (net.Conn, error) {
	conn, ok := <-h.conns
	if !ok {
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (h *handed) Close() error   { return nil }
func (h *handed) Addr() net.Addr { return vsock.Addr{} }

// A replica serves what its launcher carries to it, which comes from its
// host. A connection from anywhere else is closed unread: one that is no
// vsock stream, and one from another context id than the host's.
func TestReplicaTakesItsHostsConnectionsOnly(t *testing.T) {
	ours, theirs := net.Pipe()
	defer theirs.Close()
	listener := &handed{conns: make(chan net.Conn, 2)}
	listener.conns <- ours

	// The kernel's loopback transport: a peer with context id 1.
	local, err := vsock.Listen(vsock.AnyPort, 1)
	var dialed net.Conn
	if err == nil {
		defer local.Close()
		if conn, dialErr := vsock.Dial(vsock.LocalCID, local.Port()); dialErr == nil {
			dialed = conn
			defer dialed.Close()
			accepted, acceptErr := local.Accept()
			if acceptErr != nil {
				t.Fatal(acceptErr)
			}
			if peer := accepted.(*vsock.Conn).Peer(); peer == vsock.HostCID {
				t.Fatalf("the loopback transport's peer is the host's context id %d", peer)
			}
			listener.conns <- accepted
		}
	}
	close(listener.conns)

	conn, err := hostOnly{listener}.Accept()
	if conn != nil || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("a replica took a connection that is not its host's: %v, %v", conn, err)
	}
	closed := func(end net.Conn) bool {
		_ = end.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err := end.Read(make([]byte, 1))
		return errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe)
	}
	if !closed(theirs) {
		t.Error("a connection that is no vsock stream was kept open")
	}
	if dialed == nil {
		t.Log("no vsock loopback transport here: a peer of another context id was not tried")
	} else if !closed(dialed) {
		t.Error("a connection from another context id than the host's was kept open")
	}
}
