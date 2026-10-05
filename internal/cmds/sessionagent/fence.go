package sessionagent

import (
	"context"
	"crypto/tls"
	"net"
	"sync"

	"github.com/confidential-dot-ai/c8s/internal/streamend"
)

// fence tracks the connections the agent has accepted, so that a guest can
// end all of them at one point in time: the moment its bind arrives.
//
// A pooled guest is nobody's until then, and whoever reached it before may
// still hold a connection to it. The first bind to arrive raises the fence:
// every connection but the one it came on is closed, so nothing sent to the
// guest before its bind reaches the session. Every connection belongs to the
// epoch it was accepted in, and raising the fence starts a new one, which the
// bind's connection moves into. From then on a bind is let in only from that
// connection or from one accepted since: a bind sent again after a lost
// answer, which the guest answers as it answered the first.
type fence struct {
	mu    sync.Mutex
	epoch uint64
	conns map[*fencedConn]struct{}
	// raised says a bind has arrived, and keeper is the connection it came
	// on: nil for a bind handed to the agent with no connection.
	raised bool
	keeper *fencedConn
}

// fencedConn is one accepted connection and the epoch it was accepted in. It
// is the transport under the caller's TLS session, watched for how it ends:
// a stream passes on only an end its caller sent.
type fencedConn struct {
	*streamend.Transport
	fence *fence
	epoch uint64
	once  sync.Once
}

// Close closes the connection under its TLS session: the peer is sent no
// close_notify, and reads this as a connection that broke.
func (c *fencedConn) Close() error {
	c.once.Do(func() { c.fence.forget(c) })
	return c.Transport.Close()
}

type fenceListener struct {
	net.Listener
	fence *fence
}

func (l fenceListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.fence.track(conn), nil
}

func (f *fence) track(conn net.Conn) *fencedConn {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := &fencedConn{Transport: streamend.Watch(conn), fence: f, epoch: f.epoch}
	if f.conns == nil {
		f.conns = map[*fencedConn]struct{}{}
	}
	f.conns[c] = struct{}{}
	return c
}

func (f *fence) forget(c *fencedConn) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.conns, c)
}

// arrive is a bind arriving on c, before any of it is read. The first raises
// the fence: it closes every connection accepted so far but c, and reports
// how many. A later one is admitted only from the connection the first came
// on or from one accepted since. A connection the fence ended whose request
// was already on its way is not.
func (f *fence) arrive(c *fencedConn) (admitted bool, closed int) {
	f.mu.Lock()
	if f.raised {
		admitted = c == f.keeper || (c != nil && c.epoch == f.epoch)
		f.mu.Unlock()
		return admitted, 0
	}
	f.raised, f.keeper = true, c
	f.epoch++
	var stale []*fencedConn
	for other := range f.conns {
		if other != c {
			stale = append(stale, other)
		}
	}
	if c != nil {
		c.epoch = f.epoch
	}
	f.mu.Unlock()
	// Outside the lock: Close takes it to forget the connection.
	for _, other := range stale {
		_ = other.Close()
	}
	return true, len(stale)
}

// follows reports whether c may send what follows a bind: a bind has arrived,
// and c is the connection it came on or one accepted since.
func (f *fence) follows(c *fencedConn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.raised && (c == f.keeper || (c != nil && c.epoch == f.epoch))
}

// fenceConnKey is the context key a request's connection is found under.
type fenceConnKey struct{}

// withConn records a new connection in the context of its requests. The
// server hands over the TLS connection, which wraps the tracked one.
func withConn(ctx context.Context, c net.Conn) context.Context {
	if secured, ok := c.(*tls.Conn); ok {
		c = secured.NetConn()
	}
	if tracked, ok := c.(*fencedConn); ok {
		return context.WithValue(ctx, fenceConnKey{}, tracked)
	}
	return ctx
}

// connOf is the tracked connection a request came on, or nil when the server
// was not run through Agent.Serve.
func connOf(ctx context.Context) *fencedConn {
	c, _ := ctx.Value(fenceConnKey{}).(*fencedConn)
	return c
}
