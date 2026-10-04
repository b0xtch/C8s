package sessionagent

import (
	"context"
	"crypto/tls"
	"net"
	"sync"

	"github.com/confidential-dot-ai/c8s/internal/streamend"
)

// fence tracks the connections the agent has accepted, so that an unbound
// guest can end all of them at one point in time: the moment its host claims
// it for a session. See session.FenceResponse.
//
// Every connection belongs to the epoch it was accepted in. Raising the fence
// starts a new epoch and closes the connections of the earlier ones. A bind
// is let in only from a connection of the current epoch, before any of it is
// read, and counts as in flight until the agent is done with it. The fence is
// not raised over a bind in flight: the guest then holds something a caller
// sent it, and is no longer as it was booted.
type fence struct {
	mu    sync.Mutex
	epoch uint64
	conns map[*fencedConn]struct{}
	// binds counts the binds let in and not yet finished.
	binds int
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

// enter lets a bind in from c, or reports that c is of an epoch the fence
// ended. The caller has read none of the bind yet, and calls leave when the
// agent is done with it.
func (f *fence) enter(c *fencedConn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.epoch != 0 && (c == nil || c.epoch != f.epoch) {
		return false
	}
	f.binds++
	return true
}

func (f *fence) leave() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.binds--
}

// raise starts a new epoch and closes every connection of an earlier one but
// keep, the connection the request to raise it came on. It returns how many
// it closed. With a bind in flight it does neither, and reports false.
func (f *fence) raise(keep *fencedConn) (closed int, ok bool) {
	f.mu.Lock()
	if f.binds > 0 {
		f.mu.Unlock()
		return 0, false
	}
	f.epoch++
	var stale []*fencedConn
	for c := range f.conns {
		if c != keep {
			stale = append(stale, c)
		}
	}
	f.mu.Unlock()
	// Outside the lock: Close takes it to forget the connection.
	for _, c := range stale {
		_ = c.Close()
	}
	return len(stale), true
}

// admits reports whether a bind may be taken from c. Before the fence was
// ever raised, any connection will do, tracked or not. After, only one that
// was accepted since.
func (f *fence) admits(c *fencedConn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.epoch == 0 {
		return true
	}
	return c != nil && c.epoch == f.epoch
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
