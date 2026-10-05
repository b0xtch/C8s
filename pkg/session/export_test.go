package session

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

const (
	ConnIdle            = connIdle
	ServingVerdictTTL   = servingVerdictTTL
	RenewAhead          = renewAhead
	CredentialFreshness = credentialFreshness
)

// ScopeOf is what a verdict of a client with this policy and engine depends on.
var ScopeOf = scopeOf

// SetNow replaces the client's clock. Call it before the client is used.
func (c *Client) SetNow(now func() time.Time) { c.now = now }

// OfferSpare hands conn to the HTTP client's next dial, the way the first
// connection is handed over once its guest is attested.
func (c *Client) OfferSpare(conn *tls.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.spare, c.spareSince = conn, c.now()
}

// RetireAsFirst has the client treat conn as its first connection, between
// two exchanges, and then retire it.
func (c *Client) RetireAsFirst(conn *tls.Conn) {
	c.first.mu.Lock()
	c.first.conn, c.first.reader, c.first.used = conn, bufio.NewReader(conn), c.now()
	c.first.mu.Unlock()
	c.retireFirst()
}

// SetDial replaces how the client opens every connection.
func (c *Client) SetDial(dial func(ctx context.Context, network, addr string) (net.Conn, error)) {
	c.dial = dial
}

// SetStapleTimeout bounds a client's request for Intel's documents for the
// length of a test.
func SetStapleTimeout(t testing.TB, d time.Duration) {
	old := stapleTimeout
	stapleTimeout = d
	t.Cleanup(func() { stapleTimeout = old })
}

// Stapled asks the source that a judgment's context names, as an engine
// short of a document would. ok is false for a context that names none.
func Stapled(ctx context.Context) (docs []CollateralDocument, ok bool) {
	source, ok := ctx.Value(collateralSourceKey{}).(CollateralSource)
	if !ok {
		return nil, false
	}
	return source(ctx), true
}

// MayStapleRoot reports whether a judgment's context lets its verdict rest
// on a root CA CRL from the context's source.
func MayStapleRoot(ctx context.Context) bool { return StapledRootCRLAllowed(ctx) }
