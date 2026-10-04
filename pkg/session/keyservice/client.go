package keyservice

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	// dialTimeout bounds reaching the key service and holding it to its pin.
	dialTimeout = 30 * time.Second
	// maxAnswerBytes bounds one answer of a key service.
	maxAnswerBytes = 4 << 20
)

// Options is how a key service is reached and what it is held to.
type Options struct {
	// Pin is the key service this client talks to and no other.
	Pin *session.KeyService
	// Engine verifies the key service's evidence.
	Engine session.Engine
	// Certificate, when set, returns the caller's own attested certificate,
	// which a guest presents so that the key service knows which guest
	// asks. An owner has none.
	Certificate func() (*tls.Certificate, error)
	// Judging, when set, prepares the context the key service's evidence is
	// judged under: where the vendor's documents may come from.
	Judging func(context.Context) context.Context
	// Dial opens the connection. Nil dials the pin's address.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Now is the clock. Nil is the system's.
	Now func() time.Time
}

// Client talks to one pinned key service over one connection. Nothing is sent
// on a connection, beyond the request for the key service's own launch
// document, before the evidence in the certificate the connection ended at
// has been held to the pin.
type Client struct {
	opts Options
	addr string

	mu   sync.Mutex
	conn *tls.Conn
	read *bufio.Reader
	// key is the digest of the instance key the connection ends at: the
	// audience of every token sent on it.
	key string
}

// StatusError is an answer of the key service that is no success.
type StatusError struct {
	Status  int
	Code    string
	Message string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("the key service answered HTTP %d %s: %s", e.Status, e.Code, e.Message)
}

// NewClient returns a client of the pinned key service. No connection is
// made until a call needs one.
func NewClient(opts Options) (*Client, error) {
	if opts.Pin == nil || opts.Engine == nil {
		return nil, errors.New("a key service client needs a pin and an engine")
	}
	u, err := url.Parse(opts.Pin.URL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("key service URL %q", opts.Pin.URL)
	}
	if opts.Dial == nil {
		opts.Dial = (&net.Dialer{}).DialContext
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Client{opts: opts, addr: u.Host}, nil
}

// Close ends the client's connection.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.drop()
}

func (c *Client) drop() {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn, c.read, c.key = nil, nil, ""
	}
}

// connect opens a connection and holds its far end to the pin. The caller
// holds the lock.
func (c *Client) connect(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	raw, err := c.opts.Dial(ctx, "tcp", c.addr)
	if err != nil {
		return fmt.Errorf("reach the key service: %w", err)
	}
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		// The certificate is self-signed over an attested key: its evidence
		// is what is verified, below, before anything is sent.
		InsecureSkipVerify: true, //nolint:gosec // verified by evidence, not by a chain
	}
	if c.opts.Certificate != nil {
		config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return c.opts.Certificate()
		}
	}
	conn := tls.Client(raw, config)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return fmt.Errorf("reach the key service: %w", err)
	}
	c.conn, c.read = conn, bufio.NewReader(conn)
	fail := func(err error) error {
		c.drop()
		return err
	}
	// What anyone may ask: the document the key service says it measured.
	var state StateResponse
	if err := c.exchange(ctx, http.MethodGet, PathState, nil, "", &state); err != nil {
		return fail(err)
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return fail(&session.VerificationError{Err: errors.New("the key service presented no certificate")})
	}
	leaf := certs[0]
	if _, err := VerifySigned([]byte(c.opts.Pin.LaunchKey), state.Launch, state.Signature); err != nil {
		return fail(&session.VerificationError{Err: fmt.Errorf("the key service's launch document: %w", err)})
	}
	judging := ctx
	if c.opts.Judging != nil {
		judging = c.opts.Judging(ctx)
	}
	if err := session.VerifyService(judging, c.opts.Pin, c.opts.Engine, leaf, session.DocumentDigest(state.Launch), c.opts.Now()); err != nil {
		return fail(fmt.Errorf("the key service is not the one pinned: %w", err))
	}
	if c.key, err = session.InstanceKeyDigest(leaf.PublicKey); err != nil {
		return fail(err)
	}
	return nil
}

// exchange sends one request on the connection and reads its answer. The
// caller holds the lock.
func (c *Client) exchange(ctx context.Context, method, path string, body []byte, authorization string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, "https://"+c.addr+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	conn := c.conn
	// Closing is what ends a read or a write that waits on the far end.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := req.Write(conn); err != nil {
		return &connectionError{err}
	}
	resp, err := http.ReadResponse(c.read, req)
	if err != nil {
		return &connectionError{err}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes+1))
	_ = resp.Body.Close()
	if err != nil {
		return &connectionError{err}
	}
	if len(data) > maxAnswerBytes {
		return fmt.Errorf("the key service's answer is more than %d bytes", maxAnswerBytes)
	}
	if resp.StatusCode != http.StatusOK {
		var answer types.ErrorResponse
		_ = json.Unmarshal(data, &answer)
		return &StatusError{Status: resp.StatusCode, Code: answer.Error, Message: answer.Message}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("the key service's answer: %w", err)
	}
	return nil
}

// connectionError is a failure of the connection, after which a request may
// be sent again on a new one.
type connectionError struct{ err error }

func (e *connectionError) Error() string {
	return "the connection to the key service failed: " + e.err.Error()
}
func (e *connectionError) Unwrap() error { return e.err }

// do sends one request to the verified key service, on a new connection if
// the last one failed. Every call it carries may be made twice: the key
// service answers a repeat as it answered the first.
func (c *Client) do(ctx context.Context, method, path string, in any, signer operatorauth.AudienceAuthorizer, out any) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for attempt := 0; ; attempt++ {
		if c.conn == nil {
			if err := c.connect(ctx); err != nil {
				return err
			}
		}
		authorization := ""
		if signer != nil {
			var err error
			// The token is for the key service this connection ends at.
			if authorization, err = signer.AuthorizationFor(c.key, method, path, body); err != nil {
				return err
			}
		}
		err := c.exchange(ctx, method, path, body, authorization, out)
		var broken *connectionError
		if !errors.As(err, &broken) {
			return err
		}
		c.drop()
		if attempt > 0 || ctx.Err() != nil {
			return err
		}
	}
}

// Verify reaches the key service and holds it to the pin, and sends it
// nothing else.
func (c *Client) Verify(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return nil
	}
	return c.connect(ctx)
}

// Open opens the calling guest's session with the key service: the guest's
// launch document, under the certificate the client presents.
func (c *Client) Open(ctx context.Context, launch []byte, signature string) error {
	return c.do(ctx, http.MethodPost, PathOpen, OpenRequest{Launch: launch, Signature: signature}, nil, nil)
}

// Acquire presents the calling guest's bind and returns what it releases,
// still sealed.
func (c *Client) Acquire(ctx context.Context, req *AcquireRequest) (*AcquireResponse, error) {
	var answer AcquireResponse
	if err := c.do(ctx, http.MethodPost, PathAcquire, req, nil, &answer); err != nil {
		return nil, err
	}
	return &answer, nil
}

// RegisterAuthority registers the tenant's authority key, which signer holds.
func (c *Client) RegisterAuthority(ctx context.Context, tenant string, authorityPEM []byte, signer operatorauth.AudienceAuthorizer) error {
	return c.do(ctx, http.MethodPut, AuthorityPath(tenant), AuthorityRequest{Authority: string(authorityPEM)}, signer, nil)
}

// PutCredential stores value as the tenant's credential name, under the
// tenant's authority, which signer holds. The value leaves only on a
// connection whose far end verified as the pinned key service.
func (c *Client) PutCredential(ctx context.Context, tenant, name string, value []byte, signer operatorauth.AudienceAuthorizer) error {
	return c.do(ctx, http.MethodPut, CredentialPath(tenant, name), CredentialRequest{Value: value}, signer, nil)
}
