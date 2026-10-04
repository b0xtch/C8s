// Package daemon is a client of the c8s daemon's session API
// (docs/session-api.md): what an orchestrator and a binder drive TDs through,
// and the road a session's connections to its guest take.
//
// The daemon is outside the trust boundary. Everything this package returns
// is relayed and unjudged: pkg/session's VerifyReady and VerifyBound judge
// it, and a session.Client verifies the guest at the end of a connection
// whatever carried it there.
package daemon

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/types/known/durationpb"

	sessionv1alpha1 "github.com/confidential-dot-ai/c8s/api/session/v1alpha1"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// Options is how a daemon is reached.
type Options struct {
	// Address is the daemon's, as host:port.
	Address string
	// RootCAs verifies the daemon's certificate. Nil is the system's roots.
	RootCAs *x509.CertPool
	// ServerName is the name the daemon's certificate must carry, when it is
	// not Address's host.
	ServerName string
	// Certificate is an orchestrator's, for claiming, binding and destroying.
	// Without one the client reaches evidence and connections alone.
	Certificate *tls.Certificate
}

// Client is a connection to one daemon. It is safe for concurrent use.
type Client struct {
	conn *grpc.ClientConn
	api  sessionv1alpha1.SessionsClient
}

// Dial returns a client of the daemon. No connection is made until a call
// needs one.
func Dial(opts Options) (*Client, error) {
	if opts.Address == "" {
		return nil, errors.New("a daemon's address is required")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: opts.RootCAs, ServerName: opts.ServerName}
	if opts.Certificate != nil {
		config.Certificates = []tls.Certificate{*opts.Certificate}
	}
	conn, err := grpc.NewClient(opts.Address,
		grpc.WithTransportCredentials(credentials.NewTLS(config)),
		// A daemon that went away is noticed while a stream waits on it.
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, Timeout: 10 * time.Second}),
	)
	if err != nil {
		return nil, fmt.Errorf("daemon %s: %w", opts.Address, err)
	}
	return &Client{conn: conn, api: sessionv1alpha1.NewSessionsClient(conn)}, nil
}

// Close ends every stream of the client.
func (c *Client) Close() error { return c.conn.Close() }

// NewRequestID is an id for one change. A call repeated under the same id
// gets the first answer and changes nothing.
func NewRequestID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// Claimed is a ready TD reserved for a session.
type Claimed struct {
	TD   string
	Host string
	// Evidence is what the guest serves, relayed and unjudged.
	Evidence *session.Relayed
	// BindBy is when the claim lapses and the TD returns to its pool.
	BindBy time.Time
}

// Claim reserves a ready TD of pool for the session, waiting up to wait for
// one. The daemon has fenced the TD: nothing sent to it before can bind it.
func (c *Client) Claim(ctx context.Context, requestID, pool, name string, wait time.Duration) (*Claimed, error) {
	answer, err := c.api.Claim(ctx, &sessionv1alpha1.ClaimRequest{
		RequestId: requestID, Pool: pool, Session: name, Wait: durationpb.New(wait),
	})
	if err != nil {
		return nil, err
	}
	return &Claimed{TD: answer.GetTd(), Host: answer.GetHost(), Evidence: relayed(answer.GetEvidence()), BindBy: answer.GetBindBy().AsTime()}, nil
}

// Bind hands the claimed TD its bind and returns the guest's answer, relayed
// and unjudged: evidence that should be fresh for the bind's nonce.
func (c *Client) Bind(ctx context.Context, requestID, td string, bind *session.SignedBind) (*session.Relayed, error) {
	answer, err := c.api.Bind(ctx, &sessionv1alpha1.BindRequest{
		RequestId: requestID, Td: td, Bind: bind.Raw, Signature: []byte(bind.Signature),
	})
	if err != nil {
		return nil, err
	}
	return relayed(answer.GetEvidence()), nil
}

// Destroy ends the session's TD.
func (c *Client) Destroy(ctx context.Context, requestID, name string) (*sessionv1alpha1.Session, error) {
	return c.api.Destroy(ctx, &sessionv1alpha1.DestroyRequest{RequestId: requestID, Session: name})
}

// Evidence is what the TD's guest serves to anyone, relayed and unjudged.
func (c *Client) Evidence(ctx context.Context, td string) (*session.Relayed, error) {
	answer, err := c.api.GetEvidence(ctx, &sessionv1alpha1.EvidenceRequest{Td: td})
	if err != nil {
		return nil, err
	}
	return relayed(answer), nil
}

func relayed(e *sessionv1alpha1.Evidence) *session.Relayed {
	return &session.Relayed{
		Certificate:   e.GetCertificate(),
		Phase:         session.Phase(e.GetPhase()),
		Launch:        e.GetLaunchDocument(),
		Signature:     string(e.GetLaunchSignature()),
		Events:        e.GetEvents(),
		Bind:          e.GetBind(),
		BindSignature: string(e.GetBindSignature()),
		Evidence:      e.GetQuote(),
		Collateral:    e.GetCollateral(),
	}
}
