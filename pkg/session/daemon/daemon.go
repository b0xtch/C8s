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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
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

// Connect opens the client's connection now and returns once it is up. A
// caller whose first call should not wait for the handshake, such as an
// orchestrator that starts sessions against a deadline, connects ahead.
func (c *Client) Connect(ctx context.Context) error {
	c.conn.Connect()
	for state := c.conn.GetState(); state != connectivity.Ready; state = c.conn.GetState() {
		if !c.conn.WaitForStateChange(ctx, state) {
			return fmt.Errorf("daemon %s: %w", c.conn.Target(), ctx.Err())
		}
	}
	return nil
}

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
// and unjudged: the guest's receipt for the bind, and its evidence, which
// holds the quote over the bind's nonce if the guest had it by then.
// Otherwise the call that carried the bind brings it once the guest has
// (BindWith, BindCall.Quote), which this call does not wait for.
func (c *Client) Bind(ctx context.Context, requestID, td string, bind *session.SignedBind) (*session.Relayed, error) {
	call, err := c.StartBind(ctx, requestID, td, bind, nil)
	if err != nil {
		return nil, err
	}
	defer call.Close()
	// The call carries no sealed message.
	if err := call.closeSend(); err != nil {
		return nil, err
	}
	if err := call.Await(); err != nil {
		return nil, err
	}
	return call.Answer, nil
}

// BindCall is a Bind call that may carry a message sealed for the guest: see
// BindWith.
type BindCall struct {
	// Answer is the guest's answer to the bind, relayed and unjudged.
	Answer *session.Relayed
	// SealedStatus is the daemon's word on what became of a sealed message
	// that came with the bind: session.SealedTaken, SealedUnopened or
	// SealedTooLate. Empty for a bind that came with none. Only a sealed
	// answer that opens says the guest acted on a message.
	SealedStatus string
	// TD and Host are the TD a bind that named none claimed, and its host,
	// as the daemon says: the name connections to the session's guest are
	// made by. Whether the guest at that name is the bind's is for the
	// answer's evidence to show.
	TD, Host string

	stream sessionv1alpha1.Sessions_BindClient
	cancel context.CancelFunc
	// carried says the call has carried its sealed message, and closed that
	// its caller's side of it is closed.
	carried, closed bool

	// What the daemon sends after the answer is read by one reader, begun by
	// whoever first waits for any of it. Each of sealed and quoted is closed
	// when its part has come or the call has ended without it, and what the
	// part was is read after that.
	reading        sync.Once
	sealed, quoted chan struct{}
	sealedAnswer   []byte
	sealedStatus   string
	quote          *session.Relayed
	// ended is how the call ended: io.EOF for one the daemon ended.
	ended error
}

// BindWith hands the TD its bind, with a message sealed for the guest
// (session.SealWithBind) when sealed is not nil, and returns once the guest
// has answered the bind. The daemon carries the message and its answer
// unread.
//
// A message the guest took is answered by SealedAnswer, once the guest has
// acted on it. A binder that had not sealed its message when it sent the
// bind, because its check of the guest's evidence was still running, uses
// StartBind and sends it with SendSealed meanwhile: the guest opens it if it
// is still taking the bind.
//
// A guest runs a command once, whatever carried it there, and takes each
// credential once: a caller that has no sealed answer when it needs one
// sends session.SealedMessage.Command over a connection of its own, and is
// answered with the first run's result if the command did run, and puts its
// credentials the same way. A call repeated because its answer was lost
// sends the same sealed message with the bind.
//
// The caller closes the call.
func (c *Client) BindWith(ctx context.Context, requestID, td string, bind *session.SignedBind, sealed []byte) (*BindCall, error) {
	call, err := c.StartBind(ctx, requestID, td, bind, sealed)
	if err != nil {
		return nil, err
	}
	if err := call.Await(); err != nil {
		call.Close()
		return nil, err
	}
	return call, nil
}

// StartBind sends the bind, with sealed if it is not nil, and returns
// without waiting for the guest's answer: Await does that. In between, a
// binder that now has its message sealed sends it with SendSealed.
//
// With no TD named the bind claims its own: the ready TD of the instance key
// it names, which a binder that watches the pool has judged (WatchReady,
// session.ReadyVerdicts). The daemon lets an orchestrator do that, and a
// binder its pool names, under an authority the pool names for it. The call
// then says which TD it claimed, and a TD that another claim or bind took
// first, or that is gone, is answered with an error NotReady knows: the
// binder signs for another TD it has judged.
func (c *Client) StartBind(ctx context.Context, requestID, td string, bind *session.SignedBind, sealed []byte) (*BindCall, error) {
	ctx, cancel := context.WithCancel(ctx)
	stream, err := c.api.Bind(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	call := &BindCall{stream: stream, cancel: cancel, carried: len(sealed) > 0, sealed: make(chan struct{}), quoted: make(chan struct{})}
	if err := stream.Send(&sessionv1alpha1.BindRequest{
		RequestId: requestID, Td: td, Bind: bind.Raw, Signature: []byte(bind.Signature), Sealed: sealed,
	}); err != nil {
		// The stream's own error says why.
		_, err = stream.Recv()
		cancel()
		return nil, err
	}
	if call.carried {
		// The sealed message went with the bind: the call has no more to
		// carry.
		if err := call.closeSend(); err != nil {
			cancel()
			return nil, err
		}
	}
	return call, nil
}

// closeSend closes the caller's side of the call: the daemon ends a call
// whose bind came with no sealed message once it has.
func (b *BindCall) closeSend() error {
	if b.closed {
		return nil
	}
	b.closed = true
	return b.stream.CloseSend()
}

// Await waits for the guest's answer to the bind.
func (b *BindCall) Await() error {
	answer, err := b.stream.Recv()
	if err != nil {
		return err
	}
	out := relayed(answer.GetEvidence())
	if raw := answer.GetReceipt(); len(raw) > 0 && len(raw) <= 2*session.MaxReceiptBytes {
		var receipt session.SignedReceipt
		// A receipt that does not parse is none: the binder then has the
		// evidence alone to go by.
		if json.Unmarshal(raw, &receipt) == nil {
			out.Receipt = &receipt
		}
	}
	b.Answer, b.SealedStatus = out, answer.GetSealedStatus()
	b.TD, b.Host = answer.GetTd(), answer.GetHost()
	return nil
}

// SendSealed sends a sealed message in the call's next message, for a binder
// that sent its bind without one. It is sent once, and before the guest has
// answered the bind if the guest is to open it.
func (b *BindCall) SendSealed(sealed []byte) error {
	if b.carried || b.closed {
		return errors.New("the call has carried its sealed message, or its caller's side is closed")
	}
	b.carried = true
	if err := b.stream.Send(&sessionv1alpha1.BindRequest{Sealed: sealed}); err != nil {
		return err
	}
	return b.closeSend()
}

// read reads what the daemon sends after the answer, until the call ends:
// what became of a sealed message, with the guest's sealed answer to one it
// took, and the guest's evidence once the quote over the bind's nonce is
// settled. They come in the order the guest has them, and each is told to
// whoever waits for it as it comes.
func (b *BindCall) read() {
	b.reading.Do(func() {
		go func() {
			sealed, quoted := false, false
			defer func() {
				if !sealed {
					close(b.sealed)
				}
				if !quoted {
					close(b.quoted)
				}
			}()
			for {
				next, err := b.stream.Recv()
				if err != nil {
					b.ended = err
					return
				}
				if evidence := next.GetEvidence(); evidence != nil && !quoted {
					b.quote, quoted = relayed(evidence), true
					close(b.quoted)
				}
				if (next.GetSealedStatus() != "" || len(next.GetSealedAnswer()) > 0) && !sealed {
					b.sealedAnswer, b.sealedStatus, sealed = next.GetSealedAnswer(), next.GetSealedStatus(), true
					close(b.sealed)
				}
			}
		}()
	})
}

// SealedAnswer waits for the guest's sealed answer, which
// session.SealedMessage.Open opens. With it comes the daemon's word on what
// became of the message. An answer that is none is a message the guest did
// not take, by that word: its sender sends what it sealed over a connection
// of its own, which costs a repeat at most if the word was wrong.
func (b *BindCall) SealedAnswer() (answer []byte, status string, err error) {
	if !b.carried {
		return nil, "", errors.New("the call carried no sealed message")
	}
	if b.SealedStatus != "" && b.SealedStatus != session.SealedTaken {
		return nil, b.SealedStatus, nil
	}
	b.read()
	<-b.sealed
	switch {
	case b.sealedStatus != "" || len(b.sealedAnswer) > 0:
		return b.sealedAnswer, b.sealedStatus, nil
	case errors.Is(b.ended, io.EOF):
		// The call ended with no word on the message: it came too late to
		// be carried.
		return nil, session.SealedTooLate, nil
	}
	return nil, "", b.ended
}

// ErrQuoteNotSent is a Bind call that ended with no word of the quote over
// the bind's nonce: its daemon or its guest sends none on the call, or the
// call broke. The binder asks the guest for an attestation itself.
var ErrQuoteNotSent = errors.New("the bind's call ended without the quote over the bind's nonce")

// Quote waits for the quote the guest takes over the bind's nonce, which
// comes on the bind's own call as soon as the guest has it, and returns the
// guest's evidence with it, relayed and unjudged. The answer's own evidence
// is returned when the quote was in it. A guest that says it gave up on the
// quote is session.ErrNoBindQuote, and a call that ended with no word of one
// is ErrQuoteNotSent: either way the binder asks the guest for an
// attestation over a nonce of its own, on a connection that ends in the
// guest, and no start asks the daemon for evidence.
func (b *BindCall) Quote(ctx context.Context) (*session.Relayed, error) {
	if b.Answer != nil && len(b.Answer.Evidence) > 0 {
		return b.Answer, nil
	}
	b.read()
	select {
	case <-b.quoted:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	switch {
	case b.quote == nil && b.ended != nil && !errors.Is(b.ended, io.EOF):
		return nil, fmt.Errorf("%w: %w", ErrQuoteNotSent, b.ended)
	case b.quote == nil:
		return nil, ErrQuoteNotSent
	case len(b.quote.Evidence) > 0:
		return b.quote, nil
	case b.quote.BindQuote == session.BindQuoteGivenUp:
		return nil, session.ErrNoBindQuote
	}
	// Evidence that says neither is none to wait on.
	return nil, ErrQuoteNotSent
}

// Close ends the call.
func (b *BindCall) Close() { b.cancel() }

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

// NotReady reports whether err is the daemon's answer to a bind that named
// no TD and found no ready TD of the instance key it names: the TD was
// claimed or bound by somebody else, or is gone. Nothing reached a guest.
func NotReady(err error) bool {
	for _, detail := range status.Convert(err).Details() {
		if info, ok := detail.(*errdetails.ErrorInfo); ok && info.GetReason() == "TD_NOT_READY" && info.GetDomain() == "sessions.c8s" {
			return true
		}
	}
	return false
}

// WatchReady calls ready with what each ready TD of pool says of itself, as
// a claim of it would be answered: the TDs ready now, oldest first, then
// each as it becomes ready or comes to serve another certificate. It calls
// left, when that is not nil, with the SHA-256 of the certificate a TD was
// last shown under once the TD is ready no more. A binder judges the ready
// TDs ahead of its claims, and forgets those that left
// (session.ReadyVerdicts). It returns when ctx ends or the stream breaks,
// with the reason: a caller that keeps watching calls it again, and is shown
// the ready TDs anew. The daemon answers it only for a caller the pool's
// configuration names as a binder (BinderName).
func (c *Client) WatchReady(ctx context.Context, pool string, ready func(*session.Relayed), left func(certificate [sha256.Size]byte)) error {
	stream, err := c.api.WatchReady(ctx, &sessionv1alpha1.WatchReadyRequest{Pool: pool})
	if err != nil {
		return err
	}
	for {
		change, err := stream.Recv()
		if err != nil {
			return err
		}
		if evidence := change.GetReady(); evidence != nil {
			ready(relayed(evidence))
		}
		if gone := change.GetLeft(); len(gone) == sha256.Size && left != nil {
			left([sha256.Size]byte(gone))
		}
	}
}

// Watch calls each with every TD of the daemon's host as it is now, oldest
// first, and then with each as it changes: its pool, its state, the session
// it serves and, for one a binder's bind claimed, that binder's key. It is
// an orchestrator's call, and how it learns of a session that a binder
// started with no claim. It returns when ctx ends or the stream breaks, with
// the reason.
func (c *Client) Watch(ctx context.Context, each func(*sessionv1alpha1.Event)) error {
	stream, err := c.api.Watch(ctx, &sessionv1alpha1.WatchRequest{})
	if err != nil {
		return err
	}
	for {
		event, err := stream.Recv()
		if err != nil {
			return err
		}
		each(event)
	}
}

// BinderName is the name a pool's configuration lets a binder watch it by:
// the digest of the public key in the certificate the binder presents.
func BinderName(cert *x509.Certificate) (string, error) {
	return session.InstanceKeyDigest(cert.PublicKey)
}

const (
	// quotePause is how long BoundEvidence waits before it first looks
	// again, and quotePauseMost the longest it waits between two looks. A
	// quote takes a guest some ten milliseconds.
	quotePause     = time.Millisecond
	quotePauseMost = 50 * time.Millisecond
)

// BoundEvidence waits for the quote the TD's guest takes over its bind's
// nonce, and returns the guest's evidence with it, relayed and unjudged. A
// guest that takes none, because its ration of quotes had none to give or
// its quoting service failed, tries again a few times and then says that it
// gave up: that is session.ErrNoBindQuote. Until then it is waited for until
// ctx ends. Either way its binder asks it for an attestation itself.
//
// A daemon has so many evidence requests of one caller in flight at once.
// One it has no room for is asked again after the same pause, so that a
// binder that started many sessions at once waits its turn for each quote
// and loses none.
func (c *Client) BoundEvidence(ctx context.Context, td string) (*session.Relayed, error) {
	for pause := quotePause; ; pause = min(2*pause, quotePauseMost) {
		evidence, err := c.Evidence(ctx, td)
		switch {
		case status.Code(err) == codes.ResourceExhausted:
		case err != nil:
			return nil, err
		case len(evidence.Evidence) > 0:
			return evidence, nil
		case evidence.BindQuote == session.BindQuoteGivenUp:
			return nil, session.ErrNoBindQuote
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pause):
		}
	}
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
		BindQuote:     e.GetBindQuote(),
		Collateral:    e.GetCollateral(),

		ReadyCertificate: e.GetReadyCertificate(),
	}
}
