package session

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/internal/streamend"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// handshakeVerifyTimeout bounds the evidence check inside a TLS handshake,
// collateral fetch included. VerifyConnection carries no context.
const handshakeVerifyTimeout = 45 * time.Second

// servingVerdictTTL is how long a serving certificate that passed the
// handshake gate is taken to pass it again without being judged again. A
// client opens a TLS session for every stream, and the certificate is the
// same each time. The time is the collateral's own: within it a second
// judgment would read the same documents and decide the same.
const servingVerdictTTL = collateralTTL

// maxServingVerdicts bounds the certificates a client remembers. A guest
// presents one at a time and replaces it rarely.
const maxServingVerdicts = 8

// stapleTimeout bounds the one request a client makes for Intel's documents as
// its guest keeps them. A guest that takes longer costs the client a fetch
// from Intel.
var stapleTimeout = 3 * time.Second

// maxStapledDocuments is more than Intel's four.
const maxStapledDocuments = 8

const (
	// connIdle is how long the client keeps a connection it is not using. The
	// agent closes one after a minute.
	connIdle = 30 * time.Second
	// answerTimeout is how long the client waits for the agent's answer to
	// one request: the longest command, and then some.
	answerTimeout = (MaxExecTimeout + 30) * time.Second
)

// Client talks to one instance of one session guest's agent. Every connection is
// verified against the policy at handshake, and nothing is released or run
// before the guest's instance key is pinned: by a fresh attestation, or by a
// verdict an earlier process of the same owner kept (see Kept). Until then
// the client talks on one connection. From then on every request travels only
// on a connection that terminates at that key. The pin is for the client's
// lifetime: a guest whose agent restarted is a new instance.
//
// Every token names the guest it is for, by the key of the connection it is
// sent on: see operatorauth.Verifier.Audience.
type Client struct {
	base   string
	engine Engine
	auth   operatorauth.AudienceAuthorizer
	http   *http.Client
	// addr, dial and tls are how every connection is opened and its guest
	// verified: the HTTP client's, a stream's and the first alike.
	addr string
	dial Dialer
	tls  *tls.Config
	// now is the clock connections and verdicts age by.
	now func() time.Time
	// timing, when set, is told how long each step took.
	timing Timing

	// first is the connection the client talks on until the pin.
	first firstConn
	// renewing holds one Renew at a time.
	renewing sync.Mutex

	mu sync.Mutex
	// policy is what the client requires of its guest. It changes once, when
	// the client binds a pool guest: see BindAttested.
	policy Policy
	// instanceKey is the PKIX DER of the key the last fresh attestation bound,
	// or a kept verdict names. Once set, a connection presenting any other
	// key is refused.
	instanceKey []byte
	// scope names what this client's verdicts depend on, for a kept one: see
	// scopeOf. Empty keeps none.
	scope string
	// judgedUntil is until when the guest behind instanceKey passes the
	// handshake gate whatever certificate carries the key: see stands. The
	// judgment is this client's last, or the one of the client that kept the
	// verdict.
	judgedUntil time.Time
	// anotherKey says a guest presented another key than the pinned one.
	anotherKey bool
	// last is the fresh attestation this client last ran, and lastAt when.
	last   *Attestation
	lastAt time.Time
	// spare is a connection that ends at instanceKey and waits for the
	// client's next request or stream, and since when: the first connection
	// once the guest on it is attested, or the one Reach opened.
	// spareTransport is what watches its end, which a stream needs.
	spare          *tls.Conn
	spareTransport *streamend.Transport
	spareSince     time.Time
	// verdicts is until when a serving certificate, by the SHA-256 of its
	// DER, passes the handshake gate without being judged again. A verdict
	// from before the pin releases nothing and may rest on less than one
	// after it, so the pin ends them all: see judging.
	verdicts map[[sha256.Size]byte]time.Time
	// servingLeaf is the last certificate that carried the pinned key: the
	// one Renew judges again.
	servingLeaf *x509.Certificate

	// staple is Intel's documents as the guest keeps them, asked for once.
	staple struct {
		once sync.Once
		docs []CollateralDocument
	}
}

// firstConn is the connection a client talks on before it has attested its
// guest, one exchange at a time. With one connection, whatever the client
// says before the pin it says to one guest, and the token of its attestation
// request names the key that guest's connection ends at. A host can answer
// one address with several guests, a connection each.
type firstConn struct {
	mu        sync.Mutex
	conn      *tls.Conn
	transport *streamend.Transport
	reader    *bufio.Reader
	// used is when the last exchange on conn ended.
	used time.Time
}

// drop closes the connection, if there is one. The caller holds mu.
func (f *firstConn) drop() {
	if f.conn != nil {
		_ = f.conn.Close()
	}
	f.conn, f.transport, f.reader = nil, nil, nil
}

// ClientOption changes how a Client reaches its guest. None changes what it
// requires of the guest.
type ClientOption func(*clientOptions) error

type clientOptions struct {
	dial   Dialer
	timing Timing
	kept   *Verdict
}

// Kept gives the client a verdict an earlier process of the same owner
// reached on this guest: see Verdict. The client pins the key it names and
// asks the guest for no quote, and until the verdict's time it judges no
// certificate either. A verdict reached under another policy, or by an
// engine that required something else, is ignored, and so is nil.
//
// A credential is still released only on a fresh attestation by this client.
func Kept(v *Verdict) ClientOption {
	return func(o *clientOptions) error {
		o.kept = v
		return nil
	}
}

// Timing is told how long a client took over one step on its way to its
// guest: see Timed. It is called from whichever goroutine took the step.
type Timing func(step string, took time.Duration)

// The steps a client reports. Each is a span of its own, except that the
// handshake holds the serving verdict when the client has to reach one.
const (
	// TimedDial is the road to the guest: TCP, and the tunnel through a proxy.
	TimedDial = "dial"
	// TimedHandshake is the TLS handshake.
	TimedHandshake = "handshake"
	// TimedServingVerdict is the verdict on the evidence in the guest's
	// serving certificate, inside a handshake.
	TimedServingVerdict = "serving_verdict"
	// TimedRequest, followed by a space and the request's path, is one
	// request sent on an open connection and its answer read.
	TimedRequest = "request"
	// TimedJudgment is evidence judged against the client's policy, after
	// the request that fetched it.
	TimedJudgment = "judgment"
	// TimedStaple is the client asking its guest for Intel's documents, on a
	// connection of its own: dial, handshake, request and answer. It falls
	// inside the verdict or judgment that was short of a document.
	TimedStaple = "staple"
)

// Timed has the client report how long its steps take. It is for whoever
// measures a platform, and changes nothing about what the client requires.
func Timed(report Timing) ClientOption {
	return func(o *clientOptions) error {
		o.timing = report
		return nil
	}
}

// Dialer opens the connection a client's TLS session to its guest runs on.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// Through opens every connection with dial, for a guest that is reached
// through something that carries its bytes, such as a host's stream to it.
// The host in the client's URL is then only a name. Whatever dial reaches is
// verified like any guest: the road to it is trusted for nothing.
func Through(dial Dialer) ClientOption {
	return func(o *clientOptions) error {
		if dial == nil {
			return errors.New("a client needs a way to dial its guest")
		}
		o.dial = dial
		return nil
	}
}

// NewClient returns a client for the agent at baseURL (https://host:8443).
// auth signs requests with a key the guest's bind authorizes, each for
// the one guest it is sent to.
func NewClient(baseURL string, policy Policy, engine Engine, auth operatorauth.AudienceAuthorizer, opts ...ClientOption) (*Client, error) {
	if err := policy.validate(); err != nil {
		return nil, err
	}
	options := clientOptions{dial: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	for _, opt := range opts {
		if err := opt(&options); err != nil {
			return nil, err
		}
	}
	if engine == nil || auth == nil {
		return nil, errors.New("a session client requires an engine and an authorizer")
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" {
		return nil, fmt.Errorf("agent URL must be https://host[:port] with no path, userinfo, query or fragment")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	c := &Client{
		base: "https://" + u.Host, policy: policy, engine: engine, auth: auth,
		addr: net.JoinHostPort(u.Hostname(), port), dial: options.dial, now: time.Now,
		timing:   options.timing,
		verdicts: map[[sha256.Size]byte]time.Time{},
		scope:    scopeOf(policy, engine),
	}
	if options.kept.usable(c.scope, policy) {
		c.instanceKey, c.judgedUntil = options.kept.InstanceKey, options.kept.Until
	}
	c.tls = &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         u.Hostname(),
		InsecureSkipVerify: true, //nolint:gosec // VerifyConnection authenticates the peer by attestation
		VerifyConnection:   c.verifyConnection,
	}
	c.http = &http.Client{
		// Signed requests must never move to another endpoint.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			// The handshake is the client's own, so the connection the guest
			// was attested on can be handed over: see retireFirst.
			DialTLSContext:        c.dialTLS,
			ResponseHeaderTimeout: answerTimeout,
			IdleConnTimeout:       connIdle,
			MaxIdleConns:          2,
			MaxConnsPerHost:       4,
		},
	}
	return c, nil
}

// Close releases idle connections.
func (c *Client) Close() {
	c.first.mu.Lock()
	c.first.drop()
	c.first.mu.Unlock()
	c.mu.Lock()
	spare := c.spare
	c.spare, c.spareTransport = nil, nil
	c.mu.Unlock()
	if spare != nil {
		_ = spare.Close()
	}
	c.http.CloseIdleConnections()
}

// forgetFirst closes the first connection, unless the client has pinned its
// guest since.
func (c *Client) forgetFirst() {
	c.first.mu.Lock()
	defer c.first.mu.Unlock()
	if c.pinned() == nil {
		c.first.drop()
	}
}

// timed reports a step that began at began and has just ended.
func (c *Client) timed(step string, began time.Time) {
	if c.timing != nil {
		c.timing(step, time.Since(began))
	}
}

// required is the policy the client holds its guest to.
func (c *Client) required() Policy {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.policy
}

// pinned is the attested instance key, PKIX DER, or nil before the pin.
func (c *Client) pinned() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.instanceKey
}

func (c *Client) verifyConnection(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return refuse("agent presented no certificate")
	}
	leaf := cs.PeerCertificates[0]
	der, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return refuse("agent presents no usable instance key: %v", err)
	}
	now := c.now()
	fingerprint := sha256.Sum256(leaf.Raw)
	c.mu.Lock()
	pinned := c.instanceKey
	until, judged := c.verdicts[fingerprint]
	if !judged {
		// The verdict on the pinned key covers every certificate that carries
		// it. Before a pin there is none, and the time is zero.
		until = c.judgedUntil
	}
	c.mu.Unlock()
	if pinned != nil && !bytes.Equal(der, pinned) {
		c.mu.Lock()
		c.anotherKey = true
		c.mu.Unlock()
		return refuse("agent presents a different instance key than the one this client attested; a restarted guest needs a new client")
	}
	// The handshake itself proves the peer holds the certificate's key, every
	// time. What is remembered is the verdict on the certificate's evidence.
	due := !now.Before(until)
	if due {
		ctx, cancel := context.WithTimeout(context.Background(), handshakeVerifyTimeout)
		defer cancel()
		began := time.Now()
		// Before the pin a connection carries only what anyone may be told.
		res, err := judgeServingCert(c.judging(ctx, pinned != nil), c.required(), c.engine, leaf, now)
		if err != nil {
			return err
		}
		c.timed(TimedServingVerdict, began)
		until = stands(now, leaf, res)
		// Past the pin a connection carries what the guest is trusted with,
		// and only on a judgment that stands.
		if pinned != nil {
			if err := standsNot(now, until, leaf, res); err != nil {
				return err
			}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if pinned != nil {
		c.servingLeaf = leaf
	}
	if due {
		c.remember(fingerprint, until, now)
		if pinned != nil && until.After(c.judgedUntil) {
			c.judgedUntil = until
		}
	}
	return nil
}

// remember keeps until when the certificate of fingerprint passes the
// handshake gate without being judged again. The caller holds mu.
func (c *Client) remember(fingerprint [sha256.Size]byte, until, now time.Time) {
	for known, expiry := range c.verdicts {
		if !now.Before(expiry) {
			delete(c.verdicts, known)
		}
	}
	if len(c.verdicts) >= maxServingVerdicts {
		clear(c.verdicts)
	}
	c.verdicts[fingerprint] = until
}

// renewAhead is how long before its verdict ends a client fetches the root
// CA CRL anew when asked to renew: time for a fetch that Intel answers
// slowly, and for one more.
const renewAhead = 5 * time.Minute

// Renew keeps the verdict on the pinned guest standing for whoever holds the
// client between commands, such as a session kept for its owner's next ones.
// Within renewAhead of the verdict's end it has the engine fetch the root CA
// CRL anew, in one flight with any other fetch of it, and judges the guest's
// serving certificate again on that CRL: the verdict then stands until an
// hour after the fetch, and no command waits for Intel. Earlier, before a
// connection carried the pinned key, or with an engine that fetches nothing,
// it does nothing. A failure leaves the verdict to end at its time.
func (c *Client) Renew(ctx context.Context) error {
	refetcher, ok := c.engine.(Refetcher)
	if !ok {
		return nil
	}
	// A renewal that waited for another finds the verdict renewed.
	c.renewing.Lock()
	defer c.renewing.Unlock()
	c.mu.Lock()
	leaf, until := c.servingLeaf, c.judgedUntil
	c.mu.Unlock()
	if leaf == nil || until.Sub(c.now()) > renewAhead {
		return nil
	}
	if err := refetcher.Refetch(ctx); err != nil {
		return fmt.Errorf("fetch the root CA CRL anew: %w", err)
	}
	now := c.now()
	res, err := judgeServingCert(c.judging(ctx, true), c.required(), c.engine, leaf, now)
	if err != nil {
		return err
	}
	until = stands(now, leaf, res)
	if err := standsNot(now, until, leaf, res); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.remember(sha256.Sum256(leaf.Raw), until, now)
	if until.After(c.judgedUntil) {
		c.judgedUntil = until
	}
	return nil
}

// Verdict is what this client can vouch for to the owner's next process: the
// key it pinned and until when its last judgment of the guest's evidence
// stands. ok is false before any judgment, and for a client whose engine does
// not say what it requires.
func (c *Client) Verdict() (_ *Verdict, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.scope == "" || c.instanceKey == nil {
		return nil, false
	}
	// The wall clock alone, as a file carries it.
	return &Verdict{SchemaVersion: VerdictSchema, InstanceKey: c.instanceKey, Scope: c.scope, Until: c.judgedUntil.UTC().Round(0)}, true
}

// Pinned reports whether the client holds its guest's instance key: from an
// attestation it ran, or from a kept verdict.
func (c *Client) Pinned() bool { return c.pinned() != nil }

// AnotherKey reports whether a guest presented another key than the one this
// client pinned. Its verdict did not hold for the guest at this address, and
// whoever keeps verdicts should not keep this one.
func (c *Client) AnotherKey() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.anotherKey
}

// judging is the context a judgment of this client runs under. An engine that
// is short of one of Intel's documents may take it from the guest: see
// stapled. The root CA CRL among them it takes only for a verdict that
// releases nothing: the handshake gate before the pin, and the check that a
// guest is unbound, which lead to requests anyone may make and to a bind
// document, which is not secret. The judgment that pins the guest, and every
// verdict after it, rests on a root CA CRL this verifier had from Intel.
func (c *Client) judging(ctx context.Context, releases bool) context.Context {
	ctx = WithCollateralSource(ctx, c.stapled)
	if !releases {
		ctx = withStapledRoot(ctx)
	}
	return ctx
}

// stapled asks the guest for Intel's documents as its host handed them in,
// once in the client's life. The request travels on a connection of its own,
// which nothing verifies and which carries nothing else: no token, nothing of
// the tenant's. It is closed before the client goes on, so no connection that
// began unverified ever carries more. What comes back is a stranger's word:
// the engine holds each document to Intel's signature and to Intel's own date
// on it. A guest that has none, or that does not answer in time, costs the
// client a fetch from Intel and nothing else.
func (c *Client) stapled(ctx context.Context) []CollateralDocument {
	c.staple.once.Do(func() {
		began := time.Now()
		c.staple.docs = c.askStaple(ctx)
		c.timed(TimedStaple, began)
	})
	return c.staple.docs
}

func (c *Client) askStaple(ctx context.Context) []CollateralDocument {
	ctx, cancel := context.WithTimeout(ctx, stapleTimeout)
	defer cancel()
	raw, err := c.dial(ctx, "tcp", c.addr)
	if err != nil {
		return nil
	}
	defer raw.Close()
	// Closing is what interrupts a blocked read or write when ctx ends.
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	conn := tls.Client(raw, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         c.tls.ServerName,
		InsecureSkipVerify: true, //nolint:gosec // nothing here is trusted: the engine checks Intel's signatures
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+PathCollateral, nil)
	if err != nil {
		return nil
	}
	req.Close = true
	if err := req.Write(conn); err != nil {
		return nil
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	data, err := readutil.ReadAll(resp.Body, MaxCollateralBytes)
	if err != nil {
		return nil
	}
	var answer CollateralResponse
	if json.Unmarshal(data, &answer) != nil || len(answer.Documents) > maxStapledDocuments {
		return nil
	}
	return answer.Documents
}

// connect opens a connection to the guest and runs the handshake that
// verifies it. The session runs on a watched transport, which is what tells
// an end the guest sent from an end the road made.
func (c *Client) connect(ctx context.Context) (*tls.Conn, *streamend.Transport, error) {
	// The one document of Intel's that a guest cannot hand over for the
	// judgment that pins it is on its way while the client reaches the guest.
	// A client that has its guest pinned may have nothing left to judge.
	if c.pinned() == nil {
		Prefetch(c.engine)
	}
	began := time.Now()
	raw, err := c.dial(ctx, "tcp", c.addr)
	if err != nil {
		return nil, nil, err
	}
	c.timed(TimedDial, began)
	transport := streamend.Watch(raw)
	conn := tls.Client(transport, c.tls)
	// The dial may wait for a proxy to start the guest, and ctx alone bounds
	// that. The handshake has a bound of its own.
	shake, cancel := context.WithTimeout(ctx, handshakeVerifyTimeout+5*time.Second)
	defer cancel()
	began = time.Now()
	if err := conn.HandshakeContext(shake); err != nil {
		_ = raw.Close()
		return nil, nil, err
	}
	c.timed(TimedHandshake, began)
	return conn, transport, nil
}

// takeSpare hands out the spare connection, if there is a fresh one. A
// stream needs the transport that watches the connection's end, and takes
// no spare that has none.
func (c *Client) takeSpare(stream bool) (*tls.Conn, *streamend.Transport) {
	c.mu.Lock()
	spare, transport, since := c.spare, c.spareTransport, c.spareSince
	if spare == nil || (stream && transport == nil) {
		c.mu.Unlock()
		return nil, nil
	}
	c.spare, c.spareTransport = nil, nil
	c.mu.Unlock()
	if c.now().Sub(since) < connIdle {
		return spare, transport
	}
	_ = spare.Close()
	return nil, nil
}

// dialTLS is the HTTP client's dial: the spare connection if there is a
// fresh one, or a new one.
func (c *Client) dialTLS(ctx context.Context, _, _ string) (net.Conn, error) {
	if spare, _ := c.takeSpare(false); spare != nil {
		return spare, nil
	}
	conn, _, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// Reach opens a connection to the guest and runs the handshake that holds it
// to the pinned key. The connection then waits for the client's next request
// or stream, so reaching costs nothing that one would not have paid. It is
// how a client that rests on a kept verdict learns, before it is asked for
// anything, that its guest is still the one.
func (c *Client) Reach(ctx context.Context) error {
	if c.pinned() == nil {
		return errors.New("no instance key is pinned yet: attest the guest")
	}
	c.mu.Lock()
	waiting := c.spare != nil && c.now().Sub(c.spareSince) < connIdle
	c.mu.Unlock()
	if waiting {
		return nil
	}
	conn, transport, err := c.connect(ctx)
	if err != nil {
		return err
	}
	c.mu.Lock()
	old := c.spare
	c.spare, c.spareTransport, c.spareSince = conn, transport, c.now()
	c.mu.Unlock()
	// One that waited too long, or that another call put there meanwhile.
	if old != nil {
		_ = old.Close()
	}
	return nil
}

// retireFirst ends the time of the first connection, once the client has
// pinned its guest. A connection that ends at the pinned key and is between
// two exchanges goes to the HTTP client, so the first command after an
// attestation costs no second handshake. Any other is closed.
func (c *Client) retireFirst() {
	c.first.mu.Lock()
	conn, transport, reader := c.first.conn, c.first.transport, c.first.reader
	c.first.conn, c.first.transport, c.first.reader = nil, nil, nil
	since := c.first.used
	c.first.mu.Unlock()
	if conn == nil {
		return
	}
	c.mu.Lock()
	keep := reader.Buffered() == 0 && terminatesAt(conn, c.instanceKey) && c.spare == nil
	if keep {
		c.spare, c.spareTransport, c.spareSince = conn, transport, since
	}
	c.mu.Unlock()
	if !keep {
		_ = conn.Close()
	}
}

// keyDigest names a key, given as PKIX DER, the way InstanceKeyDigest does.
func keyDigest(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// request builds one request to the agent. A signed one carries a token for
// the guest that holds key (PKIX DER): the key of the connection the request
// is about to travel on. A key can be granted on many guests, and a token
// for one is of no use at another.
func (c *Client) request(ctx context.Context, method, path string, body []byte, signed bool, key []byte) (*http.Request, error) {
	var req *http.Request
	var err error
	if signed {
		req, err = operatorauth.NewRequest(ctx, method, c.base+path, body, operatorauth.For(c.auth, keyDigest(key)))
	} else {
		req, err = http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	}
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// terminatesAt reports whether conn's TLS peer proved possession of key (PKIX
// DER) in its handshake.
func terminatesAt(conn net.Conn, key []byte) bool {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return false
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return false
	}
	der, err := x509.MarshalPKIXPublicKey(certs[0].PublicKey)
	return err == nil && bytes.Equal(der, key)
}

// Evidence is one raw attestation exchange: what a guest answered for Nonce on
// a connection that terminated at InstanceKey. It is unverified. It is also
// self-contained, so it can be saved and judged later, or by someone else,
// with Verify.
type Evidence struct {
	Nonce []byte `json:"nonce"`
	// InstanceKey is the PKIX DER of the serving key the TLS handshake proved.
	InstanceKey []byte         `json:"instance_key"`
	Response    AttestResponse `json:"response"`
	// leaf is the certificate that carried the key, for an exchange this
	// process ran itself.
	leaf *x509.Certificate
}

// Verify runs the trust gate over a saved exchange.
func (e *Evidence) Verify(ctx context.Context, policy Policy, engine Engine) (*Attestation, error) {
	key, err := x509.ParsePKIXPublicKey(e.InstanceKey)
	if err != nil {
		return nil, refuse("evidence carries no usable instance key: %v", err)
	}
	return VerifyAttestation(ctx, policy, engine, key, e.Nonce, &e.Response)
}

// maxRetryAfter bounds one wait an agent may ask for. The caller's context
// bounds them all.
const maxRetryAfter = 5 * time.Second

// retryAfter reads a Retry-After given in seconds. Anything else is no wait.
func retryAfter(h http.Header) time.Duration {
	seconds, err := strconv.Atoi(h.Get("Retry-After"))
	if err != nil || seconds <= 0 {
		return 0
	}
	return min(time.Duration(seconds)*time.Second, maxRetryAfter)
}

// FetchEvidence requests evidence for a fresh nonce and returns it unjudged.
// A guest rations its quotes: when it says to come back, this waits and asks
// again, for as long as ctx allows.
func (c *Client) FetchEvidence(ctx context.Context) (*Evidence, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	body, err := json.Marshal(AttestRequest{Nonce: nonce})
	if err != nil {
		return nil, err
	}
	var resp AttestResponse
	var state *tls.ConnectionState
	for {
		state, err = c.do(ctx, http.MethodPost, PathAttest, body, &resp)
		var busy *StatusError
		if err == nil || !errors.As(err, &busy) || busy.Status != http.StatusTooManyRequests || busy.RetryAfter == 0 {
			break
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w (gave up waiting: %w)", err, ctx.Err())
		case <-time.After(busy.RetryAfter):
		}
	}
	if err != nil {
		return nil, err
	}
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil, refuse("attestation response did not arrive over a verified TLS connection")
	}
	// Bind to the key of the connection that carried the response: that is the
	// key whose possession the handshake just proved.
	der, err := x509.MarshalPKIXPublicKey(state.PeerCertificates[0].PublicKey)
	if err != nil {
		return nil, fmt.Errorf("encode instance key: %w", err)
	}
	return &Evidence{Nonce: nonce, InstanceKey: der, Response: resp, leaf: state.PeerCertificates[0]}, nil
}

// Attest fetches evidence for a fresh nonce and runs the trust gate on it. On
// success the guest's instance key is pinned for every later request.
func (c *Client) Attest(ctx context.Context) (*Attestation, error) {
	evidence, err := c.FetchEvidence(ctx)
	if err != nil {
		return nil, err
	}
	return c.judge(ctx, evidence)
}

// judge runs the trust gate on evidence and pins the guest's key.
func (c *Client) judge(ctx context.Context, evidence *Evidence) (*Attestation, error) {
	began := time.Now()
	att, err := evidence.Verify(c.judging(ctx, true), c.required(), c.engine)
	if err != nil {
		// Whatever answered is not the guest this client is for. The next
		// attempt starts on a new connection, which may reach another.
		c.forgetFirst()
		return nil, err
	}
	c.timed(TimedJudgment, began)
	now := c.now()
	until := stands(now, evidence.leaf, att.Result)
	// Nothing is released or run on a judgment that does not stand.
	if err := standsNot(now, until, evidence.leaf, att.Result); err != nil {
		return nil, err
	}
	c.mu.Lock()
	// Two guests can satisfy one policy. A client talks to exactly one of them.
	if c.instanceKey != nil && !bytes.Equal(c.instanceKey, att.InstanceKey) {
		c.mu.Unlock()
		return nil, refuse("this client already attested another instance key; a second guest needs its own client")
	}
	c.instanceKey = att.InstanceKey
	c.last, c.lastAt = att, now
	if until.After(c.judgedUntil) {
		c.judgedUntil = until
	}
	if evidence.leaf != nil {
		c.servingLeaf = evidence.leaf
	}
	// What the gate decided before the pin released nothing, and may rest on
	// less than what follows the pin needs. This judgment stands in its place.
	clear(c.verdicts)
	c.mu.Unlock()
	c.retireFirst()
	return att, nil
}

// credentialFreshness is how old an attestation of this client may be for a
// credential to leave on it. One hand-over is several credentials, and the
// guest rations its quotes.
const credentialFreshness = time.Minute

// recent is the attestation this client ran within credentialFreshness, or
// nil. A kept verdict is not one: it carries no evidence.
func (c *Client) recent() *Attestation {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last == nil || c.now().Sub(c.lastAt) >= credentialFreshness {
		return nil
	}
	return c.last
}

// PutCredential releases value into the guest under name. A credential leaves
// only after the guest proved to this client, for a fresh nonce and under the
// key that terminates the connection, that it is the pinned image running the
// pinned document with its sandbox admitted. An attestation this client ran
// within the last minute is that proof. Otherwise it attests first: a kept
// verdict releases nothing.
func (c *Client) PutCredential(ctx context.Context, name string, value []byte) (*Attestation, error) {
	if !credentialRE.MatchString(name) {
		return nil, fmt.Errorf("credential name %q must match %s", name, credentialRE)
	}
	att := c.recent()
	// A guest that was not running when this client last looked may be now.
	if att == nil || att.Phase != PhaseRunning {
		var err error
		if att, err = c.Attest(ctx); err != nil {
			return nil, err
		}
	}
	if att.Phase != PhaseRunning {
		return nil, refuse("refusing to release a credential to a guest in phase %s", att.Phase)
	}
	decl, ok := att.Credential(name)
	if !ok {
		return nil, fmt.Errorf("the guest's bind declares no credential %q", name)
	}
	if len(value) == 0 || len(value) > decl.Limit() {
		return nil, fmt.Errorf("credential %q must be 1..%d bytes", name, decl.Limit())
	}
	body, err := json.Marshal(CredentialRequest{Value: value})
	if err != nil {
		return nil, err
	}
	if _, err := c.do(ctx, http.MethodPut, PathCredentials+name, body, nil); err != nil {
		return nil, err
	}
	return att, nil
}

// maxExecReasks bounds how often Exec asks again for a command whose answer
// was lost with its connection, and execReaskPause is how long it waits
// before each.
const (
	maxExecReasks  = 5
	execReaskPause = 250 * time.Millisecond
)

// answerLost reports whether err is a connection that ended under a request:
// the request may have arrived, and its answer did not.
func answerLost(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}

// Exec runs one command in the sandbox context. An empty ID is filled with a
// random one; pass your own to make a retried call idempotent.
//
// A command's answer is all its connection carries until the command is done,
// so a hop that ends quiet connections, or a network that drops one, takes
// the answer of a long command with it. The guest runs a command at most once
// per id, so Exec asks again with the same id on a new connection, verified
// like the first: it joins the run in flight or reads its result.
func (c *Client) Exec(ctx context.Context, req ExecRequest) (*ExecResponse, error) {
	if req.ID == "" {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return nil, fmt.Errorf("exec id: %w", err)
		}
		req.ID = hex.EncodeToString(id[:])
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	attested := c.instanceKey != nil
	c.mu.Unlock()
	if !attested {
		if _, err := c.Attest(ctx); err != nil {
			return nil, err
		}
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	for asked := 0; ; asked++ {
		var resp ExecResponse
		_, err := c.do(ctx, http.MethodPost, PathExec, body, &resp)
		if err == nil {
			return &resp, nil
		}
		if !answerLost(err) || asked >= maxExecReasks {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(execReaskPause):
		}
	}
}

// Dial opens a stream to a TCP port of the guest's sandbox: a port the
// guest's bind opens to this client's key, on the loopback of the
// sandbox's own network namespace. It attests first if this client has not
// pinned its guest yet. The stream runs in a TLS session of its own that ends
// at the pinned instance key, so nothing between this process and the guest
// reads or changes it. That session is the client's spare connection when it
// has one, which the same handshake verified, and a new one otherwise.
//
// ctx bounds the opening, not the stream. The stream's CloseWrite ends this
// side's input and leaves the other direction open, without a TCP half-close,
// which not every proxy on the way would carry. A port nothing listens on is
// a *StatusError with http.StatusBadGateway.
func (c *Client) Dial(ctx context.Context, port int) (*Stream, error) {
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("port %d is not a TCP port", port)
	}
	if c.pinned() == nil {
		if _, err := c.Attest(ctx); err != nil {
			return nil, err
		}
	}
	body, err := json.Marshal(ForwardRequest{Port: port})
	if err != nil {
		return nil, err
	}
	// A spare connection may have ended while it waited. The guest opened
	// nothing for a request that never reached it, so a new one is asked.
	if conn, transport := c.takeSpare(true); conn != nil {
		stream, err := c.stream(ctx, conn, transport, body)
		if err == nil || !answerLost(err) {
			return stream, err
		}
	}
	// The handshake verifies the guest as every connection of this client's
	// is verified. The instance key is pinned by now, so it refuses any other.
	conn, transport, err := c.connect(ctx)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("open stream: %w", ctxErr)
		}
		return nil, err
	}
	return c.stream(ctx, conn, transport, body)
}

// stream asks the agent, on a connection that ends at the pinned key, to
// turn that connection into a stream.
func (c *Client) stream(ctx context.Context, conn *tls.Conn, transport *streamend.Transport, body []byte) (*Stream, error) {
	req, err := c.request(ctx, http.MethodPost, PathForward, body, true, c.pinned())
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", ForwardProtocol)
	// Closing is what interrupts a blocked read or write when ctx ends.
	stop := context.AfterFunc(ctx, func() { _ = transport.Close() })
	fail := func(err error) (*Stream, error) {
		stop()
		_ = transport.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("open stream: %w", ctxErr)
		}
		return nil, err
	}
	began := time.Now()
	if err := req.Write(conn); err != nil {
		return fail(fmt.Errorf("send the forward request: %w", err))
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return fail(fmt.Errorf("read the agent's answer: %w", err))
	}
	c.timed(TimedRequest+" "+PathForward, began)
	if resp.StatusCode != http.StatusSwitchingProtocols {
		data, _ := readutil.ReadAll(resp.Body, MaxRequestBytes)
		_ = resp.Body.Close()
		var env types.ErrorResponse
		_ = json.Unmarshal(data, &env)
		return fail(&StatusError{Status: resp.StatusCode, Code: env.Error, Message: env.Message, RetryAfter: retryAfter(resp.Header)})
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), ForwardProtocol) {
		return fail(fmt.Errorf("the agent switched to %q, not %s", resp.Header.Get("Upgrade"), ForwardProtocol))
	}
	if !stop() {
		// ctx ended and the connection is already closed.
		return fail(ctx.Err())
	}
	return &Stream{Conn: conn, reader: reader, transport: transport}, nil
}

// ErrStreamCut is the end of a stream that the guest did not end: the
// connection under it ended, or was ended, on the way. What was read before
// it may be short of what the sandbox sent.
var ErrStreamCut = fmt.Errorf("the stream was cut before the guest ended it: %w", io.ErrUnexpectedEOF)

// Stream is a connection to one port of the guest's sandbox: see Dial.
//
// The end of a direction is carried in order and authenticated. CloseWrite
// ends this side's input, the sandbox reads the end of its own, and the
// other direction stays open. Close does that and gives the stream up. Read
// returns io.EOF only for the sandbox's own end of its output. A stream that
// ends any other way has failed, and each side is told so: Read returns an
// error, ErrStreamCut when the connection simply ended, and the sandbox's
// connection is reset.
type Stream struct {
	*tls.Conn
	// reader has what arrived behind the agent's answer before the rest.
	reader    *bufio.Reader
	transport *streamend.Transport
}

func (s *Stream) Read(p []byte) (int, error) {
	n, err := s.reader.Read(p)
	// crypto/tls reports a connection that ended between two records as the
	// end of the stream. Only a close_notify is the guest's word for that.
	if errors.Is(err, io.EOF) && s.transport.Ended() {
		err = ErrStreamCut
	}
	return n, err
}

// Abort gives the stream up as failed: the sandbox's connection is reset
// where Close would have it read the end of its input.
func (s *Stream) Abort() error { return s.transport.Close() }

// StatusError is a non-2xx answer from the agent.
type StatusError struct {
	Status  int
	Code    string
	Message string
	// RetryAfter is how long the agent asked the caller to wait, or zero.
	RetryAfter time.Duration
}

func (e *StatusError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("agent returned HTTP %d", e.Status)
	}
	return fmt.Sprintf("agent returned HTTP %d %s: %s", e.Status, e.Code, e.Message)
}

// ReadyTD is a guest nobody has bound, as Ready verified it.
type ReadyTD struct {
	Document *Document
	// Launch is the exact launch.yaml the guest measured, and Signature the
	// pool's launch key's signature over it.
	Launch    []byte
	Signature string
	// InstanceKey is the key the connection terminated at: the one a bind for
	// this guest must name.
	InstanceKey crypto.PublicKey
}

// Ready fetches the guest's public state and proves, from the evidence in its
// serving certificate, that the guest holding this connection's key is the
// pinned image, launched under the pinned launch key, and had measured nothing
// beyond its launch document when the certificate was issued. That is enough
// to send it a bind, which is not secret. It is not a fresh attestation: the
// guest's answer to the bind is.
func (c *Client) Ready(ctx context.Context) (*ReadyTD, error) {
	var state StateResponse
	tlsState, err := c.send(ctx, http.MethodGet, PathState, nil, &state, false)
	if err != nil {
		return nil, err
	}
	if tlsState == nil || len(tlsState.PeerCertificates) == 0 {
		return nil, refuse("the guest's state did not arrive over a verified TLS connection")
	}
	began := time.Now()
	ready, err := verifyReady(c.judging(ctx, false), c.required(), c.engine, tlsState.PeerCertificates[0], &state, time.Now())
	if err != nil {
		return nil, err
	}
	c.timed(TimedJudgment, began)
	return ready, nil
}

// Bind hands the guest its bind and waits for its sandbox to be admitted. A
// guest already bound by this same bind answers as if it had just been. The
// answer is unjudged: see BindAttested.
func (c *Client) Bind(ctx context.Context, bind *SignedBind) (*BindResponse, error) {
	resp, _, err := c.bind(ctx, bind)
	return resp, err
}

func (c *Client) bind(ctx context.Context, bind *SignedBind) (*BindResponse, *tls.ConnectionState, error) {
	body, err := json.Marshal(BindRequest{Bind: bind.Raw, Signature: bind.Signature})
	if err != nil {
		return nil, nil, err
	}
	var resp BindResponse
	state, err := c.send(ctx, http.MethodPost, PathBind, body, &resp, false)
	if err != nil {
		return nil, nil, err
	}
	return &resp, state, nil
}

// BindAttested hands the guest its bind, as Bind does, and takes the guest as
// its session's from then on. bound is the policy a client of the bound guest
// holds: the launch document and the bind pinned.
//
// The bind carries a nonce, and the guest answers with evidence that is fresh
// for it, taken once it had measured the bind and admitted the sandbox. The
// client judges that under bound, pins the guest's key and keeps bound as its
// policy: what Attest on a new client for the bound guest does, without a
// second connection and without a second request. A guest whose answer
// carries no evidence is asked for it, on the same connection.
//
// An error leaves the client fit for nothing but Close. With the guest's
// answer beside the error, the guest took the bind and is not proven to be
// what the policy asks for.
func (c *Client) BindAttested(ctx context.Context, bind *SignedBind, bound Policy) (*BindResponse, *Attestation, error) {
	if err := bound.validate(); err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(bound.Bind, bind.Raw) {
		return nil, nil, errors.New("the policy for the bound guest must pin the bind that is sent")
	}
	if c.pinned() != nil {
		return nil, nil, errors.New("this client has attested a guest already: a bind needs a client of its own")
	}
	resp, state, err := c.bind(ctx, bind)
	if err != nil {
		return nil, nil, err
	}
	// The guest is bound: nothing it shows from here on fits the policy that
	// let it be reached unbound.
	c.mu.Lock()
	c.policy, c.scope = bound, scopeOf(bound, c.engine)
	c.mu.Unlock()
	if resp.Attestation == nil {
		att, err := c.Attest(ctx)
		return resp, att, err
	}
	if state == nil || len(state.PeerCertificates) == 0 {
		return resp, nil, refuse("the bind's answer did not arrive over a verified TLS connection")
	}
	// As for an attestation request: the key of the connection that carried
	// the answer is the one whose possession the handshake proved.
	der, err := x509.MarshalPKIXPublicKey(state.PeerCertificates[0].PublicKey)
	if err != nil {
		return resp, nil, fmt.Errorf("encode instance key: %w", err)
	}
	att, err := c.judge(ctx, &Evidence{Nonce: bind.Doc.EvidenceNonce(), InstanceKey: der, Response: *resp.Attestation, leaf: state.PeerCertificates[0]})
	if err != nil {
		return resp, nil, err
	}
	return resp, att, nil
}

// do sends one signed request and decodes a 2xx JSON body into out. Only an
// attestation request may precede the pin.
func (c *Client) do(ctx context.Context, method, path string, body []byte, out any) (*tls.ConnectionState, error) {
	return c.send(ctx, method, path, body, out, true)
}

// send is do, with or without a token. The two requests that carry none are
// the public ones. They and an attestation request alone may precede the pin:
// none of them sends anything secret, and only the last needs a token.
func (c *Client) send(ctx context.Context, method, path string, body []byte, out any, signed bool) (*tls.ConnectionState, error) {
	pinned := c.pinned()
	if pinned == nil {
		if signed && path != PathAttest {
			return nil, errors.New("no instance key is attested yet: attest before any other request")
		}
		state, sent, err := c.sendFirst(ctx, method, path, body, out, signed)
		if sent {
			return state, err
		}
		pinned = c.pinned()
	}
	var strayed atomic.Bool
	// began is when the request had its connection: the last one, if the
	// transport sent it again.
	var began atomic.Pointer[time.Time]
	// Every connection the HTTP client makes passes the pin in its handshake.
	// This holds a request off one that did not, however it came to be there:
	// GotConn runs before the transport writes a byte of the request.
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		now := time.Now()
		began.Store(&now)
		if !terminatesAt(info.Conn, pinned) {
			strayed.Store(true)
			_ = info.Conn.Close()
		}
	}})
	req, err := c.request(ctx, method, path, body, signed, pinned)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if strayed.Load() {
			return nil, refuse("a connection to the agent does not terminate at the attested instance key: %v", err)
		}
		return nil, err
	}
	defer resp.Body.Close()
	data, err := readutil.ReadAll(resp.Body, 4*MaxRequestBytes)
	if err != nil {
		return nil, fmt.Errorf("read agent response: %w", err)
	}
	if at := began.Load(); at != nil {
		c.timed(TimedRequest+" "+path, *at)
	}
	if err := decodeAnswer(resp.StatusCode, resp.Header, data, out); err != nil {
		return nil, err
	}
	return resp.TLS, nil
}

// sendFirst is send before the pin: one exchange on the client's first
// connection. It reports false, with nothing sent, when the client has pinned
// its guest in the meantime.
func (c *Client) sendFirst(ctx context.Context, method, path string, body []byte, out any, signed bool) (_ *tls.ConnectionState, sent bool, _ error) {
	f := &c.first
	f.mu.Lock()
	defer f.mu.Unlock()
	if c.pinned() != nil {
		return nil, false, nil
	}
	failed := func(err error) (*tls.ConnectionState, bool, error) {
		if ctxErr := ctx.Err(); ctxErr != nil {
			err = ctxErr
		}
		return nil, true, &url.Error{Op: method[:1] + strings.ToLower(method[1:]), URL: c.base + path, Err: err}
	}
	if f.conn != nil && c.now().Sub(f.used) >= connIdle {
		f.drop()
	}
	if f.conn == nil {
		conn, transport, err := c.connect(ctx)
		if err != nil {
			return failed(err)
		}
		f.conn, f.transport, f.reader = conn, transport, bufio.NewReader(conn)
	}
	conn, reader := f.conn, f.reader
	state := conn.ConnectionState()
	key, err := x509.MarshalPKIXPublicKey(state.PeerCertificates[0].PublicKey)
	if err != nil {
		f.drop()
		return failed(fmt.Errorf("encode instance key: %w", err))
	}
	req, err := c.request(ctx, method, path, body, signed, key)
	if err != nil {
		return nil, true, err
	}
	// Closing is what interrupts a blocked read or write when ctx ends.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(answerTimeout))
	var resp *http.Response
	var data []byte
	began := time.Now()
	if err = req.Write(conn); err == nil {
		if resp, err = http.ReadResponse(reader, req); err == nil {
			data, err = readutil.ReadAll(resp.Body, 4*MaxRequestBytes)
			_ = resp.Body.Close()
		}
	}
	if err == nil {
		c.timed(TimedRequest+" "+path, began)
	}
	// A connection is kept only between two whole exchanges.
	if !stop() || err != nil || resp.Close || reader.Buffered() > 0 {
		f.drop()
	} else {
		_ = conn.SetDeadline(time.Time{})
		f.used = c.now()
	}
	if err != nil {
		return failed(err)
	}
	if err := decodeAnswer(resp.StatusCode, resp.Header, data, out); err != nil {
		return nil, true, err
	}
	return &state, true, nil
}

// decodeAnswer reads the agent's answer: a 2xx JSON body into out, anything
// else as a *StatusError.
func decodeAnswer(status int, header http.Header, data []byte, out any) error {
	if status < 200 || status > 299 {
		var env types.ErrorResponse
		_ = json.Unmarshal(data, &env)
		return &StatusError{Status: status, Code: env.Error, Message: env.Message, RetryAfter: retryAfter(header)}
	}
	if out != nil {
		dec := json.NewDecoder(bytes.NewReader(data))
		if err := dec.Decode(out); err != nil {
			return fmt.Errorf("decode agent response: %w", err)
		}
		if err := dec.Decode(new(any)); err != io.EOF {
			return errors.New("agent response contains trailing data")
		}
	}
	return nil
}
