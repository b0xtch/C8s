package podcvm

import (
	"bytes"
	"context"
	"crypto/rand"
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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// handshakeVerifyTimeout bounds the evidence check inside a TLS handshake,
// collateral fetch included. VerifyConnection carries no context.
const handshakeVerifyTimeout = 45 * time.Second

// Client talks to one instance of one pod CVM's agent. Every connection is
// verified against the policy at handshake, and nothing is released or run
// before a fresh attestation has pinned the guest's instance key. From then on
// every request travels only on a connection that terminates at that key. The
// pin is for the client's lifetime: a guest whose agent restarted is a new
// instance.
type Client struct {
	base   string
	policy Policy
	engine Engine
	auth   operatorauth.Authorizer
	http   *http.Client

	mu sync.Mutex
	// instanceKey is the PKIX DER of the key the last fresh attestation bound.
	// Once set, a connection presenting any other key is refused.
	instanceKey []byte
}

// NewClient returns a client for the agent at baseURL (https://host:8443).
// auth signs requests with a key the launch document authorizes.
func NewClient(baseURL string, policy Policy, engine Engine, auth operatorauth.Authorizer) (*Client, error) {
	if err := policy.validate(); err != nil {
		return nil, err
	}
	if engine == nil || auth == nil {
		return nil, errors.New("podcvm client requires an engine and an authorizer")
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" {
		return nil, fmt.Errorf("agent URL must be https://host[:port] with no path, userinfo, query or fragment")
	}
	c := &Client{base: "https://" + u.Host, policy: policy, engine: engine, auth: auth}
	c.http = &http.Client{
		// Signed requests must never move to another endpoint.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			TLSHandshakeTimeout:   handshakeVerifyTimeout + 5*time.Second,
			ResponseHeaderTimeout: (MaxExecTimeout + 30) * time.Second,
			IdleConnTimeout:       30 * time.Second,
			MaxIdleConns:          2,
			MaxConnsPerHost:       4,
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS13,
				InsecureSkipVerify: true, //nolint:gosec // VerifyConnection authenticates the peer by attestation
				VerifyConnection:   c.verifyConnection,
			},
		},
	}
	return c, nil
}

// Close releases idle connections.
func (c *Client) Close() { c.http.CloseIdleConnections() }

func (c *Client) verifyConnection(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return refuse("agent presented no certificate")
	}
	leaf := cs.PeerCertificates[0]
	c.mu.Lock()
	pinned := c.instanceKey
	c.mu.Unlock()
	if pinned != nil {
		der, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
		if err != nil || !bytes.Equal(der, pinned) {
			return refuse("agent presents a different instance key than the one this client attested; a restarted guest needs a new client")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), handshakeVerifyTimeout)
	defer cancel()
	return VerifyServingCert(ctx, c.policy, c.engine, leaf, time.Now())
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
}

// Verify runs the trust gate over a saved exchange.
func (e *Evidence) Verify(ctx context.Context, policy Policy, engine Engine) (*Attestation, error) {
	key, err := x509.ParsePKIXPublicKey(e.InstanceKey)
	if err != nil {
		return nil, refuse("evidence carries no usable instance key: %v", err)
	}
	return VerifyAttestation(ctx, policy, engine, key, e.Nonce, &e.Response)
}

// FetchEvidence requests evidence for a fresh nonce and returns it unjudged.
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
	state, err := c.do(ctx, http.MethodPost, PathAttest, body, &resp)
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
	return &Evidence{Nonce: nonce, InstanceKey: der, Response: resp}, nil
}

// Attest fetches evidence for a fresh nonce and runs the trust gate on it. On
// success the guest's instance key is pinned for every later request.
func (c *Client) Attest(ctx context.Context) (*Attestation, error) {
	evidence, err := c.FetchEvidence(ctx)
	if err != nil {
		return nil, err
	}
	att, err := evidence.Verify(ctx, c.policy, c.engine)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Two guests can satisfy one policy. A client talks to exactly one of them.
	if c.instanceKey != nil && !bytes.Equal(c.instanceKey, att.InstanceKey) {
		return nil, refuse("this client already attested another instance key; a second guest needs its own client")
	}
	c.instanceKey = att.InstanceKey
	return att, nil
}

// PutCredential releases value into the guest under name. It attests first,
// every time: a credential leaves only after the guest proved, for a fresh
// nonce and under the key that terminates the connection, that it is the
// pinned image running the pinned document with its workload admitted.
func (c *Client) PutCredential(ctx context.Context, name string, value []byte) (*Attestation, error) {
	if !credentialRE.MatchString(name) {
		return nil, fmt.Errorf("credential name %q must match %s", name, credentialRE)
	}
	att, err := c.Attest(ctx)
	if err != nil {
		return nil, err
	}
	if att.Phase != PhaseRunning {
		return nil, refuse("refusing to release a credential to a guest in phase %s", att.Phase)
	}
	decl, ok := att.Document.Credential(name)
	if !ok {
		return nil, fmt.Errorf("the launch document declares no credential %q", name)
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

// Exec runs one command in the workload context. An empty ID is filled with a
// random one; pass your own to make a retried call idempotent.
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
	var resp ExecResponse
	if _, err := c.do(ctx, http.MethodPost, PathExec, body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// StatusError is a non-2xx answer from the agent.
type StatusError struct {
	Status  int
	Code    string
	Message string
}

func (e *StatusError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("agent returned HTTP %d", e.Status)
	}
	return fmt.Sprintf("agent returned HTTP %d %s: %s", e.Status, e.Code, e.Message)
}

// do sends one signed request and decodes a 2xx JSON body into out. Only an
// attestation request may precede the pin.
func (c *Client) do(ctx context.Context, method, path string, body []byte, out any) (*tls.ConnectionState, error) {
	c.mu.Lock()
	pinned := c.instanceKey
	c.mu.Unlock()
	if pinned == nil && path != PathAttest {
		return nil, errors.New("no instance key is attested yet: attest before any other request")
	}
	var strayed atomic.Bool
	if pinned != nil {
		// A pooled connection can predate the pin, and without a pinned document
		// its handshake proved only the image. GotConn runs before the transport
		// writes a byte of this request, so closing the connection here keeps
		// the request off it.
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
			if !terminatesAt(info.Conn, pinned) {
				strayed.Store(true)
				_ = info.Conn.Close()
			}
		}})
	}
	req, err := operatorauth.NewRequest(ctx, method, c.base+path, body, c.auth)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
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
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var env types.ErrorResponse
		_ = json.Unmarshal(data, &env)
		return nil, &StatusError{Status: resp.StatusCode, Code: env.Error, Message: env.Message}
	}
	if out != nil {
		dec := json.NewDecoder(bytes.NewReader(data))
		if err := dec.Decode(out); err != nil {
			return nil, fmt.Errorf("decode agent response: %w", err)
		}
		if err := dec.Decode(new(any)); err != io.EOF {
			return nil, errors.New("agent response contains trailing data")
		}
	}
	return resp.TLS, nil
}
