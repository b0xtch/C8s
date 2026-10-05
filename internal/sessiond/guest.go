package sessiond

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"time"

	sessionv1alpha1 "github.com/confidential-dot-ai/c8s/api/session/v1alpha1"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/disclosure"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// maxGuestAnswer bounds what the daemon reads of one answer of a guest: its
// evidence, or the sealed answer of a sealed message in base64.
const maxGuestAnswer = 8 << 20

// guestClient is how the daemon talks to the agents of its TDs. It verifies
// nothing: the daemon is outside the trust boundary, relays what a guest says
// unread, and acts on none of it beyond bookkeeping.
//
// It keeps a connection to each guest between requests, so that a claim and
// the bind after it cost no handshake: a guest takes a bind on the connection
// its host has kept since it became ready. A connection the guest closed since is replaced
// by the next request, which every request here may be sent again for.
type guestClient struct {
	http *http.Client
}

type dialLimitKey struct{}

// withDialLimit bounds how long a connection opened for a request under ctx
// may take to open, apart from how long the request may take.
func withDialLimit(ctx context.Context, limit time.Duration) context.Context {
	return context.WithValue(ctx, dialLimitKey{}, limit)
}

func newGuestClient(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *guestClient {
	return &guestClient{http: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if limit, ok := ctx.Value(dialLimitKey{}).(time.Duration); ok {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, limit)
				defer cancel()
			}
			return dial(ctx, network, addr)
		},
		// One kept connection a guest: more are opened when requests to one
		// guest overlap, and closed after.
		MaxIdleConnsPerHost: 1,
		MaxIdleConns:        0,
		IdleConnTimeout:     0,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true, //nolint:gosec // an untrusted relay: callers verify the evidence it hands on
		},
		TLSHandshakeTimeout: 10 * time.Second,
	}}}
}

// reconnect drops the kept connections, so that the next request to a guest
// is answered under the certificate the guest serves now.
func (g *guestClient) reconnect() { g.http.CloseIdleConnections() }

// refusal is a guest's definite answer that is neither success nor "try
// again".
type refusal struct {
	status  int
	code    string
	message string
}

func (r *refusal) Error() string {
	return fmt.Sprintf("the guest answered HTTP %d %s: %s", r.status, r.code, r.message)
}

// errBusy is a guest's "try again".
var errBusy = errors.New("the guest is busy")

// send sends one request and returns the guest's answer, unread. header is
// further header fields, each a name and its value.
func (g *guestClient) send(ctx context.Context, addr, method, path string, body []byte, header ...string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, "https://"+addr+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	if method != http.MethodGet {
		// A guest answers a bind sent twice as it answered the first. This
		// has the transport send one again when the kept
		// connection it chose turns out to be closed.
		req.Header.Set("Idempotency-Key", "repeatable")
	}
	return g.http.Do(req)
}

// answered is nil for an answer that is one, errBusy for a guest that says to
// come back, and the guest's refusal otherwise, which it reads from the body.
func answered(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return errBusy
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var answer types.ErrorResponse
	_ = json.Unmarshal(data, &answer)
	// A guest refuses with a code. The words for it are this side's.
	return &refusal{status: resp.StatusCode, code: answer.Error, message: disclosure.Describe(answer.Error)}
}

// do sends one request and returns the answer's body and the certificate the
// guest served it under.
func (g *guestClient) do(ctx context.Context, addr, method, path string, body []byte) (data, leaf []byte, err error) {
	resp, err := g.send(ctx, addr, method, path, body)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if err := answered(resp); err != nil {
		return nil, nil, err
	}
	data, err = io.ReadAll(io.LimitReader(resp.Body, maxGuestAnswer+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > maxGuestAnswer {
		return nil, nil, fmt.Errorf("the guest's answer to %s is more than %d bytes", path, maxGuestAnswer)
	}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		leaf = resp.TLS.PeerCertificates[0].Raw
	}
	return data, leaf, nil
}

// state asks the guest what it says of itself, and under which certificate.
func (g *guestClient) state(ctx context.Context, addr string) (*session.StateResponse, []byte, error) {
	data, leaf, err := g.do(ctx, addr, http.MethodGet, session.PathState, nil)
	if err != nil {
		return nil, nil, err
	}
	var state session.StateResponse
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, nil, fmt.Errorf("the guest's state: %w", err)
	}
	return &state, leaf, nil
}

// ready returns what the guest says of itself once it serves and waits for a
// bind, with whatever its launch document has it prepare done, and the
// certificate it said it under. Nil is a guest that is not there yet.
func (g *guestClient) ready(ctx context.Context, addr string) (state *session.StateResponse, leaf []byte) {
	state, leaf, err := g.state(ctx, addr)
	if err != nil || state.Phase != session.PhaseReady || !state.Prepared {
		return nil, nil
	}
	return state, leaf
}

// collateral is the vendor's documents as the guest keeps them, or nil.
func (g *guestClient) collateral(ctx context.Context, addr string) []byte {
	data, _, err := g.do(ctx, addr, http.MethodGet, session.PathCollateral, nil)
	if err != nil || len(data) > session.MaxCollateralBytes {
		return nil
	}
	return data
}

// evidence is what the guest serves to anyone, as the API's Evidence: its
// state, and with it the quote a bound guest took over its bind's nonce, once
// it has that. Asking has no guest take a quote.
func (g *guestClient) evidence(ctx context.Context, addr string) (*sessionv1alpha1.Evidence, error) {
	state, leaf, err := g.state(ctx, addr)
	if err != nil {
		return nil, err
	}
	evidence, err := stated(leaf, state)
	if err != nil {
		return nil, err
	}
	evidence.Collateral = g.collateral(ctx, addr)
	return evidence, nil
}

// stated is the API's Evidence of what a guest says of itself, under the
// certificate it said it under.
func stated(leaf []byte, state *session.StateResponse) (*sessionv1alpha1.Evidence, error) {
	evidence := &sessionv1alpha1.Evidence{
		Certificate:     leaf,
		LaunchDocument:  state.Launch,
		LaunchSignature: []byte(state.Signature),
		Events:          state.Events,
		Bind:            state.Bind,
		BindSignature:   []byte(state.BindSignature),
		Phase:           string(state.Phase),
	}
	if att := state.Attestation; att != nil {
		var err error
		if evidence, err = attested(leaf, att); err != nil {
			return nil, err
		}
	}
	evidence.BindQuote, evidence.ReadyCertificate = state.BindQuote, state.ReadyCertificate
	return evidence, nil
}

// attested is the API's Evidence of a guest's attestation: the quote, and
// what the guest measured as it said so with the quote.
func attested(leaf []byte, att *session.AttestResponse) (*sessionv1alpha1.Evidence, error) {
	quote, err := json.Marshal(att.Evidence)
	if err != nil {
		return nil, err
	}
	return &sessionv1alpha1.Evidence{
		Certificate:     leaf,
		LaunchDocument:  att.Launch,
		LaunchSignature: []byte(att.Signature),
		Events:          att.Events,
		Bind:            att.Bind,
		BindSignature:   []byte(att.BindSignature),
		Phase:           string(att.Phase),
		Quote:           quote,
	}, nil
}

// followed is one thing a guest says after its first answer to a bind: the
// sealed answer of a sealed message it took, or its evidence once the quote
// over the bind's nonce is settled, taken or given up.
type followed struct {
	sealed   *session.SealedReply
	evidence *sessionv1alpha1.Evidence
}

// following yields what follows a guest's first answer to a bind, in the
// order the guest sends it, and io.EOF once the guest has said all it will.
type following func() (*followed, error)

// bound is a guest's answer to a bind, as the daemon relays it.
type boundAnswer struct {
	evidence *sessionv1alpha1.Evidence
	receipt  []byte
	// sealed is what the guest says became of a sealed message that came
	// with the bind, and later what the guest says after this answer.
	sealed string
	later  following
}

// bind hands the guest its bind, with a message sealed for it if one came,
// and returns the guest's answer: its receipt for the bind, as it sent it,
// and its evidence. The evidence holds the quote over the bind's nonce if the
// guest had it by then. Otherwise it holds the certificate and the phase
// alone: the receipt says the rest, and the guest sends its evidence with the
// quote on the same answer once it has it, or its word that it gave up on
// one. A guest that took the sealed message sends its sealed answer on that
// answer too, once it has acted on it. The two come in the order the guest
// has them. wrote, if given, is called once the bind has been written to the
// guest's connection.
func (g *guestClient) bind(ctx context.Context, addr string, bind, signature, sealed []byte, wrote func()) (*boundAnswer, error) {
	body, err := json.Marshal(session.BindRequest{Bind: bind, Signature: string(signature), Sealed: sealed})
	if err != nil {
		return nil, err
	}
	if wrote != nil {
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				wrote()
			}
		}})
	}
	// This side reads the answer to its end.
	resp, err := g.send(ctx, addr, http.MethodPost, session.PathBind, body, session.BindQuoteHeader, session.BindQuoteFollows)
	if err != nil {
		return nil, err
	}
	// The answer is one document and whatever follows it. The body stays
	// open until the last is read.
	documents := json.NewDecoder(io.LimitReader(resp.Body, maxGuestAnswer))
	if err := answered(resp); err != nil {
		resp.Body.Close()
		return nil, err
	}
	var answer session.BindResponse
	if err := documents.Decode(&answer); err != nil {
		resp.Body.Close()
		return nil, fmt.Errorf("the guest's answer to the bind: %w", err)
	}
	var leaf []byte
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		leaf = resp.TLS.PeerCertificates[0].Raw
	}
	out := &boundAnswer{sealed: answer.Sealed}
	if answer.Receipt != nil {
		if out.receipt, err = json.Marshal(answer.Receipt); err != nil {
			resp.Body.Close()
			return nil, err
		}
	}
	if answer.Attestation != nil {
		if out.evidence, err = attested(leaf, answer.Attestation); err != nil {
			resp.Body.Close()
			return nil, err
		}
	} else {
		out.evidence = &sessionv1alpha1.Evidence{Certificate: leaf, Phase: string(answer.Phase)}
	}
	// What follows is read by one caller, a document at a time, to the end
	// of the answer, so that the connection is kept for the next request.
	var ended error
	out.later = func() (*followed, error) {
		if ended != nil {
			return nil, ended
		}
		next, err := follows(documents, leaf)
		if err != nil {
			ended = err
			resp.Body.Close()
		}
		return next, err
	}
	return out, nil
}

// follows reads the next document of a guest's answer to a bind after the
// first: a sealed answer, which says what became of a sealed message, or the
// guest's state. Anything else ends the reading.
func follows(documents *json.Decoder, leaf []byte) (*followed, error) {
	var raw json.RawMessage
	if err := documents.Decode(&raw); err != nil {
		// io.EOF is a guest that has said all it will.
		return nil, err
	}
	var kind struct {
		Sealed string        `json:"sealed"`
		Phase  session.Phase `json:"phase"`
	}
	if err := json.Unmarshal(raw, &kind); err != nil {
		return nil, fmt.Errorf("what followed the guest's answer to the bind: %w", err)
	}
	switch {
	case kind.Sealed != "":
		var reply session.SealedReply
		if err := json.Unmarshal(raw, &reply); err != nil {
			return nil, fmt.Errorf("the guest's answer to the sealed message: %w", err)
		}
		return &followed{sealed: &reply}, nil
	case kind.Phase != "":
		var state session.StateResponse
		if err := json.Unmarshal(raw, &state); err != nil {
			return nil, fmt.Errorf("the guest's state after its bind: %w", err)
		}
		evidence, err := stated(leaf, &state)
		if err != nil {
			return nil, err
		}
		return &followed{evidence: evidence}, nil
	}
	return nil, errors.New("the guest's answer to the bind was followed by a document that is neither a sealed answer nor its state")
}

// sealed hands a guest that is taking its bind a sealed message that
// followed the bind, and waits for what became of it.
//
// It goes on a connection of its own, since the bind's is taken until the
// guest has answered. A bind ends every connection its guest accepted before
// it arrived, and one made as the bind was written may be among them: it
// breaks, or the guest refuses what came on it unread. A second, made after
// that, is one the guest lets in, and the guest answers a message it is sent
// twice as it answered the first.
func (g *guestClient) sealed(ctx context.Context, addr string, sealed []byte) (*session.SealedReply, error) {
	body, err := json.Marshal(session.SealedRequest{Sealed: sealed})
	if err != nil {
		return nil, err
	}
	data, _, err := g.do(ctx, addr, http.MethodPost, session.PathBindSealed, body)
	var refused *refusal
	if err != nil && ctx.Err() == nil && (!errors.As(err, &refused) || refused.code == string(disclosure.Fenced)) {
		data, _, err = g.do(ctx, addr, http.MethodPost, session.PathBindSealed, body)
	}
	if err != nil {
		return nil, err
	}
	var answer session.SealedReply
	if err := json.Unmarshal(data, &answer); err != nil {
		return nil, fmt.Errorf("the guest's answer to the sealed message: %w", err)
	}
	return &answer, nil
}
