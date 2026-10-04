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
	"time"

	sessionv1alpha1 "github.com/confidential-dot-ai/c8s/api/session/v1alpha1"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/disclosure"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// maxGuestAnswer bounds what the daemon reads of one answer of a guest.
const maxGuestAnswer = 4 << 20

// guestClient is how the daemon talks to the agents of its TDs. It verifies
// nothing: the daemon is outside the trust boundary, relays what a guest says
// unread, and acts on none of it beyond bookkeeping.
//
// It keeps a connection to each guest between requests, so that a claim and
// the bind after it cost no handshake: a guest takes a bind on the connection
// its fence was raised on. A connection the guest closed since is replaced
// by the next request, which every request here may be sent again for.
type guestClient struct {
	http *http.Client
}

func newGuestClient(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *guestClient {
	return &guestClient{http: &http.Client{Transport: &http.Transport{
		DialContext: dial,
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

// do sends one request and returns the answer's body and the certificate the
// guest served it under.
func (g *guestClient) do(ctx context.Context, addr, method, path string, body []byte) (data, leaf []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, method, "https://"+addr+path, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		// A guest answers a fence or a bind sent twice as it answered the
		// first. This has the transport send one again when the kept
		// connection it chose turns out to be closed.
		req.Header.Set("Idempotency-Key", "repeatable")
	}
	resp, err := g.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
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
	switch resp.StatusCode {
	case http.StatusOK:
		return data, leaf, nil
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return nil, nil, errBusy
	}
	var answer types.ErrorResponse
	_ = json.Unmarshal(data, &answer)
	// A guest refuses with a code. The words for it are this side's.
	return nil, nil, &refusal{status: resp.StatusCode, code: answer.Error, message: disclosure.Describe(answer.Error)}
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
// bind, with whatever its launch document has it prepare done. Nil is a
// guest that is not there yet.
func (g *guestClient) ready(ctx context.Context, addr string) *session.StateResponse {
	state, _, err := g.state(ctx, addr)
	if err != nil || state.Phase != session.PhaseReady || !state.Prepared {
		return nil
	}
	return state
}

// fence has a ready guest cut every other connection it accepted so far. The
// answer says whether the guest is still nobody's, and leaf is the
// certificate it came under.
func (g *guestClient) fence(ctx context.Context, addr string) (leaf []byte, err error) {
	data, leaf, err := g.do(ctx, addr, http.MethodPost, session.PathFence, nil)
	if err != nil {
		return nil, err
	}
	var answer session.FenceResponse
	if err := json.Unmarshal(data, &answer); err != nil {
		return nil, fmt.Errorf("the guest's answer to the fence: %w", err)
	}
	if answer.Phase != session.PhaseReady {
		return nil, fmt.Errorf("the guest is %s, not ready: somebody bound it", answer.Phase)
	}
	return leaf, nil
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
		if evidence, err = attested(leaf, att); err != nil {
			return nil, err
		}
	}
	evidence.Collateral = g.collateral(ctx, addr)
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

// bind hands the guest its bind and returns the guest's answer: its receipt
// for the bind, as it sent it, and its evidence. The evidence holds the quote
// over the bind's nonce if the guest had it by then. Otherwise it holds the
// certificate and the phase alone: the receipt says the rest, and the quote
// comes with the guest's evidence once the guest has it.
func (g *guestClient) bind(ctx context.Context, addr string, bind, signature []byte) (evidence *sessionv1alpha1.Evidence, receipt []byte, err error) {
	body, err := json.Marshal(session.BindRequest{Bind: bind, Signature: string(signature)})
	if err != nil {
		return nil, nil, err
	}
	data, leaf, err := g.do(ctx, addr, http.MethodPost, session.PathBind, body)
	if err != nil {
		return nil, nil, err
	}
	var answer session.BindResponse
	if err := json.Unmarshal(data, &answer); err != nil {
		return nil, nil, fmt.Errorf("the guest's answer to the bind: %w", err)
	}
	if answer.Receipt != nil {
		if receipt, err = json.Marshal(answer.Receipt); err != nil {
			return nil, nil, err
		}
	}
	if answer.Attestation != nil {
		evidence, err = attested(leaf, answer.Attestation)
		return evidence, receipt, err
	}
	return &sessionv1alpha1.Evidence{Certificate: leaf, Phase: string(answer.Phase)}, receipt, nil
}
