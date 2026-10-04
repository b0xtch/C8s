package sessionagent_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/disclosure"
)

// pool is a harness whose guest nobody has bound yet, with the owner who will
// bind it: an authority key that signs binds and an access key the bind
// grants.
type pool struct {
	*harness
	runner    *recordingRunner
	access    *operatorauth.Signer
	accessPub string
}

func newPool(t *testing.T) *pool {
	t.Helper()
	return newPoolWith(t, nil)
}

// newPoolWith is newPool with a change to the pool's launch document.
func newPoolWith(t *testing.T, mutate func(*session.BundleOptions)) *pool {
	t.Helper()
	h := newUnbound(t, mutate)
	p := &pool{harness: h, runner: &recordingRunner{ProcessRunner: h.cfg.Runner.(*sessionagent.ProcessRunner), td: h.td}}
	h.cfg.Runner = p.runner
	p.access, p.accessPub = h.owner, h.ownerPub
	return p
}

func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func insecureClient() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // a probe: nothing about this peer is trusted
}

// freeAddr returns a loopback address nothing listens on.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// boundClient is the owner's client once it has bound the guest: it pins the
// exact documents and no longer accepts an unbound one.
func (p *pool) boundClient(t *testing.T, ready *session.ReadyTD, bind *session.SignedBind) *session.Client {
	t.Helper()
	p.pin(ready, bind)
	return p.client(t, p.access)
}

func (p *pool) postBind(t *testing.T, raw []byte, signature string) int {
	t.Helper()
	body, err := json.Marshal(session.BindRequest{Bind: raw, Signature: signature})
	if err != nil {
		t.Fatal(err)
	}
	return p.raw(t, http.MethodPost, session.PathBind, body, "")
}

// state is what the guest tells a caller who holds no key.
func (p *pool) state(t *testing.T) session.StateResponse {
	t.Helper()
	return stateAs(t, p.url, nil)
}

// stateAs is the guest's state as it tells it to the holder of signer's key,
// or to a stranger when signer is nil.
func stateAs(t *testing.T, url string, signer *operatorauth.Signer) session.StateResponse {
	t.Helper()
	req, err := http.NewRequestWithContext(ctxT(t), http.MethodGet, url+session.PathState, nil)
	if signer != nil {
		req, err = operatorauth.NewRequest(ctxT(t), http.MethodGet, url+session.PathState, nil, operatorauth.For(signer, sessiontest.Audience(t, url)))
	}
	if err != nil {
		t.Fatal(err)
	}
	client := insecureClient()
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var state session.StateResponse
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("state: HTTP %d, %v", resp.StatusCode, err)
	}
	return state
}

func stepNames(steps []session.AdmissionStep) string {
	names := make([]string, len(steps))
	for i, step := range steps {
		names[i] = step.Name
	}
	return strings.Join(names, ",")
}

// The warm path: a guest that belongs to nobody is verified, bound by a
// tenant's authority, and from then on is that tenant's and nobody else's.
func TestGuestIsBoundOnceAndThenDriven(t *testing.T) {
	p := newPool(t)
	p.start(t)
	seed := runtimemeasure.Seed(p.bundle.LaunchKey)
	launch := session.DocumentDigest(p.bundle.Launch)
	unbound := runtimemeasure.FromDigestsSeeded(seed, []string{launch})
	if got := register(t, p.td); !bytes.Equal(got, unbound[:]) {
		t.Fatalf("unbound register = %x", got)
	}
	if state := p.state(t); state.Phase != session.PhaseReady || len(state.Events) != 1 || len(state.Bind) != 0 {
		t.Fatalf("state before bind: %+v", state)
	}
	if steps := p.runner.recorded(); steps != "" {
		t.Fatalf("an unbound guest drove its runner: %s", steps)
	}

	// Unbound, the guest answers no key at all: not the pool's launch key,
	// not the key a bind will later name.
	for name, signer := range map[string]*operatorauth.Signer{"the pool's launch key": p.launchSigner(t), "the owner's access key": p.access} {
		client := p.client(t, signer)
		if _, err := client.Attest(ctxT(t)); !isStatus(err, http.StatusUnauthorized) {
			t.Fatalf("%s got an attestation from an unbound guest: %v", name, err)
		}
	}

	client := p.client(t, p.access)
	ready, err := client.Ready(ctxT(t))
	if err != nil {
		t.Fatalf("Unbound: %v", err)
	}
	if ready.Document.Pool != "agents" || !bytes.Equal(ready.Launch, p.bundle.Launch) {
		t.Fatalf("unexpected guest: %+v", ready.Document)
	}
	bind := p.bindFor(t, ready, nil)
	resp, err := client.Bind(ctxT(t), bind)
	if err != nil || resp.Phase != session.PhaseRunning || resp.Replayed {
		t.Fatalf("Bind = %+v, %v", resp, err)
	}
	// The answer says where the guest's time went: what its runner reported,
	// then the measurement, then the start.
	if got := stepNames(resp.Admission); got != "fetch,measure,start" || resp.Admission[0].Micros != preparedIn.Microseconds() {
		t.Fatalf("admission steps %+v", resp.Admission)
	}

	// The bind was measured before the runner saw anything of it, and the
	// sandbox after it was prepared and before it started.
	bindDigest := session.DocumentDigest(bind.Raw)
	bound := runtimemeasure.FromDigestsSeeded(seed, []string{launch, bindDigest})
	running := runtimemeasure.FromDigestsSeeded(seed, []string{launch, bindDigest, "sha256:" + strings.Repeat("2", 64)})
	if p.runner.recorded() != "prepare "+sandboxImage+",start" {
		t.Fatalf("runner steps = %s", p.runner.recorded())
	}
	if !bytes.Equal(p.runner.atPrepare, bound[:]) {
		t.Fatal("the sandbox was prepared before the bind was measured")
	}
	if !bytes.Equal(p.runner.atStart, running[:]) || !bytes.Equal(register(t, p.td), running[:]) {
		t.Fatal("the register does not hold launch, bind and sandbox in that order")
	}

	tenant := p.boundClient(t, ready, bind)
	att, err := tenant.Attest(ctxT(t))
	if err != nil {
		t.Fatalf("Attest after bind: %v", err)
	}
	if att.Phase != session.PhaseRunning || len(att.Events) != 3 || att.Tenant != "acme" || att.Session != "sbx-1" || att.Bind == nil {
		t.Fatalf("attestation after bind: %+v", att)
	}
	if _, err := tenant.PutCredential(ctxT(t), "test-token", []byte("s3cr3t")); err != nil {
		t.Fatalf("PutCredential: %v", err)
	}
	out, err := tenant.Exec(ctxT(t), session.ExecRequest{Argv: []string{"sh", "-c", `cat "$C8S_CREDENTIALS_DIR/test-token"`}})
	if err != nil || string(out.Stdout) != "s3cr3t" {
		t.Fatalf("exec = %+v, %v", out, err)
	}

	// The same bind again is answered as before. Any other is refused, whoever
	// signs it, and the register does not move.
	again, err := client.Bind(ctxT(t), bind)
	if err != nil || !again.Replayed || again.Phase != session.PhaseRunning || !slices.Equal(again.Admission, resp.Admission) {
		t.Fatalf("the same bind again = %+v, %v", again, err)
	}
	second := p.bindFor(t, ready, func(o *session.BindOptions) { o.Tenant = "someone-else" })
	if _, err := client.Bind(ctxT(t), second); !isStatus(err, http.StatusConflict) {
		t.Fatalf("a second bind: %v", err)
	}
	if !bytes.Equal(register(t, p.td), running[:]) {
		t.Fatal("a refused bind moved the register")
	}
	if state := stateAs(t, p.url, p.access); state.Phase != session.PhaseRunning || !bytes.Equal(state.Bind, bind.Raw) {
		t.Fatalf("state after bind: phase %s", state.Phase)
	}

	// The pool's launch key made the guest and can do nothing with it.
	platform := p.client(t, p.launchSigner(t))
	if _, err := platform.Attest(ctxT(t)); !isStatus(err, http.StatusUnauthorized) {
		t.Fatalf("the pool's launch key attests a bound guest: %v", err)
	}
}

func isStatus(err error, want int) bool {
	var status *session.StatusError
	return errors.As(err, &status) && status.Status == want
}

// An unbound guest that reads a bind it will not take measures nothing, stays
// nobody's, and ends: it has taken in input of somebody's choosing, so it is
// not handed to a tenant after that.
func TestRefusedBindRetiresAnUnboundGuest(t *testing.T) {
	otherKey := newECKey(t)
	for name, build := range map[string]func(t *testing.T, p *pool, ready *session.ReadyTD) (raw []byte, signature string){
		"for another guest's instance key": func(t *testing.T, p *pool, ready *session.ReadyTD) ([]byte, string) {
			bind := p.bindFor(t, ready, func(o *session.BindOptions) { o.InstanceKey = &otherKey.PublicKey })
			return bind.Raw, bind.Signature
		},
		"expired": func(t *testing.T, p *pool, ready *session.ReadyTD) ([]byte, string) {
			bind := p.bindFor(t, ready, func(o *session.BindOptions) { o.NotAfter = time.Now().Add(-time.Hour) })
			return bind.Raw, bind.Signature
		},
		"signed by a key it does not name": func(t *testing.T, p *pool, ready *session.ReadyTD) ([]byte, string) {
			bind := p.bindFor(t, ready, nil)
			forged, err := operatorauth.SignDetached(otherKey, bind.Raw)
			if err != nil {
				t.Fatal(err)
			}
			return bind.Raw, forged
		},
		"changed after signing": func(t *testing.T, p *pool, ready *session.ReadyTD) ([]byte, string) {
			bind := p.bindFor(t, ready, nil)
			return bytes.Replace(bind.Raw, []byte(`"tenant":"acme"`), []byte(`"tenant":"evil"`), 1), bind.Signature
		},
		"not canonical": func(t *testing.T, p *pool, ready *session.ReadyTD) ([]byte, string) {
			bind := p.bindFor(t, ready, nil)
			return append(bytes.Clone(bind.Raw), '\n'), bind.Signature
		},
		"unsigned": func(t *testing.T, p *pool, ready *session.ReadyTD) ([]byte, string) {
			return p.bindFor(t, ready, nil).Raw, ""
		},
		"not a bind at all": func(*testing.T, *pool, *session.ReadyTD) ([]byte, string) {
			return []byte(`{"schemaVersion":"c8s-session-launch/v1"}`), "AAAA"
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := newPool(t)
			p.start(t)
			ready, err := p.client(t, p.access).Ready(ctxT(t))
			if err != nil {
				t.Fatal(err)
			}
			before := register(t, p.td)
			raw, signature := build(t, p, ready)
			if status := p.postBind(t, raw, signature); status != http.StatusBadRequest {
				t.Fatalf("HTTP %d, want 400", status)
			}
			select {
			case err := <-p.agent.Fatal():
				if err == nil || !strings.Contains(err.Error(), "refused a bind while unbound") {
					t.Fatalf("the agent ends for another reason: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the agent carries on after refusing a bind")
			}
			// On its way out it takes no bind, the right one included.
			good := p.bindFor(t, ready, nil)
			if status := p.postBind(t, good.Raw, good.Signature); status != http.StatusGone {
				t.Fatalf("a bind after the refusal: HTTP %d, want 410", status)
			}
			if state := p.state(t); state.Phase != session.PhaseReady || len(state.Bind) != 0 {
				t.Fatalf("the guest left the unbound phase: %s", state.Phase)
			}
			if !bytes.Equal(before, register(t, p.td)) {
				t.Fatal("a refused bind was measured")
			}
			if steps := p.runner.recorded(); steps != "" {
				t.Fatalf("a refused bind reached the runner: %s", steps)
			}
		})
	}
}

// Once bound, the guest reads no other bind: a malformed one is refused like
// any other, and the guest carries on.
func TestBoundGuestIgnoresOtherBinds(t *testing.T) {
	p := newPool(t)
	p.start(t)
	ready, err := p.client(t, p.access).Ready(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	bind := p.bindFor(t, ready, nil)
	if status := p.postBind(t, bind.Raw, bind.Signature); status != http.StatusOK {
		t.Fatalf("bind: HTTP %d", status)
	}
	if status := p.postBind(t, []byte("not json"), "AAAA"); status != http.StatusConflict {
		t.Fatalf("garbage after the bind: HTTP %d, want 409", status)
	}
	select {
	case err := <-p.agent.Fatal():
		t.Fatalf("a bound guest ended over a bind it never read: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if _, err := p.boundClient(t, ready, bind).Attest(ctxT(t)); err != nil {
		t.Fatalf("Attest after the stray bind: %v", err)
	}
}

// Two tenants race for one guest. Exactly one bind is measured and that
// tenant's keys, and only they, drive the guest.
func TestConcurrentBindsHaveOneWinner(t *testing.T) {
	p := newPool(t)
	p.start(t)
	ready, err := p.client(t, p.access).Ready(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	const tenants = 8
	binds := make([]*session.SignedBind, tenants)
	for i := range binds {
		binds[i] = p.bindFor(t, ready, func(o *session.BindOptions) { o.Session = "sbx-" + string(rune('a'+i)) })
	}
	statuses := make([]int, tenants)
	var wg sync.WaitGroup
	for i := range binds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses[i] = p.postBind(t, binds[i].Raw, binds[i].Signature)
		}()
	}
	wg.Wait()
	winner := -1
	for i, status := range statuses {
		switch status {
		case http.StatusOK:
			if winner >= 0 {
				t.Fatalf("binds %d and %d were both accepted", winner, i)
			}
			winner = i
		case http.StatusConflict:
		default:
			t.Fatalf("bind %d: HTTP %d", i, status)
		}
	}
	if winner < 0 {
		t.Fatal("no bind was accepted")
	}
	if state := p.state(t); !bytes.Equal(state.Bind, binds[winner].Raw) {
		t.Fatalf("the guest does not show the winning bind: %s", state.Bind)
	}
	if p.runner.recorded() != "prepare "+sandboxImage+",start" {
		t.Fatalf("runner steps = %s", p.runner.recorded())
	}
}

// The first bind is the only one, so a guest that cannot admit its sandbox
// has no future: the bind fails and the agent stops.
func TestBindWhoseSandboxCannotBeAdmittedEndsTheGuest(t *testing.T) {
	p := newPool(t)
	p.runner.fail = errors.New("manifest digest mismatch")
	p.cfg.Logger = slog.New(slog.DiscardHandler)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln := freeAddr(t)
	done := make(chan error, 1)
	go func() { done <- sessionagent.Run(ctx, p.cfg, ln) }()
	p.url = "https://" + ln
	var ready *session.ReadyTD
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		var err error
		if ready, err = p.client(t, p.access).Ready(ctxT(t)); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the guest never served: %v", err)
		}
	}
	bind := p.bindFor(t, ready, nil)
	if status := p.postBind(t, bind.Raw, bind.Signature); status != http.StatusInternalServerError {
		t.Fatalf("HTTP %d, want 500", status)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "manifest digest mismatch") {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the agent kept running after a bind it could not complete")
	}
	if p.runner.recorded() != "prepare "+sandboxImage {
		t.Fatalf("runner steps = %s", p.runner.recorded())
	}
}

// testClock is a clock a test moves by hand.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fence asks the guest what its host asks when it claims the guest.
func (p *pool) fence(t *testing.T) (int, session.FenceResponse) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctxT(t), http.MethodPost, p.url+session.PathFence, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := insecureClient()
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out session.FenceResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode, out
}

// heldConn is a connection to the guest that someone opened and kept: one
// request has been answered on it and it is idle.
func (p *pool) heldConn(t *testing.T) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := tls.Dial("tcp", strings.TrimPrefix(p.url, "https://"), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // a probe: nothing about this peer is trusted
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	reader := bufio.NewReader(conn)
	if status := requestOn(t, conn, reader, http.MethodGet, session.PathState, nil); status != http.StatusOK {
		t.Fatalf("state on a held connection: %d", status)
	}
	return conn, reader
}

// requestOn sends one request on conn and returns its status, or 0 if the
// connection gave no answer.
func requestOn(t *testing.T, conn net.Conn, reader *bufio.Reader, method, path string, body []byte) int {
	t.Helper()
	req, err := http.NewRequest(method, "https://guest"+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := req.Write(conn); err != nil {
		return 0
	}
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return 0
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// A guest nobody bound goes to the next claim as it is. Whoever had it before
// may still hold a connection to it, with a bind on the way. The fence ends
// those connections and every bind sent on them, at one point in time, so the
// guest cannot become the earlier tenant's after it was claimed.
func TestFenceEndsWhatCameBeforeIt(t *testing.T) {
	p := newPool(t)
	p.start(t)
	ready, err := p.client(t, p.access).Ready(ctxT(t))
	if err != nil {
		t.Fatalf("Unbound: %v", err)
	}
	earlier := p.bindFor(t, ready, func(o *session.BindOptions) { o.Tenant = "earlier" })
	body, err := json.Marshal(session.BindRequest{Bind: earlier.Raw, Signature: earlier.Signature})
	if err != nil {
		t.Fatal(err)
	}
	held, reader := p.heldConn(t)

	status, fenced := p.fence(t)
	if status != http.StatusOK || fenced.Phase != session.PhaseReady || fenced.Closed < 1 {
		t.Fatalf("fence of an unbound guest: %d %+v, want unbound with the held connection closed", status, fenced)
	}
	// The earlier tenant's bind, on the connection it held: no answer.
	if status := requestOn(t, held, reader, http.MethodPost, session.PathBind, body); status != 0 {
		t.Fatalf("a bind on a connection from before the fence was answered %d", status)
	}
	// And one that was already past the connection when the fence came: the
	// guest does not look at it, and does not end over it.
	if _, _, err := p.agent.Bind(context.Background(), earlier.Raw, earlier.Signature); err == nil || !strings.Contains(err.Error(), "claimed") {
		t.Fatalf("a bind from before the fence: %v, want it refused as fenced", err)
	}
	select {
	case err := <-p.agent.Fatal():
		t.Fatalf("a fenced bind ended the guest: %v", err)
	default:
	}
	if state := p.state(t); state.Phase != session.PhaseReady || len(state.Bind) != 0 {
		t.Fatalf("state after the fence: %+v", state)
	}
	if steps := p.runner.recorded(); steps != "" {
		t.Fatalf("a fenced guest drove its runner: %s", steps)
	}

	// The next tenant, on a connection opened after the fence, binds it.
	next := p.bindFor(t, ready, nil)
	if status := p.postBind(t, next.Raw, next.Signature); status != http.StatusOK {
		t.Fatalf("a bind after the fence: %d", status)
	}
	if state := p.state(t); state.Phase != session.PhaseRunning || !bytes.Equal(state.Bind, next.Raw) {
		t.Fatalf("state after the bind: %+v", state)
	}
}

// A bind the guest has begun to read has put a caller's bytes inside it. The
// fence then promises nothing: it answers 409, closes no connection, and the
// bind goes on. The host takes that answer as a bound guest and destroys it.
func TestFenceIsNotRaisedOverABindInFlight(t *testing.T) {
	p := newPool(t)
	p.start(t)
	ready, err := p.client(t, p.access).Ready(ctxT(t))
	if err != nil {
		t.Fatalf("Unbound: %v", err)
	}
	earlier := p.bindFor(t, ready, func(o *session.BindOptions) { o.Tenant = "earlier" })
	body, err := json.Marshal(session.BindRequest{Bind: earlier.Raw, Signature: earlier.Signature})
	if err != nil {
		t.Fatal(err)
	}

	// The bind's headers, and its body held back. The agent's 100 Continue
	// says it has let the bind in and is waiting to read it.
	held, reader := p.heldConn(t)
	_ = held.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(held, "POST %s HTTP/1.1\r\nHost: guest\r\nContent-Type: application/json\r\nContent-Length: %d\r\nExpect: 100-continue\r\n\r\n",
		session.PathBind, len(body)); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "HTTP/1.1 100 ") {
		t.Fatalf("the agent answered a held-back bind with %q, %v, want 100 Continue", line, err)
	}
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}

	status, fenced := p.fence(t)
	if status != http.StatusConflict || fenced.Closed != 0 {
		t.Fatalf("fence with a bind in flight: %d %+v, want 409 and nothing closed", status, fenced)
	}
	if state := p.state(t); state.Phase != session.PhaseReady {
		t.Fatalf("state with the bind held back: %+v", state)
	}

	// The connection is still the earlier tenant's, and its bind completes.
	if _, err := held.Write(body); err != nil {
		t.Fatalf("the connection of a bind in flight was closed: %v", err)
	}
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("no answer to the bind: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the bind in flight was answered %d", resp.StatusCode)
	}
	if state := p.state(t); state.Phase != session.PhaseRunning || !bytes.Equal(state.Bind, earlier.Raw) {
		t.Fatalf("state after the bind: %+v", state)
	}
	// And the fence now says what the guest is.
	if status, fenced := p.fence(t); status != http.StatusOK || fenced.Phase != session.PhaseRunning {
		t.Fatalf("fence of the guest once bound: %d %+v", status, fenced)
	}
}

// refusalCode is the code of a refusal the guest sent a caller it has not
// authenticated, which carries nothing else.
func refusalCode(body []byte) disclosure.Code {
	var refusal map[string]json.RawMessage
	if json.Unmarshal(body, &refusal) != nil || len(refusal) != 1 {
		return ""
	}
	var code disclosure.Code
	_ = json.Unmarshal(refusal["error"], &code)
	return code
}

// A bind on a connection the fence ended is refused on its headers. The guest
// reads none of it, stays unbound and does not end over it.
func TestBindOnAnEndedConnectionIsRefusedUnread(t *testing.T) {
	p := newPool(t)
	p.start(t)
	ready, err := p.client(t, p.access).Ready(ctxT(t))
	if err != nil {
		t.Fatalf("Unbound: %v", err)
	}
	if status, fenced := p.fence(t); status != http.StatusOK || fenced.Phase != session.PhaseReady {
		t.Fatalf("fence: %d %+v", status, fenced)
	}
	earlier := p.bindFor(t, ready, func(o *session.BindOptions) { o.Tenant = "earlier" })
	body, err := json.Marshal(session.BindRequest{Bind: earlier.Raw, Signature: earlier.Signature})
	if err != nil {
		t.Fatal(err)
	}
	unread := &countingReader{Reader: bytes.NewReader(body)}
	req := httptest.NewRequest(http.MethodPost, session.PathBind, unread)
	req = req.WithContext(sessionagent.EndedConnContext(req.Context(), p.agent))
	rec := httptest.NewRecorder()
	p.agent.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict || refusalCode(rec.Body.Bytes()) != disclosure.Fenced {
		t.Fatalf("a bind on an ended connection: %d %s, want 409 and the fence's code", rec.Code, rec.Body)
	}
	if unread.n != 0 {
		t.Fatalf("the agent read %d bytes of a bind it refused", unread.n)
	}
	if got := rec.Header().Get("Connection"); got != "close" {
		t.Errorf("Connection = %q, want close: a server that keeps the connection reads the body to reuse it", got)
	}
	select {
	case err := <-p.agent.Fatal():
		t.Fatalf("a refused bind ended the guest: %v", err)
	default:
	}
	if state := p.state(t); state.Phase != session.PhaseReady || len(state.Bind) != 0 {
		t.Fatalf("state after the refusal: %+v", state)
	}
	// The refusal left nothing in flight: the guest can be fenced again and
	// bound on a new connection.
	if status, fenced := p.fence(t); status != http.StatusOK || fenced.Phase != session.PhaseReady {
		t.Fatalf("fence after the refusal: %d %+v", status, fenced)
	}
	next := p.bindFor(t, ready, nil)
	if status := p.postBind(t, next.Raw, next.Signature); status != http.StatusOK {
		t.Fatalf("a bind after the fence: %d", status)
	}
}

// countingReader counts the bytes read through it.
type countingReader struct {
	io.Reader
	n int
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.n += n
	return n, err
}

// A second fence ends the connections that came after the first.
func TestFenceCanBeRaisedAgain(t *testing.T) {
	p := newPool(t)
	p.start(t)
	if status, fenced := p.fence(t); status != http.StatusOK || fenced.Phase != session.PhaseReady {
		t.Fatalf("first fence: %d %+v", status, fenced)
	}
	held, reader := p.heldConn(t)
	if status, fenced := p.fence(t); status != http.StatusOK || fenced.Closed < 1 {
		t.Fatalf("second fence: %d %+v, want the connection opened since closed", status, fenced)
	}
	if status := requestOn(t, held, reader, http.MethodGet, session.PathState, nil); status != 0 {
		t.Fatalf("a connection from before the second fence still answered %d", status)
	}
}

// A bound guest is somebody's. The fence says so and touches nothing: the
// host then destroys the guest, and until it does the tenant's connections
// are the tenant's.
func TestFenceLeavesABoundGuestAlone(t *testing.T) {
	p := newPool(t)
	p.start(t)
	client := p.client(t, p.access)
	ready, err := client.Ready(ctxT(t))
	if err != nil {
		t.Fatalf("Unbound: %v", err)
	}
	if _, err := client.Bind(ctxT(t), p.bindFor(t, ready, nil)); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	held, reader := p.heldConn(t)
	status, fenced := p.fence(t)
	if status != http.StatusOK || fenced.Phase != session.PhaseRunning || fenced.Closed != 0 {
		t.Fatalf("fence of a bound guest: %d %+v, want running and nothing closed", status, fenced)
	}
	if status := requestOn(t, held, reader, http.MethodGet, session.PathState, nil); status != http.StatusOK {
		t.Fatalf("a bound guest's connection after a fence: %d", status)
	}
}

// newTimedPool is a guest whose launch document gives it an hour to be
// bound, on a clock the test holds.
func newTimedPool(t *testing.T) (*pool, *testClock) {
	t.Helper()
	p := newPoolWith(t, func(o *session.BundleOptions) { o.AgeLimit = time.Hour })
	clock := &testClock{now: time.Now()}
	p.cfg.ClockSource, p.cfg.Now = func() string { return "tsc" }, clock.Now
	return p, clock
}

func (p *pool) fatal(t *testing.T) error {
	t.Helper()
	select {
	case err := <-p.agent.Fatal():
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("the agent carries on")
		return nil
	}
}

// A guest is bound within the time its launch document gives it. Past
// that it reads no bind, the right one included, and ends.
func TestGuestTakesNoBindPastItsDeadline(t *testing.T) {
	t.Run("in time", func(t *testing.T) {
		p, clock := newTimedPool(t)
		p.start(t)
		ready, err := p.client(t, p.access).Ready(ctxT(t))
		if err != nil {
			t.Fatal(err)
		}
		clock.advance(time.Hour - time.Second)
		bind := p.bindFor(t, ready, nil)
		if status := p.postBind(t, bind.Raw, bind.Signature); status != http.StatusOK {
			t.Fatalf("a bind inside the deadline: HTTP %d", status)
		}
		// Bound, the deadline no longer applies to it.
		clock.advance(48 * time.Hour)
		p.agent.ExpireUnbound()
		select {
		case err := <-p.agent.Fatal():
			t.Fatalf("a bound guest ended at its bind deadline: %v", err)
		default:
		}
		if status := p.postBind(t, bind.Raw, bind.Signature); status != http.StatusOK {
			t.Fatalf("the same bind again, after the deadline: HTTP %d", status)
		}
	})

	t.Run("too late", func(t *testing.T) {
		p, clock := newTimedPool(t)
		p.start(t)
		ready, err := p.client(t, p.access).Ready(ctxT(t))
		if err != nil {
			t.Fatal(err)
		}
		before := register(t, p.td)
		clock.advance(time.Hour + time.Second)
		bind := p.bindFor(t, ready, nil)
		if status := p.postBind(t, bind.Raw, bind.Signature); status != http.StatusBadRequest {
			t.Fatalf("a bind past the deadline: HTTP %d, want 400", status)
		}
		if err := p.fatal(t); !strings.Contains(err.Error(), "longer than its launch document allows") {
			t.Fatalf("the agent ends for another reason: %v", err)
		}
		if status := p.postBind(t, bind.Raw, bind.Signature); status != http.StatusGone {
			t.Fatalf("a second bind past the deadline: HTTP %d, want 410", status)
		}
		if !bytes.Equal(before, register(t, p.td)) {
			t.Fatal("a bind past the deadline was measured")
		}
		if steps := p.runner.recorded(); steps != "" {
			t.Fatalf("a bind past the deadline reached the runner: %s", steps)
		}
	})

	t.Run("nobody came", func(t *testing.T) {
		p, clock := newTimedPool(t)
		p.start(t)
		if left, bounded := p.agent.UnboundFor(); !bounded || left != time.Hour {
			t.Fatalf("UnboundFor = %s, %t, want an hour", left, bounded)
		}
		// Before the deadline the guest stays.
		clock.advance(59 * time.Minute)
		p.agent.ExpireUnbound()
		select {
		case err := <-p.agent.Fatal():
			t.Fatalf("the guest ended before its deadline: %v", err)
		default:
		}
		clock.advance(2 * time.Minute)
		p.agent.ExpireUnbound()
		if err := p.fatal(t); !strings.Contains(err.Error(), "longer than its launch document allows") {
			t.Fatalf("the agent ends for another reason: %v", err)
		}
		if state := p.state(t); state.Phase != session.PhaseReady {
			t.Fatalf("an expired guest is in phase %s", state.Phase)
		}
	})
}

// A deadline needs a clock the host cannot slow. A guest on any other
// clocksource does not stage a document that sets one, and a document that
// sets none stages on any.
func TestBindDeadlineNeedsTheGuestsOwnClock(t *testing.T) {
	for _, source := range []string{"kvm-clock", "hpet", ""} {
		p, _ := newTimedPool(t)
		p.cfg.ClockSource = func() string { return source }
		if _, err := sessionagent.Stage(context.Background(), p.cfg); err == nil || !strings.Contains(err.Error(), "not tsc") {
			t.Errorf("staged a bind deadline on clocksource %q: %v", source, err)
		}
	}
	unread, _ := newTimedPool(t)
	unread.cfg.ClockSource = nil
	if _, err := sessionagent.Stage(context.Background(), unread.cfg); err == nil || !strings.Contains(err.Error(), "not tsc") {
		t.Errorf("staged a bind deadline with no clocksource to read: %v", err)
	}
	p := newPool(t)
	p.cfg.ClockSource = func() string { return "kvm-clock" }
	agent, err := sessionagent.Stage(context.Background(), p.cfg)
	if err != nil {
		t.Fatalf("a pool document with no deadline: %v", err)
	}
	if _, bounded := agent.UnboundFor(); bounded {
		t.Error("a document with no deadline reports one")
	}
}

// The kernel can leave the tsc clocksource while the guest waits, for one the
// host feeds. The time the guest counted since is then the host's to choose,
// so a bind that arrives finds no deadline left to honor and is refused, in
// time or not, and the guest ends.
func TestBindIsRefusedOnceTheKernelLeftItsOwnClock(t *testing.T) {
	p, clock := newTimedPool(t)
	var source atomic.Value
	source.Store("tsc")
	p.cfg.ClockSource = func() string { return source.Load().(string) }
	p.start(t)
	ready, err := p.client(t, p.access).Ready(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	before := register(t, p.td)
	clock.advance(time.Minute)
	source.Store("hpet")
	bind := p.bindFor(t, ready, nil)
	if status := p.postBind(t, bind.Raw, bind.Signature); status != http.StatusBadRequest {
		t.Fatalf("a bind after the kernel left tsc: HTTP %d, want 400", status)
	}
	if err := p.fatal(t); !strings.Contains(err.Error(), "left the tsc clocksource") {
		t.Fatalf("the agent ends for another reason: %v", err)
	}
	if !bytes.Equal(before, register(t, p.td)) {
		t.Fatal("the refused bind was measured")
	}
	if steps := p.runner.recorded(); steps != "" {
		t.Fatalf("the refused bind reached the runner: %s", steps)
	}

	// A document that sets no deadline counts nothing, and binds on any clock.
	open := newPool(t)
	open.cfg.ClockSource = func() string { return "hpet" }
	open.start(t)
	ready, err = open.client(t, open.access).Ready(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	bind = open.bindFor(t, ready, nil)
	if status := open.postBind(t, bind.Raw, bind.Signature); status != http.StatusOK {
		t.Fatalf("a bind with no deadline to count, on another clocksource: HTTP %d", status)
	}
}

// What a guest says of itself it says to anyone: how far along it is, its key
// and the documents it measured. A launch document names nobody, and a bind
// reached the guest through its host. Holding a key adds nothing.
func TestStateIsPublic(t *testing.T) {
	p := newPool(t)
	p.start(t)
	launchDigest := session.DocumentDigest(p.bundle.Launch)

	unbound := p.state(t)
	if unbound.Phase != session.PhaseReady || len(unbound.InstanceKey) == 0 || len(unbound.Bind) != 0 || unbound.BindSignature != "" {
		t.Fatalf("an unbound guest's state: %+v", unbound)
	}
	if !bytes.Equal(unbound.Launch, p.bundle.Launch) || unbound.Signature == "" || len(unbound.Events) != 1 || unbound.Events[0] != launchDigest {
		t.Fatalf("an unbound guest must show its launch document and its one event: %+v", unbound)
	}

	client := p.client(t, p.access)
	ready, err := client.Ready(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	bind := p.bindFor(t, ready, nil)
	if _, err := client.Bind(ctxT(t), bind); err != nil {
		t.Fatal(err)
	}

	outsider, _ := newSigner(t)
	for name, signer := range map[string]*operatorauth.Signer{"no key": nil, "the pool's launch key": p.launchSigner(t), "another key": outsider, "the owner's access key": p.access} {
		state := stateAs(t, p.url, signer)
		if state.Phase != session.PhaseRunning || !bytes.Equal(state.InstanceKey, unbound.InstanceKey) || state.Prestaged {
			t.Errorf("%s: a bound guest's state: %+v", name, state)
		}
		if !bytes.Equal(state.Bind, bind.Raw) || state.BindSignature != bind.Signature || len(state.Events) != 3 ||
			state.Events[1] != session.DocumentDigest(bind.Raw) || !bytes.Equal(state.Launch, p.bundle.Launch) {
			t.Errorf("%s was not shown the guest's documents and events: %+v", name, state)
		}
	}
}

// The check of an unbound guest is a connection, the guest's state and a
// judgment of the certificate's evidence against that state. The bind is one
// request on the same connection.
func TestUnboundCheckReportsItsSteps(t *testing.T) {
	p := newPool(t)
	p.start(t)
	var mu sync.Mutex
	var steps []string
	client, err := session.NewClient(p.url, p.policy, sessiontest.Engine{}, p.access, session.Timed(func(step string, _ time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		steps = append(steps, step)
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ready, err := client.Ready(ctxT(t))
	if err != nil {
		t.Fatalf("Unbound: %v", err)
	}
	if _, err := client.Bind(ctxT(t), p.bindFor(t, ready, nil)); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := "dial, serving_verdict, handshake, request /v1/state, judgment, request /v1/bind"
	if got := strings.Join(steps, ", "); got != want {
		t.Fatalf("steps: %s\n want: %s", got, want)
	}
}

// A pool document may list images to unpack ahead. The agent hands the list
// to its runner when it starts waiting for a bind, before any tenant exists,
// and a document with no list asks nothing of the runner.
func TestGuestUnpacksItsDocumentsImagesAhead(t *testing.T) {
	other := "registry.example/other@sha256:" + strings.Repeat("3", 64)
	p := newPoolWith(t, func(o *session.BundleOptions) { o.Prestage = []string{sandboxImage, other} })
	p.start(t)
	if got := p.runner.recorded(); got != "prestage "+sandboxImage+" "+other {
		t.Fatalf("the runner was asked: %q", got)
	}
	// The list is in the document the guest measured, for anyone to read.
	if state := p.state(t); !bytes.Contains(state.Launch, []byte(other)) {
		t.Fatalf("the launch document does not show the list:\n%s", state.Launch)
	}
	ready, err := p.client(t, p.access).Ready(ctxT(t))
	if err != nil || len(ready.Document.Prestage) != 2 {
		t.Fatalf("the verified pool document lists %v, %v", ready, err)
	}
	// The guest says when it is done with them, to anyone: its host offers
	// it to a tenant only then.
	if p.state(t).Prestaged {
		t.Fatal("the guest says it is done with images it is still unpacking")
	}
	close(p.runner.unpacking)
	if !p.state(t).Prestaged {
		t.Fatal("the guest does not say it is done with its images")
	}
	// Bound, it is somebody's, and says nothing of the kind any more.
	if _, err := p.client(t, p.access).Bind(ctxT(t), p.bindFor(t, ready, nil)); err != nil {
		t.Fatal(err)
	}
	if p.state(t).Prestaged || stateAs(t, p.url, p.access).Prestaged {
		t.Fatal("a bound guest still reports on the images it unpacked ahead")
	}

	plain := newPool(t)
	plain.start(t)
	if got := plain.runner.recorded(); got != "" {
		t.Fatalf("a pool document with no list drove its runner: %q", got)
	}
	// Nothing to unpack is done at once.
	if !plain.state(t).Prestaged {
		t.Fatal("a guest with no list does not say it is ready")
	}
}

// Until the guest has begun on its list it is not done with it: its API is
// up before it admits anything.
func TestGuestIsNotPrestagedBeforeItBegan(t *testing.T) {
	p := newPoolWith(t, func(o *session.BundleOptions) { o.Prestage = []string{sandboxImage} })
	agent, err := sessionagent.Stage(context.Background(), p.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.WarmUp(context.Background()); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := agent.Server()
	go func() { _ = agent.Serve(srv, ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	if stateAs(t, "https://"+ln.Addr().String(), nil).Prestaged {
		t.Fatal("a guest that has not begun on its list says it is done with it")
	}
}

// guestMemory is a guest's memory as its kernel shows it and accepts it.
type guestMemory struct {
	mu           sync.Mutex
	unacceptedMB int
	aheadMB      int
	writes       []int
	// hold, when set, keeps the kernel from finishing a write until closed.
	hold chan struct{}
}

func (g *guestMemory) read() ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return []byte(fmt.Sprintf("MemFree: %d kB\nUnaccepted: %d kB\n", (g.aheadMB+g.unacceptedMB)<<10, g.unacceptedMB<<10)), nil
}

func (g *guestMemory) accept(megabytes int) error {
	g.mu.Lock()
	g.writes = append(g.writes, megabytes)
	hold := g.hold
	g.mu.Unlock()
	if hold != nil {
		<-hold
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	taken := min(megabytes, g.unacceptedMB)
	g.unacceptedMB, g.aheadMB = g.unacceptedMB-taken, g.aheadMB+taken
	return nil
}

func (g *guestMemory) asked() []int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.writes)
}

func (g *guestMemory) left() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.unacceptedMB
}

// until polls a condition another goroutine brings about.
func until(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("never happened: %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// A pool guest keeps a reserve of accepted memory for its tenant's start. It
// accepts it after its images are unpacked, which takes memory of its own,
// and tells its host that it is ready only once it holds it. What is left it
// accepts for the tenant, once the tenant's sandbox runs.
func TestGuestIsReadyOnceItHoldsItsMemoryReserve(t *testing.T) {
	p := newPoolWith(t, func(o *session.BundleOptions) { o.Prestage = []string{sandboxImage} })
	guest := &guestMemory{unacceptedMB: 200, hold: make(chan struct{})}
	p.cfg.Memory = sessionagent.NewTestMemory(128, true, guest.read, guest.accept)
	p.start(t)
	time.Sleep(20 * time.Millisecond)
	if asked := guest.asked(); len(asked) != 0 || p.state(t).Prestaged {
		t.Fatalf("while its images are being unpacked the guest accepted %v, ready %v", asked, p.state(t).Prestaged)
	}
	close(p.runner.unpacking)
	until(t, "the reserve is asked for", func() bool { return len(guest.asked()) == 1 })
	if p.state(t).Prestaged {
		t.Fatal("the guest says it is ready while its reserve is being accepted")
	}
	close(guest.hold)
	until(t, "the guest is ready", func() bool { return p.state(t).Prestaged })
	// Unbound, it holds the reserve and accepts no more.
	time.Sleep(20 * time.Millisecond)
	if asked := guest.asked(); !slices.Equal(asked, []int{128}) {
		t.Fatalf("an unbound guest accepted %v", asked)
	}

	ready, err := p.client(t, p.access).Ready(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.client(t, p.access).Bind(ctxT(t), p.bindFor(t, ready, nil)); err != nil {
		t.Fatal(err)
	}
	until(t, "the rest is accepted", func() bool { return guest.left() == 0 })
	if asked := guest.asked(); !slices.Equal(asked, []int{128, 32, 32, 8}) {
		t.Fatalf("the guest accepted %v", asked)
	}
}

// With nothing to unpack the reserve is all a pool guest does ahead, and it
// is not ready before it holds it. A guest told to keep none is ready at once.
func TestGuestWithNoImagesStillWaitsForItsReserve(t *testing.T) {
	p := newPool(t)
	guest := &guestMemory{unacceptedMB: 200, hold: make(chan struct{})}
	p.cfg.Memory = sessionagent.NewTestMemory(64, false, guest.read, guest.accept)
	p.start(t)
	until(t, "the reserve is asked for", func() bool { return len(guest.asked()) == 1 })
	if p.state(t).Prestaged {
		t.Fatal("the guest says it is ready while its reserve is being accepted")
	}
	close(guest.hold)
	until(t, "the guest is ready", func() bool { return p.state(t).Prestaged })

	// Bound with the rest left alone: the sandbox accepts what it grows into.
	ready, err := p.client(t, p.access).Ready(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.client(t, p.access).Bind(ctxT(t), p.bindFor(t, ready, nil)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if asked := guest.asked(); !slices.Equal(asked, []int{64}) {
		t.Fatalf("the guest accepted %v", asked)
	}
}
