package session_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// refusals counts what an agent logs as a refused request.
type refusals struct {
	slog.Handler
	n atomic.Int32
}

func (r *refusals) Handle(ctx context.Context, record slog.Record) error {
	if record.Message == "request refused" {
		r.n.Add(1)
	}
	return r.Handler.Handle(ctx, record)
}

// served is a guest whose agent serves on loopback: a simulated TD, the
// agent inside it, the owner whose authority binds it, and what a client
// needs to reach and verify it.
type served struct {
	td     *sessiontest.TD
	agent  *sessionagent.Agent
	bundle *session.Bundle
	addr   string
	// policy is what a client of the guest holds: for a bound guest, its
	// launch document and its bind pinned.
	policy    session.Policy
	authority *ecdsa.PrivateKey
	// signer holds the access key the guest's bind grants, and accessPub is
	// that key's public half.
	signer    *operatorauth.Signer
	accessPub string
	bind      *session.SignedBind
	srv       *http.Server
	home      string
	refused   *refusals
}

// serveReady boots a guest of a pool of its own and serves its agent. Nobody
// has bound it.
func serveReady(t *testing.T, td *sessiontest.TD) *served {
	t.Helper()
	dir, bundle := newBundle(t, td, nil)
	td.SeedLaunchKey(bundle.LaunchKey)
	s := &served{td: td, bundle: bundle, home: t.TempDir(), refused: &refusals{Handler: slog.DiscardHandler}, authority: newKey(t)}
	credDir := filepath.Join(t.TempDir(), "credentials")
	runner, err := sessionagent.NewProcessRunner(sessionagent.RunnerConfig{UID: -1, GID: -1, Home: s.home, CredentialDir: credDir})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := sessionagent.Stage(context.Background(), sessionagent.Config{
		Platform: "tdx", PubkeyPath: filepath.Join(dir, session.OpkeyDir, session.PubkeyFile),
		LaunchDir: filepath.Join(dir, session.OpkeyDir), CredentialDir: credDir,
		TEE: sessiontest.TEE{TD: td}, Runner: runner, Logger: slog.New(s.refused), Bare: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.WarmUp(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := agent.Admit(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.agent = agent
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.srv = agent.Server()
	go func() { _ = agent.Serve(s.srv, ln) }()
	t.Cleanup(func() { _ = s.srv.Close() })
	s.addr = ln.Addr().String()

	access := newKey(t)
	accessPEM, err := certutil.MarshalECKeyPEM(access)
	if err != nil {
		t.Fatal(err)
	}
	if s.signer, err = operatorauth.NewSignerFromKeyPEM(accessPEM); err != nil {
		t.Fatal(err)
	}
	s.accessPub = keyPEM(t, access)
	s.policy = policyFor(t, td, bundle)
	s.policy.Launch, s.policy.Authority, s.policy.AllowReady = nil, []byte(keyPEM(t, s.authority)), true
	return s
}

// serve is serveReady for a guest its owner has bound: to a session with no
// sandbox image, which the served key may drive.
func serve(t *testing.T, td *sessiontest.TD, mutate func(*session.BindOptions)) *served {
	t.Helper()
	s := serveReady(t, td)
	binder, err := session.NewClient("https://"+s.addr, s.policy, sessiontest.Engine{}, s.signer)
	if err != nil {
		t.Fatal(err)
	}
	defer binder.Close()
	ready, err := binder.Ready(within(t))
	if err != nil {
		t.Fatalf("Ready: %v", err)
	}
	opts := session.BindOptions{
		Authority: s.authority, InstanceKey: ready.InstanceKey, Tenant: "acme", Session: "sbx-1", NotAfter: time.Now().Add(time.Hour),
		Policy: session.BindPolicy{Access: session.Access{Exec: []string{s.accessPub}, Credentials: []string{s.accessPub}}},
	}
	if mutate != nil {
		mutate(&opts)
	}
	if s.bind, err = session.NewBind(opts); err != nil {
		t.Fatal(err)
	}
	if _, err := binder.Bind(within(t), s.bind); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	s.policy.Launch, s.policy.Bind, s.policy.AllowReady = ready.Launch, s.bind.Raw, false
	return s
}

// twin serves a second guest of the same image, bound by an authority of its
// own to a session that welcomes the first guest's access key.
func (s *served) twin(t *testing.T) *served {
	t.Helper()
	td := sessiontest.NewTD()
	td.MRTD, td.RTMR[0], td.RTMR[1], td.RTMR[2] = s.td.MRTD, s.td.RTMR[0], s.td.RTMR[1], s.td.RTMR[2]
	return serve(t, td, func(o *session.BindOptions) {
		o.Policy.Access = session.Access{Exec: []string{s.accessPub}, Credentials: []string{s.accessPub}}
	})
}

// clock is a clock a test moves.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// judging is the test engine, counting what it is asked to judge and
// refusing all of it on demand.
type judging struct {
	sessiontest.Engine
	calls  atomic.Int32
	refuse atomic.Bool
}

func (e *judging) VerifyEvidence(ctx context.Context, env teetypes.AttestationEvidence, reportData []byte) (*teetypes.VerificationResult, error) {
	e.calls.Add(1)
	if e.refuse.Load() {
		return nil, &session.VerificationError{Err: errors.New("the engine refuses everything")}
	}
	return e.Engine.VerifyEvidence(ctx, env, reportData)
}

func clientFor(t *testing.T, url string, s *served, engine session.Engine) (*session.Client, *clock) {
	t.Helper()
	client, err := session.NewClient(url, s.policy, engine, s.signer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	now := &clock{now: time.Now()}
	client.SetNow(now.Now)
	return client, now
}

func within(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func run(t *testing.T, client *session.Client) {
	t.Helper()
	if resp, err := client.Exec(within(t), session.ExecRequest{Argv: []string{"true"}}); err != nil || resp.ExitCode != 0 {
		t.Fatalf("exec = %+v, %v", resp, err)
	}
}

func isVerdict(err error) bool {
	var verdict *session.VerificationError
	return errors.As(err, &verdict)
}

// A client opens a TLS session for every stream, and after every pause. The
// guest presents the same certificate each time, and the verdict on its
// evidence is good for a while. The handshake still proves, each time, that
// the peer holds the certificate's key.
func TestServingCertificateIsJudgedOncePerPeriod(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	engine := &judging{}
	client, now := clientFor(t, "https://"+s.addr, s, engine)

	if _, err := client.Attest(within(t)); err != nil {
		t.Fatal(err)
	}
	// The certificate at the handshake, and the fresh evidence.
	if n := engine.calls.Load(); n != 2 {
		t.Fatalf("the first attestation asked the engine %d times, want 2", n)
	}
	// A new connection presents the certificate again.
	client.Close()
	run(t, client)
	if n := engine.calls.Load(); n != 2 {
		t.Fatalf("a certificate that had just passed was judged again: %d calls", n)
	}
	now.advance(session.ServingVerdictTTL)
	client.Close()
	run(t, client)
	if n := engine.calls.Load(); n != 3 {
		t.Fatalf("after %s the certificate must be judged again, once: %d calls", session.ServingVerdictTTL, n)
	}
}

// Only a verdict that passed is remembered.
func TestARefusedServingCertificateIsJudgedAgain(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	engine := &judging{}
	engine.refuse.Store(true)
	client, _ := clientFor(t, "https://"+s.addr, s, engine)
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := client.Attest(within(t)); !isVerdict(err) {
			t.Fatalf("attempt %d: a refused certificate got as far as %v", attempt, err)
		}
		if n := int(engine.calls.Load()); n != attempt {
			t.Fatalf("attempt %d: the engine was asked %d times", attempt, n)
		}
	}
	engine.refuse.Store(false)
	if _, err := client.Attest(within(t)); err != nil {
		t.Fatalf("once the engine accepts: %v", err)
	}
}

// Before the pin the client talks on one connection, which it gives up when
// it has gone unused for as long as an agent keeps one.
func TestFirstConnectionIsOneAndIsNotKeptIdle(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	way := sessiontest.NewHop(t, s.addr)
	client, now := clientFor(t, way.URL, s, sessiontest.Engine{})
	for i := 0; i < 3; i++ {
		if _, err := client.FetchEvidence(within(t)); err != nil {
			t.Fatal(err)
		}
	}
	if n := way.Accepted(); n != 1 {
		t.Fatalf("three exchanges before the pin opened %d connections, want 1", n)
	}
	now.advance(session.ConnIdle)
	if _, err := client.FetchEvidence(within(t)); err != nil {
		t.Fatalf("an exchange after a pause: %v", err)
	}
	if n := way.Accepted(); n != 2 {
		t.Fatalf("after a pause of %s the client opened %d connections in all, want 2", session.ConnIdle, n)
	}
}

// An agent that ends the connection with its answer is taken at its word.
func TestFirstConnectionIsGivenUpWhenTheAgentClosesIt(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	s.srv.SetKeepAlivesEnabled(false)
	way := sessiontest.NewHop(t, s.addr)
	client, _ := clientFor(t, way.URL, s, sessiontest.Engine{})
	for i := 1; i <= 2; i++ {
		if _, err := client.FetchEvidence(within(t)); err != nil {
			t.Fatalf("exchange %d: %v", i, err)
		}
		if n := way.Accepted(); n != i {
			t.Fatalf("after %d exchanges the client had opened %d connections", i, n)
		}
	}
}

// The connection a guest was attested on carries the next request, unless it
// waited for one too long.
func TestAttestedConnectionCarriesTheNextRequest(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)

	way := sessiontest.NewHop(t, s.addr)
	client, _ := clientFor(t, way.URL, s, sessiontest.Engine{})
	run(t, client)
	if n := way.Accepted(); n != 1 {
		t.Fatalf("an attestation and a command opened %d connections, want 1", n)
	}

	way = sessiontest.NewHop(t, s.addr)
	client, now := clientFor(t, way.URL, s, sessiontest.Engine{})
	if _, err := client.Attest(within(t)); err != nil {
		t.Fatal(err)
	}
	now.advance(session.ConnIdle)
	run(t, client)
	if n := way.Accepted(); n != 2 {
		t.Fatalf("a command %s after the attestation: %d connections in all, want 2", session.ConnIdle, n)
	}
}

// dialUnverified opens a TLS session to addr the way no client of a guest
// does: with nothing about the peer checked.
func dialUnverified(t *testing.T, addr string) *tls.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // the test's stand-in for a connection that ends elsewhere
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// Once a client has attested its guest, a request travels only on a
// connection that ends at that guest's key. Every connection the client
// opens passes that in its handshake. One that came to the client's hands
// any other way gets nothing: not the command, and not its token.
func TestRequestStaysOffAConnectionThatEndsElsewhere(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	other := s.twin(t)
	client, _ := clientFor(t, "https://"+s.addr, s, sessiontest.Engine{})
	if _, err := client.Attest(within(t)); err != nil {
		t.Fatal(err)
	}
	client.Close()

	client.OfferSpare(dialUnverified(t, other.addr))
	marker := session.ExecRequest{Argv: []string{"sh", "-c", `echo here > "$HOME/marker"`}}
	if _, err := client.Exec(within(t), marker); !isVerdict(err) {
		t.Fatalf("a command offered a connection to another guest: %v", err)
	}
	if n := other.refused.n.Load(); n != 0 {
		t.Fatalf("the other guest was sent %d requests", n)
	}
	if _, err := os.Stat(filepath.Join(other.home, "marker")); err == nil {
		t.Fatal("the command ran in a guest the client never attested")
	}
	// The stray connection is gone, and the next request finds the guest.
	if resp, err := client.Exec(within(t), marker); err != nil || resp.ExitCode != 0 {
		t.Fatalf("the next command: %+v, %v", resp, err)
	}
	if _, err := os.Stat(filepath.Join(s.home, "marker")); err != nil {
		t.Fatalf("the command did not run in the attested guest: %v", err)
	}
}

// The first connection goes on to carry requests only if it ends at the key
// the client pinned.
func TestFirstConnectionGoesOnOnlyIfItEndsAtThePinnedKey(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	other := s.twin(t)
	client, _ := clientFor(t, "https://"+s.addr, s, sessiontest.Engine{})
	if _, err := client.Attest(within(t)); err != nil {
		t.Fatal(err)
	}
	client.Close()

	stray := dialUnverified(t, other.addr)
	client.RetireAsFirst(stray)
	_ = stray.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := stray.Write([]byte("x")); err == nil || strings.Contains(err.Error(), "timeout") {
		t.Fatalf("a first connection that ends elsewhere was left open: %v", err)
	}
	run(t, client)
	if n := other.refused.n.Load(); n != 0 {
		t.Fatalf("the other guest was sent %d requests", n)
	}
}

// A client that is asked to says where its time went: each step as it ends,
// in the order they end. The verdict on the serving certificate is reached
// inside the handshake, and the connection the guest was attested on carries
// the command, so no second dial is reported.
func TestClientReportsItsSteps(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	var mu sync.Mutex
	var steps []string
	client, err := session.NewClient("https://"+s.addr, s.policy, sessiontest.Engine{}, s.signer,
		session.Timed(func(step string, took time.Duration) {
			mu.Lock()
			defer mu.Unlock()
			if took <= 0 || took > time.Minute {
				t.Errorf("%s is reported to have taken %s", step, took)
			}
			steps = append(steps, step)
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	run(t, client)
	reported := func() string {
		mu.Lock()
		defer mu.Unlock()
		return strings.Join(steps, ", ")
	}
	want := "dial, serving_verdict, handshake, request /v1/attest, judgment, request /v1/exec"
	if got := reported(); got != want {
		t.Fatalf("steps: %s\n want: %s", got, want)
	}
	// A second command is one more request on the same connection.
	run(t, client)
	if got := reported(); got != want+", request /v1/exec" {
		t.Fatalf("steps after a second command: %s", got)
	}
}

// A stream takes the client's waiting connection only if the client itself
// verified it and watches its end. One that came to its hands any other way
// carries no stream: the request for it goes to the client's own guest.
func TestStreamTakesNoConnectionThatCameAnotherWay(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	other := s.twin(t)
	client, _ := clientFor(t, "https://"+s.addr, s, sessiontest.Engine{})
	if _, err := client.Attest(within(t)); err != nil {
		t.Fatal(err)
	}
	client.Close()

	client.OfferSpare(dialUnverified(t, other.addr))
	// This guest's bind opens no port, and it says so itself.
	_, err := client.Dial(within(t), 8080)
	var status *session.StatusError
	if !errors.As(err, &status) {
		t.Fatalf("a stream with a stray connection waiting: %v", err)
	}
	if n := other.refused.n.Load(); n != 0 {
		t.Fatalf("the other guest was sent %d requests", n)
	}
}
