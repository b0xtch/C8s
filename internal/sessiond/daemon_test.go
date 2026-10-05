package sessiond_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	sessionv1alpha1 "github.com/confidential-dot-ai/c8s/api/session/v1alpha1"
	"github.com/confidential-dot-ai/c8s/internal/sessiond"
	"github.com/confidential-dot-ai/c8s/internal/sessiond/sessiondtest"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/daemon"
	"github.com/confidential-dot-ai/c8s/pkg/session/sessionsim"
)

// host is a host with a daemon over simulated guests, and the test that
// drives it.
type host struct {
	*sessiondtest.Host
	t *testing.T
}

func newHost(t *testing.T, depth int, mutate func(*sessiond.Config)) *host {
	t.Helper()
	return &host{Host: sessiondtest.NewHost(t, depth, mutate), t: t}
}

func requestID(t *testing.T) string {
	t.Helper()
	id, err := daemon.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

// owner is a tenant's authority and the access key its binds grant.
type owner struct {
	authority    *ecdsa.PrivateKey
	authorityPub []byte
	accessPEM    []byte
	accessPub    string
}

func newOwner(t *testing.T) *owner {
	t.Helper()
	key := func() (*ecdsa.PrivateKey, []byte, []byte) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		private, err := certutil.MarshalECKeyPEM(k)
		if err != nil {
			t.Fatal(err)
		}
		public, err := session.PublicKeyPEM(&k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return k, private, public
	}
	o := &owner{}
	o.authority, _, o.authorityPub = key()
	var accessPub []byte
	_, o.accessPEM, accessPub = key()
	o.accessPub = string(accessPub)
	return o
}

// started is a session the owner started through the daemon.
type started struct {
	td    string
	ready *session.ReadyTD
	bind  *session.SignedBind
	// answer is the guest's evidence over the bind's nonce, as the daemon
	// relayed it: with the bind's answer, or a moment after it.
	answer *session.Relayed
	// receipt is the guest's receipt for the bind, verified.
	receipt *session.BindReceipt
	policy  session.Policy
	verdict *session.Verdict
}

// begin claims a TD for the session, verifies it as the pinned image, has
// the owner's authority bind it, verifies the guest's receipt, and then the
// quote that follows it: what a binder does.
func (h *host) begin(c *daemon.Client, o *owner, name string) (*started, error) {
	h.t.Helper()
	claimed, err := c.Claim(ctx(h.t), requestID(h.t), sessiondtest.Pool, name, 10*time.Second)
	if err != nil {
		return nil, err
	}
	return h.bind(c, o, name, claimed)
}

func (h *host) bind(c *daemon.Client, o *owner, name string, claimed *daemon.Claimed) (*started, error) {
	h.t.Helper()
	readyPolicy := session.Policy{Image: h.Identity, LaunchKey: h.LaunchKey, Authority: o.authorityPub, AllowReady: true}
	ready, err := session.VerifyReady(ctx(h.t), readyPolicy, h.Engine, claimed.Evidence, time.Now())
	if err != nil {
		return nil, err
	}
	bind, err := session.NewBind(session.BindOptions{
		Authority: o.authority, InstanceKey: ready.InstanceKey, Tenant: "acme", Session: name,
		NotAfter: time.Now().Add(time.Minute),
		Policy: session.BindPolicy{
			Access:      session.Access{Exec: []string{o.accessPub}, Credentials: []string{o.accessPub}},
			Credentials: []session.Credential{{Name: "token", MaxBytes: 64}},
		},
	})
	if err != nil {
		return nil, err
	}
	answer, err := c.Bind(ctx(h.t), requestID(h.t), claimed.TD, bind)
	if err != nil {
		return nil, err
	}
	return h.judge(c, claimed.TD, ready, bind, answer)
}

// judge is what a binder does with the guest's answer to its bind: it
// verifies the guest's receipt, and then the quote that follows it.
func (h *host) judge(c *daemon.Client, td string, ready *session.ReadyTD, bind *session.SignedBind, answer *session.Relayed) (*started, error) {
	h.t.Helper()
	binding := session.Binding{LaunchKey: h.LaunchKey, Launch: ready.Launch, Bind: bind}
	policy := binding.Policy(h.Identity)
	receipt, err := session.VerifyBoundReceipt(policy, ready, bind, answer)
	if err != nil {
		return nil, err
	}
	if len(answer.Evidence) == 0 {
		if answer, err = c.BoundEvidence(ctx(h.t), td); err != nil {
			return nil, err
		}
	}
	att, err := session.VerifyBound(ctx(h.t), policy, h.Engine, ready.InstanceKey, bind, answer)
	if err != nil {
		return nil, err
	}
	if err := receipt.Confirmed(att); err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(answer.Certificate)
	if err != nil {
		return nil, err
	}
	verdict, err := session.VerdictOn(policy, h.Engine, att, leaf, time.Now())
	if err != nil {
		return nil, err
	}
	return &started{td: td, ready: ready, bind: bind, answer: answer, receipt: receipt, policy: policy, verdict: verdict}, nil
}

// drive is a client of the session's guest, reached through the daemon with
// no certificate: the guest is who authenticates it.
func (h *host) drive(o *owner, s *started) *session.Client {
	h.t.Helper()
	signer, err := operatorauth.NewSignerFromKeyPEM(o.accessPEM)
	if err != nil {
		h.t.Fatal(err)
	}
	c, err := session.NewClient("https://session.invalid:8443", s.policy, h.Engine, signer,
		session.Through(h.Client(nil).Dialer(s.td)), session.Kept(s.verdict))
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(c.Close)
	return c
}

func wantCode(t *testing.T, err error, code codes.Code, what string) {
	t.Helper()
	if status.Code(err) != code {
		t.Fatalf("%s: got %v, want %s", what, err, code)
	}
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("never: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The whole of milestone 1's path through the daemon: a session starts from
// the pool, its binder verifies the pinned image and the guest's key and the
// bind's fresh evidence, a credential is released, and one authenticated
// command runs.
func TestSessionStartsFromThePool(t *testing.T) {
	h := newHost(t, 1, nil)
	o := newOwner(t)
	s, err := h.begin(h.AsOrchestrator(), o, "s1")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if s.verdict == nil {
		t.Fatal("the bind's evidence gave no verdict to keep")
	}
	guest := h.drive(o, s)
	if _, err := guest.PutCredential(ctx(t), "token", []byte("hunter2")); err != nil {
		t.Fatalf("release a credential: %v", err)
	}
	result, err := guest.Exec(ctx(t), session.ExecRequest{Argv: []string{"sh", "-c", `cat "$C8S_CREDENTIALS_DIR/token"`}})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if result.ExitCode != 0 || string(result.Stdout) != "hunter2" {
		t.Fatalf("the command gave exit %d, %q", result.ExitCode, result.Stdout)
	}
	// The pool is refilled behind the session.
	eventually(t, "a second TD boots", func() bool { return h.Runner.Booted() >= 2 })

	gone, err := h.AsOrchestrator().Destroy(ctx(t), requestID(t), "s1")
	if err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if gone.GetState() != sessionv1alpha1.SessionState_SESSION_STATE_DESTROYED || gone.GetTd() != s.td {
		t.Fatalf("destroy answered %v", gone)
	}
	if _, err := guest.Exec(ctx(t), session.ExecRequest{Argv: []string{"true"}}); err == nil {
		t.Fatal("a destroyed session ran a command")
	}
}

// A repeat of a request gets the first answer and changes nothing.
func TestRepeatedRequestsChangeNothing(t *testing.T) {
	h := newHost(t, 1, nil)
	c, o := h.AsOrchestrator(), newOwner(t)
	claimID := requestID(t)
	first, err := c.Claim(ctx(t), claimID, sessiondtest.Pool, "s1", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.Claim(ctx(t), claimID, sessiondtest.Pool, "s1", 0)
	if err != nil {
		t.Fatalf("the repeated claim: %v", err)
	}
	if again.TD != first.TD || !again.BindBy.Equal(first.BindBy) || !bytes.Equal(again.Evidence.Certificate, first.Evidence.Certificate) {
		t.Fatal("the repeated claim was answered differently")
	}
	_, err = c.Claim(ctx(t), claimID, sessiondtest.Pool, "s2", 0)
	wantCode(t, err, codes.InvalidArgument, "a claim's id used for another session")
	_, err = c.Claim(ctx(t), requestID(t), sessiondtest.Pool, "s1", 0)
	wantCode(t, err, codes.AlreadyExists, "a second claim for a session that has a TD")

	s, err := h.bind(c, o, "s1", first)
	if err != nil {
		t.Fatal(err)
	}
	// The same bind under a new id is another request, and the TD has its one.
	_, err = c.Bind(ctx(t), requestID(t), s.td, s.bind)
	wantCode(t, err, codes.FailedPrecondition, "a second bind request")

	destroyID := requestID(t)
	if _, err := c.Destroy(ctx(t), destroyID, "s1"); err != nil {
		t.Fatal(err)
	}
	gone, err := c.Destroy(ctx(t), destroyID, "s1")
	if err != nil || gone.GetState() != sessionv1alpha1.SessionState_SESSION_STATE_DESTROYED || gone.GetTd() != s.td {
		t.Fatalf("the repeated destroy: %v, %v", gone, err)
	}
	_, err = c.Destroy(ctx(t), requestID(t), "never-was")
	wantCode(t, err, codes.NotFound, "destroying a session nobody claimed")
	// The session's name is free again, for a new TD.
	if next, err := h.begin(c, o, "s1"); err != nil || next.td == s.td {
		t.Fatalf("a session started anew: %v", err)
	}
}

// A bind repeated under its request's id is answered as the first was.
func TestRepeatedBindIsAnsweredAsTheFirst(t *testing.T) {
	h := newHost(t, 1, nil)
	c, o := h.AsOrchestrator(), newOwner(t)
	claimed, err := c.Claim(ctx(t), requestID(t), sessiondtest.Pool, "s1", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ready, err := session.VerifyReady(ctx(t), session.Policy{Image: h.Identity, LaunchKey: h.LaunchKey, Authority: o.authorityPub, AllowReady: true}, h.Engine, claimed.Evidence, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bind, err := session.NewBind(session.BindOptions{
		Authority: o.authority, InstanceKey: ready.InstanceKey, Tenant: "acme", Session: "s1", NotAfter: time.Now().Add(time.Minute),
		Policy: session.BindPolicy{Access: session.Access{Exec: []string{o.accessPub}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	id := requestID(t)
	first, err := c.Bind(ctx(t), id, claimed.TD, bind)
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.Bind(ctx(t), id, claimed.TD, bind)
	if err != nil {
		t.Fatalf("the repeated bind: %v", err)
	}
	if first.Receipt == nil || again.Receipt == nil || !bytes.Equal(first.Receipt.Receipt, again.Receipt.Receipt) ||
		first.Receipt.Signature != again.Receipt.Signature || !bytes.Equal(first.Evidence, again.Evidence) {
		t.Fatal("the repeated bind was answered with another receipt or other evidence")
	}
	other, err := session.NewBind(session.BindOptions{
		Authority: o.authority, InstanceKey: ready.InstanceKey, Tenant: "acme", Session: "s1", NotAfter: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Bind(ctx(t), id, claimed.TD, other)
	wantCode(t, err, codes.InvalidArgument, "a bind's id used for another bind")
}

// A pool with nothing ready says so, and says when to come back.
func TestClaimOnAnEmptyPool(t *testing.T) {
	h := newHost(t, 1, func(c *sessiond.Config) { c.Capacity = 1 })
	c, o := h.AsOrchestrator(), newOwner(t)
	if _, err := h.begin(c, o, "s1"); err != nil {
		t.Fatal(err)
	}
	// The host is at its capacity: the pool cannot be refilled.
	began := time.Now()
	_, err := c.Claim(ctx(t), requestID(t), sessiondtest.Pool, "s2", 300*time.Millisecond)
	wantCode(t, err, codes.ResourceExhausted, "a claim on an empty pool")
	if waited := time.Since(began); waited < 300*time.Millisecond {
		t.Fatalf("the claim waited %s of its 300ms", waited)
	}
	hinted := false
	for _, detail := range status.Convert(err).Details() {
		if retry, ok := detail.(*errdetails.RetryInfo); ok && retry.GetRetryDelay().AsDuration() > 0 {
			hinted = true
		}
	}
	if !hinted {
		t.Fatal("the answer does not say when to come back")
	}
	_, err = c.Claim(ctx(t), requestID(t), "elsewhere", "s2", 0)
	wantCode(t, err, codes.NotFound, "a claim on a pool the host does not have")
	// A waiting claim takes the TD that capacity makes room for.
	waiting := make(chan error, 1)
	go func() {
		_, err := c.Claim(ctx(t), requestID(t), sessiondtest.Pool, "s3", 20*time.Second)
		waiting <- err
	}()
	if _, err := c.Destroy(ctx(t), requestID(t), "s1"); err != nil {
		t.Fatal(err)
	}
	if err := <-waiting; err != nil {
		t.Fatalf("the waiting claim: %v", err)
	}
}

// A claim nobody binds returns its TD to the pool, and a bind that comes
// after is refused: nothing of a tenant entered the TD.
func TestClaimLapses(t *testing.T) {
	h := newHost(t, 1, func(c *sessiond.Config) { c.Capacity = 1 })
	c, o := h.AsOrchestrator(), newOwner(t)
	id := requestID(t)
	claimed, err := c.Claim(ctx(t), id, sessiondtest.Pool, "s1", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if grace := time.Until(claimed.BindBy); grace <= 0 || grace > time.Second {
		t.Fatalf("the claim's grace is %s", grace)
	}
	time.Sleep(time.Until(claimed.BindBy) + 200*time.Millisecond)
	_, err = h.bind(c, o, "s1", claimed)
	wantCode(t, err, codes.FailedPrecondition, "a bind after the claim lapsed")
	_, err = c.Claim(ctx(t), id, sessiondtest.Pool, "s1", 0)
	wantCode(t, err, codes.FailedPrecondition, "the lapsed claim repeated")
	// The same TD serves the next claim: the host has room for one only.
	next, err := c.Claim(ctx(t), requestID(t), sessiondtest.Pool, "s2", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if next.TD != claimed.TD {
		t.Fatal("the lapsed TD did not return to the pool")
	}
	if _, err := h.bind(c, o, "s2", next); err != nil {
		t.Fatalf("the returned TD could not be bound: %v", err)
	}
}

// A claim given back before any bind returns its TD to the pool at once:
// nothing of the session entered the guest.
func TestDestroyGivesAClaimBack(t *testing.T) {
	h := newHost(t, 1, func(c *sessiond.Config) { c.Capacity = 1 })
	c, o := h.AsOrchestrator(), newOwner(t)
	claimID, destroyID := requestID(t), requestID(t)
	claimed, err := c.Claim(ctx(t), claimID, sessiondtest.Pool, "s1", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	gone, err := c.Destroy(ctx(t), destroyID, "s1")
	if err != nil || gone.GetState() != sessionv1alpha1.SessionState_SESSION_STATE_DESTROYED || gone.GetTd() != claimed.TD {
		t.Fatalf("destroy of a claimed session: %v, %v", gone, err)
	}
	again, err := c.Destroy(ctx(t), destroyID, "s1")
	if err != nil || again.GetTd() != claimed.TD {
		t.Fatalf("the repeated destroy: %v, %v", again, err)
	}
	_, err = c.Destroy(ctx(t), destroyID, "s2")
	wantCode(t, err, codes.InvalidArgument, "a destroy's id used for another session")
	_, err = h.bind(c, o, "s1", claimed)
	wantCode(t, err, codes.FailedPrecondition, "a bind after the claim was given back")
	_, err = c.Claim(ctx(t), claimID, sessiondtest.Pool, "s1", 0)
	wantCode(t, err, codes.FailedPrecondition, "the claim that was given back, repeated")
	// The host has room for one TD, and no boot is needed: the same TD
	// serves the next session.
	next, err := c.Claim(ctx(t), requestID(t), sessiondtest.Pool, "s1", 0)
	if err != nil || next.TD != claimed.TD {
		t.Fatalf("the TD did not return to the pool: %v", err)
	}
	if _, err := h.bind(c, o, "s1", next); err != nil {
		t.Fatalf("the returned TD could not be bound: %v", err)
	}
	if h.Runner.Booted() != 1 {
		t.Fatalf("%d TDs were booted for one", h.Runner.Booted())
	}
}

// Nobody but an orchestrator claims, binds or destroys. Evidence is anyone's,
// and so is a connection to a bound TD, which the guest authenticates.
func TestCallersAreHeldToTheirCertificates(t *testing.T) {
	h := newHost(t, 1, nil)
	anyone, o := h.Client(nil), newOwner(t)
	_, err := anyone.Claim(ctx(t), requestID(t), sessiondtest.Pool, "s1", 0)
	wantCode(t, err, codes.Unauthenticated, "a claim with no certificate")
	_, err = anyone.Destroy(ctx(t), requestID(t), "s1")
	wantCode(t, err, codes.Unauthenticated, "a destroy with no certificate")
	// A certificate of another authority is as good as none, and so is one
	// of the orchestrators' authority whose time is over. The handshake takes
	// either: it proves a key, and each call decides whose.
	for name, cert := range map[string]*tls.Certificate{"a stranger's certificate": &h.Stranger, "a certificate that has ended": &h.Ended} {
		c := h.Client(cert)
		_, err = c.Claim(ctx(t), requestID(t), sessiondtest.Pool, "s1", 0)
		wantCode(t, err, codes.Unauthenticated, "a claim under "+name)
		_, err = c.Destroy(ctx(t), requestID(t), "s1")
		wantCode(t, err, codes.Unauthenticated, "a destroy under "+name)
		if _, err := c.Evidence(ctx(t), "no-such-td"); status.Code(err) == codes.Unauthenticated {
			t.Fatalf("evidence under %s: %v", name, err)
		}
	}

	s, err := h.begin(h.AsOrchestrator(), o, "s1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = anyone.Bind(ctx(t), requestID(t), s.td, s.bind)
	wantCode(t, err, codes.Unauthenticated, "a bind with no certificate")
	evidence, err := anyone.Evidence(ctx(t), s.td)
	if err != nil {
		t.Fatalf("evidence with no certificate: %v", err)
	}
	if evidence.Phase != session.PhaseRunning || !bytes.Equal(evidence.Bind, s.bind.Raw) {
		t.Fatalf("the evidence of a bound TD says phase %s", evidence.Phase)
	}
	// A stranger connects, and the guest tells it nothing but no.
	stranger := newOwner(t)
	_, err = h.drive(stranger, s).Exec(ctx(t), session.ExecRequest{Argv: []string{"true"}})
	var refused *session.StatusError
	if !errors.As(err, &refused) || refused.Status != 401 {
		t.Fatalf("a stranger's command: %v", err)
	}
}

// A TD nobody has bound carries no connection: a caller that knows its name
// cannot reach it, and so cannot bind it for itself.
func TestOnlyABoundTDCarriesConnections(t *testing.T) {
	h := newHost(t, 1, nil)
	c, o := h.AsOrchestrator(), newOwner(t)
	claimed, err := c.Claim(ctx(t), requestID(t), sessiondtest.Pool, "s1", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	dial := h.Client(nil).Dialer(claimed.TD)
	read := func() error {
		conn, err := dial(ctx(t), "", "")
		if err != nil {
			return err
		}
		defer conn.Close()
		_, err = conn.Read(make([]byte, 1))
		return err
	}
	wantCode(t, read(), codes.FailedPrecondition, "a connection to a claimed TD")
	conn, err := h.Client(nil).Dialer("td-00000000000000000000000000000000")(ctx(t), "", "")
	if err == nil {
		_, err = conn.Read(make([]byte, 1))
	}
	wantCode(t, err, codes.NotFound, "a connection to a TD that is not")
	s, err := h.bind(c, o, "s1", claimed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.drive(o, s).Exec(ctx(t), session.ExecRequest{Argv: []string{"true"}}); err != nil {
		t.Fatalf("a command on the bound TD: %v", err)
	}
}

// A claim is the daemon's own record and asks the guest nothing: the guest
// learns of it from the bind, and raises its fence then. A connection
// somebody opened before the bind outlives the claim and is cut by the bind.
func TestBindFencesTheGuestAndAClaimAsksItNothing(t *testing.T) {
	h := newHost(t, 1, func(c *sessiond.Config) { c.Capacity = 1 })
	eventually(t, "the pool's TD boots", func() bool { return h.Runner.Booted() >= 1 })
	td := h.Runner.Last()
	// Somebody on the host reached the guest before it was claimed.
	early, err := tls.Dial("tcp", td.Address(), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // a stranger's connection
	if err != nil {
		t.Fatal(err)
	}
	defer early.Close()
	answers := func() bool {
		req, err := http.NewRequest(http.MethodGet, "https://guest"+session.PathState, nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = early.SetDeadline(time.Now().Add(10 * time.Second))
		if err := req.Write(early); err != nil {
			return false
		}
		resp, err := http.ReadResponse(bufio.NewReader(early), req)
		if err != nil {
			return false
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}
	c, o := h.AsOrchestrator(), newOwner(t)
	eventually(t, "the pool's TD is ready", func() bool {
		_, err := c.Evidence(ctx(t), "none")
		return status.Code(err) == codes.NotFound && td.Asked(session.PathState) > 0
	})
	asked := td.Asked("")
	claimed, err := c.Claim(ctx(t), requestID(t), sessiondtest.Pool, "s1", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got := td.Asked(""); got != asked {
		t.Fatalf("the claim had the guest asked %d times", got-asked)
	}
	if len(claimed.Evidence.Certificate) == 0 || len(claimed.Evidence.Launch) == 0 {
		t.Fatalf("the claim relayed %+v", claimed.Evidence)
	}
	if !answers() {
		t.Fatal("the connection opened before the claim did not outlive it")
	}
	if _, err := h.bind(c, o, "s1", claimed); err != nil {
		t.Fatal(err)
	}
	if got := td.Asked(session.PathBind); got != 1 {
		t.Fatalf("the guest was sent %d binds", got)
	}
	if answers() {
		t.Fatal("the connection opened before the bind outlived it")
	}
}

// The daemon holds one connection to each guest it keeps ready. A claim
// relays what the guest said of itself over it when it became ready, and the
// bind goes over the same connection: between the daemon and the guest a
// session starts with no handshake and one request.
func TestSessionStartsOverTheKeptConnection(t *testing.T) {
	h := newHost(t, 1, func(c *sessiond.Config) { c.Capacity = 1 })
	o := newOwner(t)
	s, err := h.begin(h.AsOrchestrator(), o, "s1")
	if err != nil {
		t.Fatal(err)
	}
	td := h.Runner.Last()
	if got := td.Accepted(); got != 1 {
		t.Fatalf("the guest accepted %d connections from boot to its bind's answer, want the daemon's one", got)
	}
	// What the claim relayed from before is what the guest holds: it verified
	// as the pinned image, and the bind made for it was taken.
	if s.ready == nil || len(s.ready.Launch) == 0 {
		t.Fatalf("the claim relayed %+v", s.ready)
	}
	if _, err := h.drive(o, s).Exec(ctx(t), session.ExecRequest{Argv: []string{"true"}}); err != nil {
		t.Fatalf("a command on the session: %v", err)
	}
}

// A guest closes a connection that sat idle, and a road drops one. The
// daemon's bind then goes over a new one, and a session still starts.
func TestKeptConnectionIsReplacedWhenItIsGone(t *testing.T) {
	h := newHost(t, 1, func(c *sessiond.Config) { c.Capacity = 1 })
	eventually(t, "the pool's TD boots", func() bool { return h.Runner.Booted() >= 1 })
	td := h.Runner.Last()
	c := h.AsOrchestrator()
	eventually(t, "the pool's TD is ready", func() bool {
		_, err := c.Evidence(ctx(t), "none")
		return status.Code(err) == codes.NotFound && td.Asked(session.PathCollateral) > 0
	})
	// What the daemon kept of the guest is still good: the claim needs no
	// connection. The bind does, and makes one.
	td.Cut()
	o := newOwner(t)
	if _, err := h.begin(c, o, "s1"); err != nil {
		t.Fatalf("a session after the kept connection was closed: %v", err)
	}
	if got := td.Accepted(); got != 2 {
		t.Fatalf("the guest accepted %d connections: the daemon's first and the one its bind made make 2", got)
	}
}

// A guest that refuses its bind is ended: whatever it made of those bytes, it
// is not offered to another session.
func TestRefusedBindEndsTheTD(t *testing.T) {
	h := newHost(t, 1, nil)
	c, o := h.AsOrchestrator(), newOwner(t)
	claimed, err := c.Claim(ctx(t), requestID(t), sessiondtest.Pool, "s1", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ready, err := session.VerifyReady(ctx(t), session.Policy{Image: h.Identity, LaunchKey: h.LaunchKey, Authority: o.authorityPub, AllowReady: true}, h.Engine, claimed.Evidence, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bind, err := session.NewBind(session.BindOptions{
		Authority: o.authority, InstanceKey: ready.InstanceKey, Tenant: "acme", Session: "s1", NotAfter: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	forged := *bind
	forged.Signature = strings.Repeat("A", len(bind.Signature))
	_, err = c.Bind(ctx(t), requestID(t), claimed.TD, &forged)
	wantCode(t, err, codes.FailedPrecondition, "a bind under a forged signature")
	_, err = c.Bind(ctx(t), requestID(t), claimed.TD, bind)
	wantCode(t, err, codes.FailedPrecondition, "a bind for a TD that ended")
	_, err = h.Client(nil).Evidence(ctx(t), claimed.TD)
	wantCode(t, err, codes.FailedPrecondition, "evidence of a TD that ended")
	// The session is not stuck with the ended TD.
	if _, err := h.begin(c, o, "s1"); err != nil {
		t.Fatalf("the session could not start on another TD: %v", err)
	}
}

// A binder that pins another image or another launch key signs nothing, and
// one that is handed another guest's answer does not take it.
func TestBinderRefusesWhatItDidNotPin(t *testing.T) {
	h := newHost(t, 2, nil)
	c, o := h.AsOrchestrator(), newOwner(t)
	claimed, err := c.Claim(ctx(t), requestID(t), sessiondtest.Pool, "s1", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	policy := session.Policy{Image: h.Identity, LaunchKey: h.LaunchKey, Authority: o.authorityPub, AllowReady: true}
	other := sessionsim.NewGuest(t, nil)
	otherImage, err := runtimemeasure.LoadImageManifest(other.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := os.ReadFile(other.LaunchKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	var refused *session.VerificationError
	wrongImage := policy
	wrongImage.Image = otherImage
	if _, err := session.VerifyReady(ctx(t), wrongImage, h.Engine, claimed.Evidence, time.Now()); !errors.As(err, &refused) {
		t.Fatalf("a TD of another image: %v", err)
	}
	wrongKey := policy
	wrongKey.LaunchKey = otherKey
	if _, err := session.VerifyReady(ctx(t), wrongKey, h.Engine, claimed.Evidence, time.Now()); !errors.As(err, &refused) {
		t.Fatalf("a TD launched under another key: %v", err)
	}
	// A host that relays one TD's certificate with another's documents.
	second, err := c.Claim(ctx(t), requestID(t), sessiondtest.Pool, "s2", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	s, err := h.bind(c, o, "s1", claimed)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := h.bind(c, o, "s2", second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.VerifyBound(ctx(t), s.policy, h.Engine, s.ready.InstanceKey, s.bind, s2.answer); !errors.As(err, &refused) {
		t.Fatalf("another guest's answer passed as this one's: %v", err)
	}
	// What a bound guest serves to anyone is the quote it took over its
	// bind's nonce. It verifies for the bind it answers and confirms that
	// bind's receipt, and does neither for another session's.
	public, err := h.Client(nil).Evidence(ctx(t), s.td)
	if err != nil {
		t.Fatal(err)
	}
	att, err := session.VerifyBound(ctx(t), s.policy, h.Engine, s.ready.InstanceKey, s.bind, public)
	if err != nil {
		t.Fatalf("the quote a bound guest serves to anyone: %v", err)
	}
	if err := s.receipt.Confirmed(att); err != nil {
		t.Fatalf("the quote a bound guest serves does not confirm its receipt: %v", err)
	}
	if err := s2.receipt.Confirmed(att); !errors.As(err, &refused) {
		t.Fatalf("one guest's quote confirmed another's receipt: %v", err)
	}
	if _, err := session.VerifyBound(ctx(t), s2.policy, h.Engine, s2.ready.InstanceKey, s2.bind, public); !errors.As(err, &refused) {
		t.Fatalf("one guest's served quote passed as another's answer: %v", err)
	}
	if _, err := session.VerifyBoundReceipt(s.policy, s.ready, s.bind, &session.Relayed{}); !errors.As(err, &refused) {
		t.Fatalf("an answer with no receipt passed as receipted: %v", err)
	}
	// A quote with nothing but the state around it answers no bind.
	bare := *public
	bare.Evidence = nil
	if _, err := session.VerifyBound(ctx(t), s.policy, h.Engine, s.ready.InstanceKey, s.bind, &bare); !errors.As(err, &refused) {
		t.Fatalf("evidence with no quote passed as the answer to a bind: %v", err)
	}
	// The answer that was verified is still the one that verifies.
	if _, err := session.VerifyBound(ctx(t), s.policy, h.Engine, s.ready.InstanceKey, s.bind, s.answer); err != nil {
		t.Fatalf("the guest's own answer: %v", err)
	}
}

// A daemon started later finds the host's TDs and answers as the first did.
func TestRestartedDaemonTakesOverItsTDs(t *testing.T) {
	h := newHost(t, 1, nil)
	c, o := h.AsOrchestrator(), newOwner(t)
	claimID := requestID(t)
	claimed, err := c.Claim(ctx(t), claimID, sessiondtest.Pool, "s1", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	s, err := h.bind(c, o, "s1", claimed)
	if err != nil {
		t.Fatal(err)
	}
	guest := h.drive(o, s)
	if _, err := guest.Exec(ctx(t), session.ExecRequest{Argv: []string{"true"}}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the pool is refilled", func() bool { return h.Runner.Booted() >= 2 })
	booted := h.Runner.Booted()

	h.Stop()
	h.StartDaemon()
	c = h.AsOrchestrator()
	again, err := c.Claim(ctx(t), claimID, sessiondtest.Pool, "s1", 0)
	if err != nil || again.TD != claimed.TD {
		t.Fatalf("the claim repeated after the restart: %v", err)
	}
	// The session's guest never noticed: a new connection reaches it.
	if _, err := h.drive(o, s).Exec(ctx(t), session.ExecRequest{Argv: []string{"true"}}); err != nil {
		t.Fatalf("a command after the restart: %v", err)
	}
	if _, err := h.begin(c, o, "s2"); err != nil {
		t.Fatalf("a session on the pool's adopted TD: %v", err)
	}
	if now := h.Runner.Booted(); now > booted+1 {
		t.Fatalf("the restarted daemon booted %d TDs where one refill was due", now-booted)
	}
	if _, err := c.Destroy(ctx(t), requestID(t), "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.drive(o, s).Exec(ctx(t), session.ExecRequest{Argv: []string{"true"}}); err == nil {
		t.Fatal("a session destroyed after the restart still ran a command")
	}
}

// A TD that went while no daemon ran is ended by the next one.
func TestRestartedDaemonEndsWhatIsGone(t *testing.T) {
	h := newHost(t, 1, nil)
	c, o := h.AsOrchestrator(), newOwner(t)
	s, err := h.begin(c, o, "s1")
	if err != nil {
		t.Fatal(err)
	}
	h.Stop()
	for _, td := range h.Runner.All() {
		td.Stop()
	}
	h.StartDaemon()
	c = h.AsOrchestrator()
	_, err = h.Client(nil).Evidence(ctx(t), s.td)
	wantCode(t, err, codes.FailedPrecondition, "evidence of a TD that went with no daemon running")
	if _, err := h.begin(c, o, "s2"); err != nil {
		t.Fatalf("the pool did not come back: %v", err)
	}
}

// A guest that ends on its own, as one past its age limit does, is replaced.
func TestEndedGuestIsReplaced(t *testing.T) {
	h := newHost(t, 1, nil)
	eventually(t, "the pool's TD boots", func() bool { return h.Runner.Booted() >= 1 })
	h.Runner.Last().Stop()
	eventually(t, "a replacement boots", func() bool { return h.Runner.Booted() >= 2 })
	if _, err := h.begin(h.AsOrchestrator(), newOwner(t), "s1"); err != nil {
		t.Fatal(err)
	}
}

// Boots that fail are tried again, further and further apart.
func TestFailedBootsBackOff(t *testing.T) {
	h := newHost(t, 1, nil)
	eventually(t, "the pool's TD boots", func() bool { return h.Runner.Booted() >= 1 })
	// The TD the pool had goes, and its replacements do not boot.
	h.Runner.Fail(errors.New("no memory"))
	h.Runner.Last().Stop()
	_, err := h.AsOrchestrator().Claim(ctx(t), requestID(t), sessiondtest.Pool, "s1", 500*time.Millisecond)
	wantCode(t, err, codes.ResourceExhausted, "a claim while boots fail")
	h.Runner.Fail(nil)
	if _, err := h.AsOrchestrator().Claim(ctx(t), requestID(t), sessiondtest.Pool, "s1", 20*time.Second); err != nil {
		t.Fatalf("the pool did not recover: %v", err)
	}
}
