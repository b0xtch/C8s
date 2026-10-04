package sessionagent_test

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	agratls "github.com/confidential-dot-ai/attestation-go/ratls"
	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// quotingTEE is a simulated TEE that keeps what each quote was for, in the
// order the guest asked, and can fail one.
type quotingTEE struct {
	sessiontest.TEE
	mu      sync.Mutex
	asked   [][]byte
	failing int
}

func (q *quotingTEE) Evidence(ctx context.Context, reportData []byte) (teetypes.AttestationEvidence, error) {
	q.mu.Lock()
	q.asked = append(q.asked, slices.Clone(reportData))
	fail := q.failing > 0
	if fail {
		q.failing--
	}
	q.mu.Unlock()
	if fail {
		return teetypes.AttestationEvidence{}, errors.New("the quoting service is away")
	}
	return q.TEE.Evidence(ctx, reportData)
}

func (q *quotingTEE) quotes() [][]byte {
	q.mu.Lock()
	defer q.mu.Unlock()
	return slices.Clone(q.asked)
}

// failNext has the next quote fail.
func (q *quotingTEE) failNext() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.failing = 1
}

// steps records what a client reports of its way to the guest.
type steps struct {
	mu    sync.Mutex
	taken []string
}

func (s *steps) option() session.ClientOption {
	return session.Timed(func(step string, _ time.Duration) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.taken = append(s.taken, step)
	})
}

func (s *steps) count(step string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, taken := range s.taken {
		if taken == step {
			n++
		}
	}
	return n
}

func (s *steps) list() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.taken, ", ")
}

// said keeps what an agent logs.
type said struct {
	mu    sync.Mutex
	lines []string
}

func (s *said) Enabled(context.Context, slog.Level) bool { return true }
func (s *said) WithAttrs([]slog.Attr) slog.Handler       { return s }
func (s *said) WithGroup(string) slog.Handler            { return s }
func (s *said) Handle(_ context.Context, record slog.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, record.Message)
	return nil
}

func (s *said) has(message string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Contains(s.lines, message)
}

// quoted is a pool whose guest's quotes are kept, and what its agent logs.
func quoted(t *testing.T) (*pool, *quotingTEE, *said) {
	t.Helper()
	p := newPool(t)
	tee, log := &quotingTEE{TEE: sessiontest.TEE{TD: p.td}}, &said{}
	p.cfg.TEE, p.cfg.Logger = tee, slog.New(log)
	p.start(t)
	return p, tee, log
}

// withoutEvidence is what an agent logs when it could not give a bind's
// sender the evidence it asked for.
const withoutEvidence = "a bind is answered without evidence"

// watched is a client of the unbound guest that says which steps it takes.
func (p *pool) watched(t *testing.T, policy session.Policy) (*session.Client, *steps) {
	t.Helper()
	taken := &steps{}
	client, err := session.NewClient(p.url, policy, sessiontest.Engine{}, p.access, taken.option())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client, taken
}

// boundPolicy is what a tenant holds a guest to once it has bound it.
func (p *pool) boundPolicy(ready *session.ReadyTD, bind *session.SignedBind) session.Policy {
	binding := session.Binding{LaunchKey: p.bundle.LaunchKey, Launch: ready.Launch, Bind: bind}
	return binding.Policy(p.policy.Image)
}

// certificateQuote is the report data of a serving certificate's quote.
func certificateQuote(t *testing.T, key *ecdsa.PublicKey) []byte {
	t.Helper()
	rd, err := agratls.ReportDataForKey(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rd[:48]
}

// awaitQuotes waits until the guest has asked for n quotes.
func awaitQuotes(t *testing.T, tee *quotingTEE, n int) [][]byte {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		asked := tee.quotes()
		if len(asked) >= n {
			return asked
		}
		if time.Now().After(deadline) {
			t.Fatalf("the guest asked for %d quotes, want %d", len(asked), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A bind that comes with a nonce is answered with the evidence its sender
// would have asked for next. The sender judges it and is the bound guest's
// client from then on: one connection, no attestation request, and the quote
// for it taken ahead of the one the reissued serving certificate needs.
func TestBindIsAnsweredWithItsOwnEvidence(t *testing.T) {
	p, tee, log := quoted(t)
	// Before the bind the client asks nothing of a tenant: there is none.
	// What it asks here no bound guest of this test meets, so the answer's
	// evidence passes only under the policy the client is handed with it.
	unbound := p.policy
	unbound.Tenant, unbound.Session = "nobody", "none"
	client, taken := p.watched(t, unbound)
	ready, err := client.Ready(ctxT(t))
	if err != nil {
		t.Fatalf("Unbound: %v", err)
	}
	bind := p.bindFor(t, ready, nil)
	bound := p.boundPolicy(ready, bind)
	before := len(tee.quotes())

	resp, att, err := client.BindAttested(ctxT(t), bind, bound)
	if err != nil {
		t.Fatalf("BindAttested: %v", err)
	}
	if resp.Phase != session.PhaseRunning || resp.Replayed || resp.Attestation == nil {
		t.Fatalf("the bind's answer: %+v", resp)
	}
	if att.Phase != session.PhaseRunning || len(att.Events) != 3 || att.Tenant != "acme" || att.Session != "sbx-1" || att.Bind == nil {
		t.Fatalf("the attestation the answer carried: %+v", att)
	}
	if taken.count(session.TimedDial) != 1 || taken.count(session.TimedRequest+" "+session.PathAttest) != 0 ||
		taken.count(session.TimedRequest+" "+session.PathBind) != 1 || taken.count(session.TimedJudgment) != 2 {
		t.Fatalf("the client's steps: %s", taken.list())
	}

	// Two quotes: the answer's, for a nonce, and then the certificate's.
	asked := awaitQuotes(t, tee, before+2)[before:]
	certificate := certificateQuote(t, ready.InstanceKey.(*ecdsa.PublicKey))
	if len(asked) != 2 || slices.Equal(asked[0], certificate) || !slices.Equal(asked[1], certificate) {
		t.Fatalf("the guest's quotes after the bind: %d, the certificate's first: %v", len(asked), slices.Equal(asked[0], certificate))
	}

	// The evidence is an attestation by this client: a credential leaves on
	// it, and the guest is asked for nothing more.
	if _, err := client.PutCredential(ctxT(t), "test-token", []byte("s3cr3t")); err != nil {
		t.Fatalf("PutCredential: %v", err)
	}
	out, err := client.Exec(ctxT(t), session.ExecRequest{Argv: []string{"sh", "-c", `cat "$C8S_CREDENTIALS_DIR/test-token"`}})
	if err != nil || string(out.Stdout) != "s3cr3t" {
		t.Fatalf("exec = %+v, %v", out, err)
	}
	if n := len(tee.quotes()); n != before+2 || taken.count(session.TimedDial) != 1 {
		t.Fatalf("%d quotes and %d dials after a credential and a command", n-before, taken.count(session.TimedDial))
	}

	// The client holds the bound guest's policy now: its verdict is one a
	// later client of the bound guest takes.
	kept, ok := client.Verdict()
	if !ok {
		t.Fatal("no verdict to keep")
	}
	next, err := session.NewClient(p.url, bound, sessiontest.Engine{}, p.access, session.Kept(kept))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(next.Close)
	if !next.Pinned() {
		t.Fatal("the verdict is not one of the bound guest's policy")
	}

	// It has its guest, and binds no other.
	if _, _, err := client.BindAttested(ctxT(t), bind, bound); err == nil || !strings.Contains(err.Error(), "attested a guest already") {
		t.Fatalf("a second bind by the same client: %v", err)
	}
	if log.has(withoutEvidence) {
		t.Fatal("the agent says it gave no evidence")
	}
}

// The policy for the bound guest pins the bind that is sent: with any other
// the client would judge the answer against a document the guest never saw.
func TestBindAttestedSendsTheBindItsPolicyPins(t *testing.T) {
	p, tee, _ := quoted(t)
	client, taken := p.watched(t, p.policy)
	ready, err := client.Ready(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	bind := p.bindFor(t, ready, nil)
	other := p.bindFor(t, ready, func(o *session.BindOptions) { o.Session = "sbx-2" })
	before := len(tee.quotes())
	if _, _, err := client.BindAttested(ctxT(t), bind, p.boundPolicy(ready, other)); err == nil || !strings.Contains(err.Error(), "must pin the bind that is sent") {
		t.Fatalf("a policy that pins another bind: %v", err)
	}
	unpinned := p.boundPolicy(ready, bind)
	unpinned.Authority = nil
	if _, _, err := client.BindAttested(ctxT(t), bind, unpinned); err == nil {
		t.Fatal("a policy that names no authority was taken")
	}
	if taken.count(session.TimedRequest+" "+session.PathBind) != 0 || len(tee.quotes()) != before {
		t.Fatalf("a bind was sent: %s", taken.list())
	}
	if state := p.state(t); state.Phase != session.PhaseReady {
		t.Fatalf("the guest is %s", state.Phase)
	}
}

// A guest that cannot give the evidence with its answer gives the answer
// alone, and the sender asks on the connection it has.
func TestBindAnsweredWithoutEvidenceIsAttestedOnTheSameConnection(t *testing.T) {
	p, tee, log := quoted(t)
	client, taken := p.watched(t, p.policy)
	ready, err := client.Ready(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	bind := p.bindFor(t, ready, nil)
	tee.failNext()
	resp, att, err := client.BindAttested(ctxT(t), bind, p.boundPolicy(ready, bind))
	if err != nil {
		t.Fatalf("BindAttested: %v", err)
	}
	if resp.Attestation != nil || resp.Phase != session.PhaseRunning {
		t.Fatalf("the bind's answer: %+v", resp)
	}
	if att == nil || att.Phase != session.PhaseRunning || len(att.Events) != 3 {
		t.Fatalf("the attestation: %+v", att)
	}
	if taken.count(session.TimedDial) != 1 || taken.count(session.TimedRequest+" "+session.PathAttest) != 1 {
		t.Fatalf("the client's steps: %s", taken.list())
	}
	if !log.has(withoutEvidence) {
		t.Fatal("the agent did not say that it gave no evidence")
	}
}

// The same bind sent again, by a client that lost the first answer, is
// answered as bound and with evidence for the new nonce.
func TestReplayedBindIsAnsweredWithEvidenceToo(t *testing.T) {
	p, _, _ := quoted(t)
	client, _ := p.watched(t, p.policy)
	ready, err := client.Ready(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	bind := p.bindFor(t, ready, nil)
	bound := p.boundPolicy(ready, bind)
	if _, err := client.Bind(ctxT(t), bind); err != nil {
		t.Fatal(err)
	}
	again, taken := p.watched(t, bound)
	resp, att, err := again.BindAttested(ctxT(t), bind, bound)
	if err != nil {
		t.Fatalf("the same bind again: %v", err)
	}
	if !resp.Replayed || resp.Attestation == nil || att.Phase != session.PhaseRunning || att.Tenant != "acme" {
		t.Fatalf("answer %+v, attestation %+v", resp, att)
	}
	if taken.count(session.TimedDial) != 1 || taken.count(session.TimedRequest+" "+session.PathAttest) != 0 {
		t.Fatalf("the client's steps: %s", taken.list())
	}
}

// The answer's evidence is a quote like any other: it comes out of the
// guest's ration, and a guest that has spent it answers the bind alone.
func TestBindEvidenceComesOutOfTheGuestsRation(t *testing.T) {
	p := newPool(t)
	// The guest's clock stands still, so no quote comes due by itself.
	clock := &testClock{now: time.Now()}
	p.cfg.Now = clock.Now
	p.start(t)
	client, _ := p.watched(t, p.policy)
	ready, err := client.Ready(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	bind := p.bindFor(t, ready, nil)
	bound := p.boundPolicy(ready, bind)
	if _, err := client.Bind(ctxT(t), bind); err != nil {
		t.Fatal(err)
	}
	tenant, _ := p.watched(t, bound)
	const burst = 20
	for i := range burst {
		if _, err := tenant.Attest(ctxT(t)); err != nil {
			t.Fatalf("attestation %d of the burst: %v", i+1, err)
		}
	}
	again, taken := p.watched(t, bound)
	resp, att, err := again.BindAttested(ctxT(t), bind, bound)
	if err != nil {
		t.Fatalf("the same bind again: %v", err)
	}
	if !resp.Replayed || resp.Attestation != nil {
		t.Fatalf("a guest with its ration spent answered %+v", resp)
	}
	// The sender asked in its turn, and waited for it.
	if att == nil || att.Phase != session.PhaseRunning || taken.count(session.TimedRequest+" "+session.PathAttest) != 1 {
		t.Fatalf("attestation %+v after the steps %s", att, taken.list())
	}
}
