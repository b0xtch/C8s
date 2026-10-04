package sessionagent_test

import (
	"bytes"
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
// order the guest asked, can fail one, and can hold its quotes back.
type quotingTEE struct {
	sessiontest.TEE
	mu      sync.Mutex
	asked   [][]byte
	failing int
	never   []byte
	held    chan struct{}
}

func (q *quotingTEE) Evidence(ctx context.Context, reportData []byte) (teetypes.AttestationEvidence, error) {
	q.mu.Lock()
	q.asked = append(q.asked, slices.Clone(reportData))
	fail := q.failing > 0
	if fail {
		q.failing--
	}
	if q.never != nil && bytes.Equal(q.never, reportData) {
		fail = true
	}
	held := q.held
	q.mu.Unlock()
	if held != nil {
		select {
		case <-held:
		case <-ctx.Done():
			return teetypes.AttestationEvidence{}, ctx.Err()
		}
	}
	if fail {
		return teetypes.AttestationEvidence{}, errors.New("the quoting service is away")
	}
	return q.TEE.Evidence(ctx, reportData)
}

// hold has every quote asked for from now on wait until the returned
// function is called.
func (q *quotingTEE) hold() (release func()) {
	held := make(chan struct{})
	q.mu.Lock()
	q.held = held
	q.mu.Unlock()
	return sync.OnceFunc(func() {
		q.mu.Lock()
		q.held = nil
		q.mu.Unlock()
		close(held)
	})
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

// failFor has every quote over reportData fail.
func (q *quotingTEE) failFor(reportData []byte) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.never = slices.Clone(reportData)
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

// withoutEvidence is what an agent logs when an attempt at the quote over
// its bind's nonce gave none.
const withoutEvidence = "no quote was taken over the bind's nonce"

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

// A bind that comes with a nonce is answered with the guest's receipt, and
// the guest takes the evidence its sender would have asked for next: it comes
// with the answer or with the guest's state. The sender judges it, holds it
// to the receipt, and is the bound guest's client from then on: one
// connection, no attestation request, and the quote for it taken ahead of the
// one the reissued serving certificate needs.
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
	if resp.Phase != session.PhaseRunning || resp.Replayed || resp.Receipt == nil {
		t.Fatalf("the bind's answer: %+v", resp)
	}
	if att.Phase != session.PhaseRunning || len(att.Events) != 3 || att.Tenant != "acme" || att.Session != "sbx-1" || att.Bind == nil {
		t.Fatalf("the attestation that followed the answer: %+v", att)
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

// A guest whose quoting service fails it once answers its bind with the
// receipt alone, takes the quote again a moment later and serves it: the
// sender waits for it and asks for no attestation.
func TestBindQuoteThatFailsIsTakenAgain(t *testing.T) {
	p, tee, log := quoted(t)
	client, taken := p.watched(t, p.policy)
	ready, err := client.Ready(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	bind := p.bindFor(t, ready, nil)
	before := len(tee.quotes())
	tee.failNext()
	resp, att, err := client.BindAttested(ctxT(t), bind, p.boundPolicy(ready, bind))
	if err != nil {
		t.Fatalf("BindAttested: %v", err)
	}
	if resp.Attestation != nil || resp.Receipt == nil || resp.Phase != session.PhaseRunning {
		t.Fatalf("the bind's answer: %+v", resp)
	}
	if att == nil || att.Phase != session.PhaseRunning || len(att.Events) != 3 {
		t.Fatalf("the attestation: %+v", att)
	}
	if taken.count(session.TimedDial) != 1 || taken.count(session.TimedRequest+" "+session.PathAttest) != 0 {
		t.Fatalf("the client's steps: %s", taken.list())
	}
	if !log.has(withoutEvidence) {
		t.Fatal("the agent did not say that an attempt gave no quote")
	}
	// The failed attempt, the certificate's quote, and the second attempt:
	// both attempts are for the bind's nonce.
	asked := awaitQuotes(t, tee, before+3)[before:]
	certificate := certificateQuote(t, ready.InstanceKey.(*ecdsa.PublicKey))
	if !slices.Equal(asked[0], asked[2]) || !slices.Equal(asked[1], certificate) {
		t.Fatal("the guest's quotes after the bind are not the bind's, the certificate's and the bind's again")
	}
}

// The bind's answer does not wait for the quote. A guest whose quoting
// service is slow answers with its receipt, signed by the key the bind names,
// and its state serves the quote once it is taken. The receipt and the quote
// say the same.
func TestBindIsAnsweredWithAReceiptAndTheQuoteFollows(t *testing.T) {
	p, tee, _ := quoted(t)
	client, _ := p.watched(t, p.policy)
	ready, err := client.Ready(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	bind := p.bindFor(t, ready, nil)
	bound := p.boundPolicy(ready, bind)
	release := tee.hold()
	defer release()
	resp, err := client.Bind(ctxT(t), bind)
	if err != nil {
		t.Fatalf("Bind while the quoting service is slow: %v", err)
	}
	if resp.Attestation != nil || resp.Receipt == nil || resp.Phase != session.PhaseRunning {
		t.Fatalf("the bind's answer: %+v", resp)
	}
	receipt, err := session.VerifyBindReceipt(bound, ready.InstanceKey, bind, resp.Receipt)
	if err != nil {
		t.Fatalf("the receipt: %v", err)
	}
	image, err := bind.Doc.Policy.Sandbox.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Bind != session.DocumentDigest(bind.Raw) || receipt.Nonce != bind.Doc.Nonce || receipt.Phase != session.PhaseRunning ||
		!slices.Equal(receipt.Events, []string{session.DocumentDigest(bind.Raw), image}) {
		t.Fatalf("the receipt says %+v", receipt)
	}
	if state := p.state(t); state.Phase != session.PhaseRunning || state.Attestation != nil {
		t.Fatalf("the state before the quote is taken: phase %s, quote %v", state.Phase, state.Attestation != nil)
	}
	// The same bind again is answered as the first time.
	again, err := client.Bind(ctxT(t), bind)
	if err != nil || !again.Replayed || again.Receipt == nil ||
		!bytes.Equal(again.Receipt.Receipt, resp.Receipt.Receipt) || again.Receipt.Signature != resp.Receipt.Signature {
		t.Fatalf("the same bind again: %+v, %v", again, err)
	}

	release()
	var quote *session.AttestResponse
	for deadline := time.Now().Add(5 * time.Second); quote == nil; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the guest's state never served the quote over the bind's nonce")
		}
		quote = p.state(t).Attestation
	}
	att, err := session.VerifyAttestation(ctxT(t), bound, sessiontest.Engine{}, ready.InstanceKey, bind.Doc.EvidenceNonce(), quote)
	if err != nil {
		t.Fatalf("the quote that followed the receipt: %v", err)
	}
	if err := receipt.Confirmed(att); err != nil {
		t.Fatalf("the quote does not confirm the receipt: %v", err)
	}
	// And a bind sent again from then on carries it.
	if again, err = client.Bind(ctxT(t), bind); err != nil || again.Attestation == nil {
		t.Fatalf("the same bind after the quote was taken: %+v, %v", again, err)
	}
}

// A sender that takes its guest by BindAttested waits for the quote the
// guest takes over the bind's nonce: it asks the guest's state for it, and
// for no attestation of its own.
func TestBindAttestedWaitsForTheQuoteItsGuestTakes(t *testing.T) {
	p, tee, _ := quoted(t)
	client, taken := p.watched(t, p.policy)
	ready, err := client.Ready(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	bind := p.bindFor(t, ready, nil)
	release := tee.hold()
	defer release()
	type outcome struct {
		resp *session.BindResponse
		att  *session.Attestation
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		resp, att, err := client.BindAttested(ctxT(t), bind, p.boundPolicy(ready, bind))
		done <- outcome{resp, att, err}
	}()
	// The guest answers the bind while its quoting service is slow, and
	// the sender goes on asking for the quote.
	for deadline := time.Now().Add(5 * time.Second); taken.count(session.TimedRequest+" "+session.PathState) < 3; time.Sleep(2 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the sender did not ask the guest's state for the quote: %s", taken.list())
		}
	}
	select {
	case got := <-done:
		t.Fatalf("BindAttested returned before the guest had a quote: %+v, %v", got.att, got.err)
	default:
	}
	release()
	var got outcome
	select {
	case got = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("BindAttested did not return once the guest had its quote")
	}
	if got.err != nil {
		t.Fatalf("BindAttested: %v", got.err)
	}
	if got.resp.Attestation != nil || got.resp.Receipt == nil || got.att == nil || got.att.Phase != session.PhaseRunning || len(got.att.Events) != 3 {
		t.Fatalf("answer %+v, attestation %+v", got.resp, got.att)
	}
	if taken.count(session.TimedDial) != 1 || taken.count(session.TimedRequest+" "+session.PathAttest) != 0 {
		t.Fatalf("the client's steps: %s", taken.list())
	}
	if _, ok := client.Verdict(); !ok {
		t.Fatal("no verdict on a guest whose quote was judged")
	}
}

// A client that is given its guest by a verified receipt runs its first
// command without a quote. It keeps no verdict until the quote that followed
// has confirmed the receipt, and takes no other guest's quote for it.
func TestClientGoesOnWithAReceiptAndKeepsNoVerdictOnIt(t *testing.T) {
	p, tee, _ := quoted(t)
	binder, _ := p.watched(t, p.policy)
	ready, err := binder.Ready(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	bind := p.bindFor(t, ready, nil)
	bound := p.boundPolicy(ready, bind)
	release := tee.hold()
	defer release()
	resp, err := binder.Bind(ctxT(t), bind)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := session.VerifyBindReceipt(bound, ready.InstanceKey, bind, resp.Receipt)
	if err != nil {
		t.Fatalf("the receipt: %v", err)
	}
	taken := &steps{}
	client, err := session.NewClient(p.url, bound, sessiontest.Engine{}, p.access, taken.option(), session.Receipted(ready.InstanceKey))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if !client.Pinned() {
		t.Fatal("a receipt pinned nothing")
	}
	out, err := client.Exec(ctxT(t), session.ExecRequest{Argv: []string{"echo", "on a receipt"}})
	if err != nil || string(out.Stdout) != "on a receipt\n" {
		t.Fatalf("the first command, sent on the receipt: %+v, %v", out, err)
	}
	if taken.count(session.TimedRequest+" "+session.PathAttest) != 0 {
		t.Fatalf("the client asked for a quote: %s", taken.list())
	}
	if _, ok := client.Verdict(); ok {
		t.Fatal("the client keeps a verdict that rests on a receipt")
	}

	release()
	var quote *session.AttestResponse
	for deadline := time.Now().Add(5 * time.Second); quote == nil; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the guest's state never served the quote over the bind's nonce")
		}
		quote = p.state(t).Attestation
	}
	att, err := session.VerifyAttestation(ctxT(t), bound, sessiontest.Engine{}, ready.InstanceKey, bind.Doc.EvidenceNonce(), quote)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.Confirmed(att); err != nil {
		t.Fatal(err)
	}
	// Another guest's attestation confirms nothing for this client.
	stranger := *att
	stranger.InstanceKey = append([]byte(nil), att.InstanceKey...)
	stranger.InstanceKey[len(stranger.InstanceKey)-1] ^= 1
	if err := client.Confirmed(&stranger, nil); err == nil {
		t.Fatal("an attestation under another key confirmed the client's receipt")
	}
	if _, ok := client.Verdict(); ok {
		t.Fatal("the client keeps a verdict after a confirmation it refused")
	}
	if err := client.Confirmed(att, nil); err != nil {
		t.Fatalf("Confirmed: %v", err)
	}
	kept, ok := client.Verdict()
	if !ok {
		t.Fatal("no verdict after the quote confirmed the receipt")
	}
	next, err := session.NewClient(p.url, bound, sessiontest.Engine{}, p.access, session.Kept(kept))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(next.Close)
	if !next.Pinned() {
		t.Fatal("the verdict is not one of the bound guest's policy")
	}
	// The quote is an attestation for the owner's nonce: a credential
	// follows on it, and the guest is asked for nothing more.
	if _, err := client.PutCredential(ctxT(t), "test-token", []byte("s3cr3t")); err != nil {
		t.Fatalf("PutCredential: %v", err)
	}
	if taken.count(session.TimedRequest+" "+session.PathAttest) != 0 {
		t.Fatalf("the client asked for a quote after its bind's quote was confirmed: %s", taken.list())
	}
}

// The same bind sent again, by a client that lost the first answer, is
// answered as the first time: as bound, and with the evidence the guest took
// over the bind's nonce.
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
	if !resp.Replayed || resp.Receipt == nil || att.Phase != session.PhaseRunning || att.Tenant != "acme" {
		t.Fatalf("answer %+v, attestation %+v", resp, att)
	}
	if taken.count(session.TimedDial) != 1 || taken.count(session.TimedRequest+" "+session.PathAttest) != 0 {
		t.Fatalf("the client's steps: %s", taken.list())
	}
}

// A guest that cannot take the quote over its bind's nonce answers with its
// receipt alone and serves no quote. A sender that has waited for one asks
// for an attestation on the connection it has, and that attestation confirms
// the receipt like the bind's own quote would have.
func TestBindWithoutAQuoteIsAttestedOnTheSameConnection(t *testing.T) {
	p, tee, log := quoted(t)
	taken := &steps{}
	client, err := session.NewClient(p.url, p.policy, sessiontest.Engine{}, p.access, taken.option(), session.QuoteWait(100*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	ready, err := client.Ready(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	bind := p.bindFor(t, ready, nil)
	events, err := session.ExpectedEvents(ready.Launch, bind, session.PhaseRunning)
	if err != nil {
		t.Fatal(err)
	}
	over, err := session.ReportData(ready.InstanceKey.(*ecdsa.PublicKey), bind.Doc.EvidenceNonce(), events)
	if err != nil {
		t.Fatal(err)
	}
	tee.failFor(over)
	resp, att, err := client.BindAttested(ctxT(t), bind, p.boundPolicy(ready, bind))
	if err != nil {
		t.Fatalf("BindAttested: %v", err)
	}
	if resp.Replayed || resp.Attestation != nil || resp.Receipt == nil {
		t.Fatalf("a guest that could take no quote for its bind answered %+v", resp)
	}
	if att == nil || att.Phase != session.PhaseRunning || len(att.Events) != 3 || taken.count(session.TimedDial) != 1 ||
		taken.count(session.TimedRequest+" "+session.PathAttest) != 1 {
		t.Fatalf("attestation %+v after the steps %s", att, taken.list())
	}
	if state := p.state(t); state.Attestation != nil {
		t.Fatal("the guest serves a quote over the bind's nonce that it never took")
	}
	if !log.has(withoutEvidence) {
		t.Fatal("the agent did not say that an attempt gave no quote")
	}
}

// The quote over the bind's nonce is a quote like any other: it comes out of
// the guest's ration. Of the burst a bound guest gives at once, the bind's
// quote was one, and the attestation that finds the burst spent waits its
// turn.
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
	if _, _, err := client.BindAttested(ctxT(t), bind, bound); err != nil {
		t.Fatalf("BindAttested: %v", err)
	}
	tenant, _ := p.watched(t, bound)
	const burst = 20
	for i := range burst - 1 {
		if _, err := tenant.Attest(ctxT(t)); err != nil {
			t.Fatalf("attestation %d after the bind: %v", i+1, err)
		}
	}
	began := time.Now()
	if _, err := tenant.Attest(ctxT(t)); err != nil {
		t.Fatalf("the attestation after the burst: %v", err)
	}
	// A fifth of a second is the pace after the burst.
	if waited := time.Since(began); waited < 150*time.Millisecond {
		t.Fatalf("the attestation after the bind's quote and %d more was given in %s: the bind's quote was not one of the burst", burst-1, waited)
	}
}
