package sessionagent_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/disclosure"
)

// replayed is the register of p's guest once it holds events.
func replayed(p *pool, events []string) []byte {
	value := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(p.bundle.LaunchKey), events)
	return value[:]
}

// A guest holds its one-time keys for as long as it is nobody's, and has
// erased both by the time its sandbox is started: nothing of the tenant runs
// in a guest that could still sign a receipt or open a command sealed to it.
func TestOneTimeKeysAreGoneBeforeTheSandboxStarts(t *testing.T) {
	p := newPool(t)
	p.runner.starting, p.runner.started = make(chan struct{}), make(chan struct{})
	// Read as the agent starts its sandbox, and not a moment later: whether
	// everything of the keys is erased by then.
	var erased atomic.Bool
	p.runner.onStart = func() { erased.Store(sessionagent.OneTimeKeysErased(p.agent)) }
	p.start(t)
	client := p.client(t, p.access)
	ready, err := client.Ready(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	if sessionagent.OneTimeKeysGone(p.agent) {
		t.Fatal("a guest nobody has bound has no one-time keys left")
	}
	bind := p.bindFor(t, ready, nil)
	type answer struct {
		resp *session.BindResponse
		err  error
	}
	bound := make(chan answer, 1)
	go func() {
		resp, err := client.Bind(ctxT(t), bind)
		bound <- answer{resp, err}
	}()
	select {
	case <-p.runner.starting:
	case <-time.After(10 * time.Second):
		t.Fatal("the sandbox was never started")
	}
	// The runtime has been told to start the sandbox and has not yet: the
	// keys are gone, and the collection that erases what signing left has
	// run to its end.
	if !sessionagent.OneTimeKeysGone(p.agent) {
		t.Fatal("the guest still holds a one-time key as its sandbox starts")
	}
	if !erased.Load() {
		t.Fatal("what the one-time keys left on the heap is not collected as the sandbox starts")
	}
	close(p.runner.started)
	first := <-bound
	if first.err != nil {
		t.Fatal(first.err)
	}
	// The receipt was signed while the key was there, and is the guest's.
	if _, err := session.VerifyBindReceipt(p.boundPolicy(ready, bind), ready.InstanceKey, ready.OneTime, bind, first.resp.Receipt); err != nil {
		t.Fatalf("the receipt of a guest that erased its key: %v", err)
	}
}

// The guest signs its receipt as soon as it has measured its bind: the key
// it signs with is gone before the sandbox's image is prepared, checked or
// measured, and what signing left is collected beside those steps. The
// receipt names the image the guest has yet to measure, and leaves the guest
// only once the register holds what it names and the sandbox runs.
func TestReceiptIsSignedOnceTheBindIsMeasuredAndReleasedOnceTheSandboxRuns(t *testing.T) {
	p := newPool(t)
	p.runner.gate = make(chan struct{})
	p.start(t)
	c := found(t, p)
	bound := make(chan bindAnswer, 1)
	go func() { bound <- c.post(t, c.bind, nil) }()
	// The guest has measured the bind and is preparing its sandbox.
	until(t, "the guest took its bind", func() bool { return c.phase(t) == session.PhaseBound })
	if !sessionagent.OneTimeSigningGone(c.agent) {
		t.Fatal("the guest still holds its signing key while it prepares its sandbox")
	}
	// The key a sealed message opens under stays until the sandbox is about
	// to start: one may still come.
	if sessionagent.OneTimeKEMGone(c.agent) {
		t.Fatal("the guest erased its KEM key before its sandbox was prepared")
	}
	events, err := session.ExpectedEvents(p.bundle.Launch, c.bind, session.PhaseRunning)
	if err != nil {
		t.Fatal(err)
	}
	// The register holds the bind and not yet the image the receipt names.
	measured := register(t, p.td)
	if want := replayed(p, events[:2]); !bytes.Equal(measured, want) {
		t.Fatalf("while the sandbox is prepared the register holds %x, want the launch document and the bind alone", measured)
	}
	select {
	case early := <-bound:
		t.Fatalf("the bind was answered before the sandbox ran: %d %+v", early.status, early.bound)
	default:
	}
	close(p.runner.gate)
	answer := <-bound
	if answer.status != http.StatusOK || answer.bound.Receipt == nil {
		t.Fatalf("the bind's answer: %d %+v", answer.status, answer.bound)
	}
	receipt, err := session.VerifyBindReceipt(c.boundPolicy(c.ready, c.bind), c.ready.InstanceKey, c.ready.OneTime, c.bind, answer.bound.Receipt)
	if err != nil {
		t.Fatalf("the receipt: %v", err)
	}
	// What it names is what the register holds now, the image included.
	if !slices.Equal(receipt.Events, events[1:]) || len(events) != 3 {
		t.Fatalf("the receipt names %v, want %v", receipt.Events, events[1:])
	}
	if got := register(t, p.td); !bytes.Equal(got, replayed(p, events)) || bytes.Equal(got, measured) {
		t.Fatalf("once the sandbox runs the register holds %x, want every event the receipt names", got)
	}
}

// A guest that signed its receipt and then could not admit its sandbox ends,
// and its receipt with it: the bind's sender is told the bind failed, and
// nothing else.
func TestReceiptOfAGuestThatAdmitsNoSandboxIsNeverReleased(t *testing.T) {
	p := newPool(t)
	p.runner.fail = errors.New("the image does not unpack")
	p.start(t)
	c := found(t, p)
	request, err := json.Marshal(session.BindRequest{Bind: c.bind.Raw, Signature: c.bind.Signature})
	if err != nil {
		t.Fatal(err)
	}
	client := insecureClient()
	defer client.CloseIdleConnections()
	resp, err := client.Post(c.url+session.PathBind, "application/json", bytes.NewReader(request))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == http.StatusOK || refusalCode(body) != disclosure.BindFailed {
		t.Fatalf("a guest that admitted no sandbox answered its bind with %d %s", resp.StatusCode, body)
	}
	if !sessionagent.OneTimeSigningGone(c.agent) {
		t.Fatal("the guest did not sign: its signing key is still there")
	}
	if err := p.fatal(t); err == nil {
		t.Fatal("the guest carries on")
	}
}

// The sandbox is not started while the collection that erases what the
// one-time keys left is still on its way: the agent waits for it, however
// long it takes, and starts the sandbox once it is done.
func TestSandboxStartWaitsForTheCollection(t *testing.T) {
	p := newPool(t)
	p.runner.gate = make(chan struct{})
	p.runner.starting, p.runner.started = make(chan struct{}), make(chan struct{})
	p.start(t)
	c := found(t, p)
	release := sessionagent.HoldCollections(c.agent)
	bound := make(chan bindAnswer, 1)
	go func() { bound <- c.post(t, c.bind, nil) }()
	// The receipt is signed and the key gone, and the collection that began
	// then is on its way, beside the sandbox's preparation.
	until(t, "the collection began", func() bool { return sessionagent.OneTimeCollecting(c.agent) == 1 })
	if !sessionagent.OneTimeSigningGone(c.agent) {
		t.Fatal("a collection began before the receipt was signed")
	}
	// The guest gets everything else done, and waits for it.
	close(p.runner.gate)
	select {
	case <-p.runner.starting:
		t.Fatal("the sandbox was started before what the one-time keys left was collected")
	case <-time.After(150 * time.Millisecond):
	}
	if sessionagent.OneTimeKeysErased(c.agent) {
		t.Fatal("a collection that is held reads as done")
	}
	release()
	select {
	case <-p.runner.starting:
	case <-time.After(10 * time.Second):
		t.Fatal("the sandbox was never started")
	}
	if !sessionagent.OneTimeKeysErased(c.agent) {
		t.Fatal("the sandbox is started, and the collection is not done")
	}
	close(p.runner.started)
	if answer := <-bound; answer.status != http.StatusOK {
		t.Fatalf("the bind's answer: %d", answer.status)
	}
}
