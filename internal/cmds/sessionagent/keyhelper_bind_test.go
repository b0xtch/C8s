package sessionagent_test

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// newHelped is a pool whose guest holds its one-time keys in a key helper,
// as a real guest does.
func newHelped(t *testing.T) *pool {
	t.Helper()
	p := newPool(t)
	sessionagent.HoldKeysInHelper(&p.cfg)
	return p
}

// A guest's one-time keys live in its key helper. The helper signs the
// guest's receipt and opens its sealed message, and is gone before the
// sandbox is started: by then nothing of the keys is left anywhere, and the
// agent has run no collection for them, having never held them.
func TestKeyHelperIsGoneBeforeTheSandboxStarts(t *testing.T) {
	p := newHelped(t)
	p.start(t)
	c := found(t, p)
	if !sessionagent.KeysInHelper(c.agent) {
		t.Fatal("the guest holds its one-time keys itself")
	}
	c.runner.starting, c.runner.started = make(chan struct{}), make(chan struct{})
	var erased atomic.Bool
	c.runner.onStart = func() { erased.Store(sessionagent.OneTimeKeysErased(c.agent)) }
	if sessionagent.OneTimeKeysGone(c.agent) {
		t.Fatal("the helper of a guest nobody has bound is gone")
	}
	message := c.seal(t, c.access, c.bind, true)
	first := make(chan bindAnswer, 1)
	go func() { first <- c.post(t, c.bind, message.Sealed) }()
	select {
	case <-c.runner.starting:
	case <-time.After(10 * time.Second):
		t.Fatal("the sandbox was never started")
	}
	if !sessionagent.OneTimeKeysGone(c.agent) || !erased.Load() {
		t.Fatal("the key helper is not gone as the sandbox starts")
	}
	if n := sessionagent.OneTimeCollections(c.agent); n != 0 {
		t.Fatalf("the agent ran %d collections for keys it never held", n)
	}
	close(c.runner.started)
	answer := <-first
	if answer.status != http.StatusOK || answer.bound.Phase != session.PhaseRunning || answer.bound.Sealed != session.SealedTaken {
		t.Fatalf("the bind's answer: %d %+v", answer.status, answer.bound)
	}
	// The receipt is the helper's signature under the key the ready guest's
	// evidence bound, and the sealed answer is sealed under the secret the
	// helper handed over with the opened message.
	if _, err := session.VerifyBindReceipt(c.boundPolicy(c.ready, c.bind), c.ready.InstanceKey, c.ready.OneTime, c.bind, answer.bound.Receipt); err != nil {
		t.Fatalf("the receipt the helper signed: %v", err)
	}
	if result := ran(t, message, answer); result.ExitCode != 0 {
		t.Fatalf("the sealed command: %+v", result)
	}
}

// A helper that was asked for more than its one signature exits without an
// answer, and a guest whose helper is gone before its bind ends: it could
// sign no receipt.
func TestGuestEndsOverAKeyHelperAskedForMore(t *testing.T) {
	p := newHelped(t)
	p.start(t)
	c := found(t, p)
	if err := sessionagent.AskKeyHelperTwice(c.agent); err != nil {
		t.Fatalf("the first signature: %v", err)
	}
	if err := sessionagent.AskKeyHelperTwice(c.agent); err == nil {
		t.Fatal("the key helper signed twice")
	}
	if err := p.fatal(t); err == nil || !strings.Contains(err.Error(), "key helper") {
		t.Fatalf("the guest ended with: %v", err)
	}
}

// A helper that dies under a guest nobody has bound ends the guest.
func TestGuestEndsWhenItsKeyHelperDies(t *testing.T) {
	p := newHelped(t)
	p.start(t)
	sessionagent.EndKeyHelper(p.agent)
	if err := p.fatal(t); err == nil || !strings.Contains(err.Error(), "key helper") {
		t.Fatalf("the guest ended with: %v", err)
	}
}
