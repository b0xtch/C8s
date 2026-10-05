package sessionagent_test

import (
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// A guest holds its one-time keys for as long as it is nobody's, and has
// erased both by the time its sandbox is started: nothing of the tenant runs
// in a guest that could still sign a receipt or open a command sealed to it.
func TestOneTimeKeysAreGoneBeforeTheSandboxStarts(t *testing.T) {
	p := newPool(t)
	p.runner.starting, p.runner.started = make(chan struct{}), make(chan struct{})
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
	// The runtime has been told to start the sandbox and has not yet.
	if !sessionagent.OneTimeKeysGone(p.agent) {
		t.Fatal("the guest still holds a one-time key as its sandbox starts")
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
