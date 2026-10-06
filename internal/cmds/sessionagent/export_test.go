package sessionagent

import (
	"context"
	"crypto/ecdsa"
	"log/slog"
	"net"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// RecordStep is what a runner calls to report a step of an admission.
var RecordStep = recordStep

// SetBindQuotePauses has a guest that could not take its bind's quote wait
// these long before each further attempt, until the test ends.
func SetBindQuotePauses(t interface{ Cleanup(func()) }, pauses ...time.Duration) {
	before := bindQuotePauses
	bindQuotePauses = pauses
	t.Cleanup(func() { bindQuotePauses = before })
}

// SetSandboxEndMargin has a guest whose sandbox has ended give what it owes
// this long beyond the pauses of its bind's quote, until the test ends.
func SetSandboxEndMargin(t interface{ Cleanup(func()) }, margin time.Duration) {
	before := sandboxEndMargin
	sandboxEndMargin = margin
	t.Cleanup(func() { sandboxEndMargin = before })
}

// AdmissionOf is how long the agent's sandbox took to admit, step by step.
func AdmissionOf(a *Agent) []session.AdmissionStep {
	a.measured.RLock()
	defer a.measured.RUnlock()
	return a.admission
}

// EndedConnContext is the context of a request on a connection the agent's
// fence has ended but that is still open: one whose request was on its way
// when the fence closed it.
func EndedConnContext(ctx context.Context, a *Agent) context.Context {
	a.fence.mu.Lock()
	defer a.fence.mu.Unlock()
	return context.WithValue(ctx, fenceConnKey{}, &fencedConn{fence: &a.fence, epoch: a.fence.epoch - 1})
}

// The bounds on streams to the sandbox's ports.
const (
	MaxForwards        = maxForwards
	MaxForwardsPerKey  = maxForwardsPerKey
	MaxInflightRequest = maxInflightRequests
)

// NewTestMemory is a Memory over a test's own meminfo and knob, which starts
// on the rest as soon as it is asked to.
func NewTestMemory(reserveMB int, rest bool, read func() ([]byte, error), accept func(megabytes int) error) *Memory {
	return &Memory{
		ReserveMB: reserveMB, Rest: rest, Logger: slog.New(slog.DiscardHandler),
		read: read, accept: accept,
		after: func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil },
		idle:  func() error { return nil },
	}
}

// OneTimeKeysGone reports whether the guest has erased both of its one-time
// keys.
func OneTimeKeysGone(a *Agent) bool { return a.oneTime.gone() }

// OneTimeKeysErased reports whether the guest has erased both of its
// one-time keys and collected what work on them left on its heap.
func OneTimeKeysErased(a *Agent) bool { return a.oneTime.erased() }

// HoldCollections has every collection of what the guest's one-time keys
// left wait until the returned function is called.
func HoldCollections(a *Agent) (release func()) {
	hold := make(chan struct{})
	a.oneTime.mu.Lock()
	a.oneTime.hold = hold
	a.oneTime.mu.Unlock()
	return func() { close(hold) }
}

// OneTimeCollecting is how many collections of what the guest's one-time
// keys left are on their way.
func OneTimeCollecting(a *Agent) int {
	a.oneTime.mu.Lock()
	defer a.oneTime.mu.Unlock()
	return a.oneTime.collecting
}

// OneTimeCollections is how many collections of what the guest's one-time
// keys left have run since the guest made the keys.
func OneTimeCollections(a *Agent) int {
	a.oneTime.mu.Lock()
	defer a.oneTime.mu.Unlock()
	return a.oneTime.collected
}

// pipeKeyHelper is a key helper that runs in this process, at the other end
// of a pipe: the helper's own code and the agent's, without the process
// between them.
func pipeKeyHelper() (*keyHelper, error) {
	ours, theirs := net.Pipe()
	done := make(chan error, 1)
	go func() {
		err := serveKeys(theirs)
		_ = theirs.Close()
		done <- err
	}()
	return newKeyHelper(ours, func() error { return <-done }), nil
}

// HoldKeysInHelper has an agent staged from cfg hold its one-time keys in a
// key helper, as a guest's does, with the helper in this process.
func HoldKeysInHelper(cfg *Config) { cfg.keyHelper = pipeKeyHelper }

// KeysInHelper reports whether the guest's one-time keys are a helper's.
func KeysInHelper(a *Agent) bool { return a.oneTime.helper != nil }

// KeyHelperPID is the process of the guest's key helper, or 0 where the
// helper is none.
func KeyHelperPID(a *Agent) int { return a.oneTime.helper.pid }

// AskKeyHelperTwice has the guest's key helper asked to sign once more than
// the agent asks it, as nothing of the agent's does.
func AskKeyHelperTwice(a *Agent) error {
	h := a.oneTime.helper
	_, err := h.exchange(helperSign, [][]byte{[]byte("once more")}, helperSigned, 64)
	return err
}

// EndKeyHelper ends the guest's key helper under its agent, as a helper that
// died would end.
func EndKeyHelper(a *Agent) {
	h := a.oneTime.helper
	h.mu.Lock()
	conn := h.conn
	h.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

// OneTimeSigningGone reports whether the guest has erased its one-time
// signing key.
func OneTimeSigningGone(a *Agent) bool {
	if h := a.oneTime.helper; h != nil {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.signed
	}
	a.oneTime.mu.Lock()
	defer a.oneTime.mu.Unlock()
	return a.oneTime.signing == nil
}

// OneTimeKEMGone reports whether the guest has erased its one-time KEM key.
func OneTimeKEMGone(a *Agent) bool {
	if h := a.oneTime.helper; h != nil {
		return h.kemGone()
	}
	a.oneTime.mu.Lock()
	defer a.oneTime.mu.Unlock()
	return a.oneTime.kem == nil
}

// SealedState is what became of the guest's sealed message so far: empty
// while one may still come.
func SealedState(a *Agent) string {
	a.sealed.mu.Lock()
	defer a.sealed.mu.Unlock()
	return a.sealed.state
}

// PutSealedCredential is what the guest makes of one sealed credential, for
// a bind that grants granted its credentials and declares declared.
func PutSealedCredential(a *Agent, c *session.OpenedCredential, granted []*ecdsa.PublicKey, declared []session.Credential) string {
	return a.putSealedCredential(c, granted, declared)
}
