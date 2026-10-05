package sessionagent

import (
	"context"
	"log/slog"
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

// OneTimeKEMGone reports whether the guest has erased its one-time KEM key.
func OneTimeKEMGone(a *Agent) bool {
	a.oneTime.mu.Lock()
	defer a.oneTime.mu.Unlock()
	return a.oneTime.kem == nil
}

// CommandState is what became of the guest's first command so far: empty
// while one may still come.
func CommandState(a *Agent) string {
	a.command.mu.Lock()
	defer a.command.mu.Unlock()
	return a.command.state
}
