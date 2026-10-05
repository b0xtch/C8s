package sessiond_test

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// The daemon has so many evidence requests of one caller in flight at once.
// One more is refused as one to ask again, with nothing sent to a guest, and
// another caller is served meanwhile. A caller that waits for a bind's quote
// by asking for its guest's evidence asks again until it has room.
func TestCallerWithTooManyEvidenceRequestsAsksAgain(t *testing.T) {
	h := newHost(t, 1, nil)
	c, o := h.AsOrchestrator(), newOwner(t)
	s := h.seals(c, o, "s1", false)
	if _, err := c.Bind(ctx(t), requestID(t), s.td, s.bind); err != nil {
		t.Fatal(err)
	}
	if _, err := c.BoundEvidence(ctx(t), s.td); err != nil {
		t.Fatalf("the bound guest's evidence: %v", err)
	}
	leaf, err := x509.ParseCertificate(h.Orchestrator.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	release := h.Daemon.HoldEvidenceRelays(leaf.PublicKey)
	defer release()
	asked := s.guest.Asked(session.PathState)
	if _, err := c.Evidence(ctx(t), s.td); status.Code(err) != codes.ResourceExhausted || !strings.Contains(err.Error(), "ask again") {
		t.Fatalf("one request more than a caller has in flight at once: %v", err)
	}
	if n := s.guest.Asked(session.PathState) - asked; n != 0 {
		t.Fatalf("the guest was asked %d times for a request the daemon refused", n)
	}
	// Whoever asks about a TD that is not there is told so, room or none.
	if _, err := c.Evidence(ctx(t), "td-none"); status.Code(err) != codes.NotFound {
		t.Fatalf("evidence of a TD the daemon does not know: %v", err)
	}
	// A caller the daemon knows by its address has places of its own.
	if evidence, err := h.Client(nil).Evidence(ctx(t), s.td); err != nil || len(evidence.Evidence) == 0 {
		t.Fatalf("another caller's request while the first has no room: %v", err)
	}
	waiting, cancel := context.WithTimeout(ctx(t), 100*time.Millisecond)
	_, err = c.BoundEvidence(waiting, s.td)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a wait for evidence the daemon has no room for: %v", err)
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		release()
	}()
	if evidence, err := c.BoundEvidence(ctx(t), s.td); err != nil || len(evidence.Evidence) == 0 {
		t.Fatalf("the evidence once there was room: %v", err)
	}
}
