package daemon_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sessionv1alpha1 "github.com/confidential-dot-ai/c8s/api/session/v1alpha1"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// relaying is a daemon whose guest answers each evidence request with the
// next of what a test lined up, and with the last of it from then on.
type relaying struct {
	sessionv1alpha1.UnimplementedSessionsServer
	mu      sync.Mutex
	answers []*sessionv1alpha1.Evidence
	asked   int
	failing error
}

func (r *relaying) GetEvidence(context.Context, *sessionv1alpha1.EvidenceRequest) (*sessionv1alpha1.Evidence, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failing != nil {
		return nil, r.failing
	}
	answer := r.answers[min(r.asked, len(r.answers)-1)]
	r.asked++
	return answer, nil
}

func (r *relaying) requests() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.asked
}

// A binder waits for the quote its guest takes over the bind's nonce by
// asking for the guest's evidence until the quote is in it. A guest that
// says it gave up is waited for no longer, and a binder whose own patience
// ends first stops asking.
func TestBoundEvidenceWaitsForTheQuoteOrTheGuestsWord(t *testing.T) {
	trying := &sessionv1alpha1.Evidence{Phase: "running", BindQuote: session.BindQuoteTrying}
	quoted := &sessionv1alpha1.Evidence{Phase: "running", BindQuote: session.BindQuoteTaken, Quote: []byte(`{"platform":"tdx"}`), Events: []string{"a", "b"}}
	gaveUp := &sessionv1alpha1.Evidence{Phase: "running", BindQuote: session.BindQuoteGivenUp}
	within := func(d time.Duration) context.Context {
		ctx, cancel := context.WithTimeout(context.Background(), d)
		t.Cleanup(cancel)
		return ctx
	}

	guest := &relaying{answers: []*sessionv1alpha1.Evidence{trying, trying, trying, quoted}}
	evidence, err := serveAPI(t, guest).BoundEvidence(within(20*time.Second), "td-1")
	if err != nil || string(evidence.Evidence) != `{"platform":"tdx"}` || evidence.BindQuote != session.BindQuoteTaken || len(evidence.Events) != 2 {
		t.Fatalf("the evidence with the quote: %+v, %v", evidence, err)
	}
	if guest.requests() != 4 {
		t.Fatalf("the guest was asked %d times, want once for each answer until the quote", guest.requests())
	}

	guest = &relaying{answers: []*sessionv1alpha1.Evidence{trying, gaveUp}}
	began := time.Now()
	evidence, err = serveAPI(t, guest).BoundEvidence(within(20*time.Second), "td-1")
	if !errors.Is(err, session.ErrNoBindQuote) || evidence != nil {
		t.Fatalf("a guest that gave up: %+v, %v", evidence, err)
	}
	if guest.requests() != 2 || time.Since(began) > 10*time.Second {
		t.Fatalf("a guest that gave up was asked %d times over %s", guest.requests(), time.Since(began))
	}

	// A guest that goes on trying, and one of an image that does not say:
	// the binder's patience decides.
	for name, answer := range map[string]*sessionv1alpha1.Evidence{"still trying": trying, "says nothing": {Phase: "running"}} {
		guest = &relaying{answers: []*sessionv1alpha1.Evidence{answer}}
		evidence, err = serveAPI(t, guest).BoundEvidence(within(300*time.Millisecond), "td-1")
		if evidence != nil || err == nil || errors.Is(err, session.ErrNoBindQuote) {
			t.Fatalf("%s: %+v, %v, want the wait to end with its context", name, evidence, err)
		}
		if guest.requests() < 3 {
			t.Fatalf("%s: the guest was asked %d times in the wait", name, guest.requests())
		}
	}

	// What the daemon refuses, it refuses once.
	guest = &relaying{failing: status.Error(codes.NotFound, "no such TD")}
	if _, err := serveAPI(t, guest).BoundEvidence(within(20*time.Second), "td-9"); status.Code(err) != codes.NotFound {
		t.Fatalf("a TD the daemon does not know: %v", err)
	}
}
