package daemon_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sessionv1alpha1 "github.com/confidential-dot-ai/c8s/api/session/v1alpha1"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/daemon"
)

// binding is a daemon that answers a bind with what a test lines up: the
// first answer, then each later message as the test lets it go, and then
// the call's end.
type binding struct {
	sessionv1alpha1.UnimplementedSessionsServer
	first *sessionv1alpha1.Bound
	later chan *sessionv1alpha1.Bound
	// ending is what the call ends with once later is closed.
	ending error
}

func (b *binding) Bind(stream sessionv1alpha1.Sessions_BindServer) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}
	if err := stream.Send(b.first); err != nil {
		return err
	}
	for {
		select {
		case next, more := <-b.later:
			if !more {
				return b.ending
			}
			if err := stream.Send(next); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return nil
		}
	}
}

// What a daemon sends after a bind's answer comes in the order the guest
// had it, and each part is told to whoever waits for it as it comes: the
// sealed answer of a sealed message, and the guest's evidence with the quote
// over the bind's nonce. A guest that says it gave up on the quote, and a
// call that ends with no word of one, each have their binder ask for an
// attestation itself, and are told apart.
func TestBindCallBringsWhatFollowsItsAnswer(t *testing.T) {
	within := func(d time.Duration) context.Context {
		ctx, cancel := context.WithTimeout(context.Background(), d)
		t.Cleanup(cancel)
		return ctx
	}
	bind := &session.SignedBind{Raw: []byte("bind"), Signature: "signature"}
	receipted := &sessionv1alpha1.Bound{Evidence: &sessionv1alpha1.Evidence{Phase: "running"}, SealedStatus: session.SealedTaken}
	quote := &sessionv1alpha1.Bound{Evidence: &sessionv1alpha1.Evidence{Phase: "running", BindQuote: session.BindQuoteTaken, Quote: []byte(`{"platform":"tdx"}`)}}
	sealed := &sessionv1alpha1.Bound{SealedStatus: session.SealedTaken, SealedAnswer: []byte("sealed answer")}
	gaveUp := &sessionv1alpha1.Bound{Evidence: &sessionv1alpha1.Evidence{Phase: "running", BindQuote: session.BindQuoteGivenUp}}
	called := func(t *testing.T, api *binding) *daemon.BindCall {
		t.Helper()
		call, err := serveAPI(t, api).BindWith(within(20*time.Second), "request-1", "td-1", bind, []byte("sealed message"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(call.Close)
		return call
	}
	answered := func(t *testing.T, call *daemon.BindCall) {
		t.Helper()
		if answer, said, err := call.SealedAnswer(); err != nil || said != session.SealedTaken || string(answer) != "sealed answer" {
			t.Fatalf("the sealed answer: %q, %q, %v", answer, said, err)
		}
	}

	t.Run("the quote before the sealed answer", func(t *testing.T) {
		api := &binding{first: receipted, later: make(chan *sessionv1alpha1.Bound, 2)}
		call := called(t, api)
		// Neither has come: a wait for the quote ends with its context.
		if quoted, err := call.Quote(within(50 * time.Millisecond)); quoted != nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("a wait for a quote that has not come: %+v, %v", quoted, err)
		}
		api.later <- quote
		quoted, err := call.Quote(within(20 * time.Second))
		if err != nil || string(quoted.Evidence) != `{"platform":"tdx"}` || quoted.BindQuote != session.BindQuoteTaken {
			t.Fatalf("the quote: %+v, %v", quoted, err)
		}
		api.later <- sealed
		answered(t, call)
		close(api.later)
	})
	t.Run("the sealed answer before the quote", func(t *testing.T) {
		api := &binding{first: receipted, later: make(chan *sessionv1alpha1.Bound, 2)}
		call := called(t, api)
		api.later <- sealed
		answered(t, call)
		api.later <- quote
		if quoted, err := call.Quote(within(20 * time.Second)); err != nil || len(quoted.Evidence) == 0 {
			t.Fatalf("the quote after the sealed answer: %+v, %v", quoted, err)
		}
		close(api.later)
	})
	t.Run("a guest that gave up on its quote", func(t *testing.T) {
		api := &binding{first: receipted, later: make(chan *sessionv1alpha1.Bound, 2)}
		call := called(t, api)
		api.later <- gaveUp
		close(api.later)
		if quoted, err := call.Quote(within(20 * time.Second)); quoted != nil || !errors.Is(err, session.ErrNoBindQuote) || errors.Is(err, daemon.ErrQuoteNotSent) {
			t.Fatalf("a guest that gave up: %+v, %v", quoted, err)
		}
		// No sealed answer came either, and the call ended: too late.
		if answer, said, err := call.SealedAnswer(); err != nil || said != session.SealedTooLate || answer != nil {
			t.Fatalf("the sealed answer of a call that ended without it: %q, %q, %v", answer, said, err)
		}
	})
	t.Run("a call that ends with no word of the quote", func(t *testing.T) {
		api := &binding{first: receipted, later: make(chan *sessionv1alpha1.Bound, 1)}
		call := called(t, api)
		api.later <- sealed
		close(api.later)
		answered(t, call)
		if quoted, err := call.Quote(within(20 * time.Second)); quoted != nil || !errors.Is(err, daemon.ErrQuoteNotSent) || errors.Is(err, session.ErrNoBindQuote) {
			t.Fatalf("a call that ended without a quote: %+v, %v", quoted, err)
		}
	})
	t.Run("a call that breaks", func(t *testing.T) {
		api := &binding{first: receipted, later: make(chan *sessionv1alpha1.Bound), ending: status.Error(codes.Unavailable, "the guest went away")}
		call := called(t, api)
		close(api.later)
		// The wait says no quote was sent, and what ended the call.
		if _, err := call.Quote(within(20 * time.Second)); !errors.Is(err, daemon.ErrQuoteNotSent) || !strings.Contains(err.Error(), "the guest went away") {
			t.Fatalf("a call that broke before its quote: %v", err)
		}
		if _, _, err := call.SealedAnswer(); status.Code(err) != codes.Unavailable {
			t.Fatalf("the sealed answer of a call that broke: %v", err)
		}
	})
	t.Run("a quote that came with the answer", func(t *testing.T) {
		with := &sessionv1alpha1.Bound{Evidence: quote.GetEvidence(), SealedStatus: session.SealedTaken}
		api := &binding{first: with, later: make(chan *sessionv1alpha1.Bound)}
		call := called(t, api)
		// Nothing more is waited for.
		if quoted, err := call.Quote(within(20 * time.Second)); err != nil || quoted != call.Answer {
			t.Fatalf("the quote of an answer that carried it: %+v, %v", quoted, err)
		}
		close(api.later)
	})
}
