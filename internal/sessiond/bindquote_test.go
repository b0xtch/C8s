package sessiond_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// A binder waits for the quote over its bind's nonce on the bind's own
// call. The guest answers with its receipt at once, and with the sealed
// answer of a command that ended while its quoting service is still at it.
// The daemon hands on the guest's evidence with the quote as soon as the
// guest has it, and the binder holds it to the receipt. Nobody asks the
// guest what it is meanwhile: a start costs the daemon no evidence request.
func TestBindsQuoteComesOnTheBindsOwnCall(t *testing.T) {
	h := newHost(t, 1, nil)
	c, o := h.AsOrchestrator(), newOwner(t)
	s := h.seals(c, o, "s1", false)
	message := s.seal(t)
	release := s.guest.HoldQuotes()
	defer release()
	// The vendor's documents as the daemon keeps them for this guest.
	documents := []byte("the vendor's documents, as the guest handed them over")
	h.Daemon.KeepCollateral(s.td, documents)

	call, err := c.BindWith(ctx(t), requestID(t), s.td, s.bind, message.Sealed)
	if err != nil {
		t.Fatalf("the bind with its sealed message: %v", err)
	}
	defer call.Close()
	if call.Answer.Receipt == nil || len(call.Answer.Evidence) != 0 {
		t.Fatalf("the answer of a guest whose quoting service is slow: receipt %v, %d bytes of quote", call.Answer.Receipt != nil, len(call.Answer.Evidence))
	}
	// The answer carries what the bind changed, and nothing its binder holds
	// already: not the guest's certificate, its launch document or the bind,
	// and none of the vendor's documents, though the daemon keeps some.
	if a := call.Answer; len(a.Collateral)+len(a.Certificate)+len(a.Launch)+len(a.Bind)+len(a.ReadyCertificate) != 0 || a.Phase == "" {
		t.Fatalf("the answer came with %d bytes of the vendor's documents, %d of a certificate, %d of a launch document and %d of a bind, in phase %q",
			len(a.Collateral), len(a.Certificate), len(a.Launch), len(a.Bind), a.Phase)
	}
	binding := session.Binding{LaunchKey: h.LaunchKey, Launch: s.ready.Launch, Bind: s.bind}
	policy := binding.Policy(h.Identity)
	receipt, err := session.VerifyBoundReceipt(policy, s.ready, s.bind, call.Answer)
	if err != nil {
		t.Fatal(err)
	}
	// The command's answer does not wait for the quote.
	if _, opened := result(t, call, message); opened.ExitCode != 0 || s.runs(t) != 1 {
		t.Fatalf("the command's result: %+v, after %d runs", opened, s.runs(t))
	}
	// The quote is not there, and its binder waits on the call for it.
	waiting, cancel := context.WithTimeout(ctx(t), 100*time.Millisecond)
	quoted, err := call.Quote(waiting)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || quoted != nil {
		t.Fatalf("a wait for a quote the guest does not have: %+v, %v", quoted, err)
	}
	asked := s.guest.Asked(session.PathState)
	release()
	if quoted, err = call.Quote(ctx(t)); err != nil {
		t.Fatalf("the quote on the bind's call: %v", err)
	}
	// It is the quote with the events and the phase it covers, and again
	// nothing its binder holds: the binder judges it under the launch
	// document it verified the guest by, against the vendor's documents as it
	// fetched them itself.
	if quoted.BindQuote != session.BindQuoteTaken || len(quoted.Events) == 0 ||
		len(quoted.Collateral)+len(quoted.Certificate)+len(quoted.Launch)+len(quoted.Bind)+len(quoted.ReadyCertificate) != 0 {
		t.Fatalf("the evidence that came with the quote: quote said to be %q, %d events, %d bytes of the vendor's documents, %d of a certificate, %d of a launch document, %d of a bind",
			quoted.BindQuote, len(quoted.Events), len(quoted.Collateral), len(quoted.Certificate), len(quoted.Launch), len(quoted.Bind))
	}
	att, err := session.VerifyBound(ctx(t), policy, h.Engine, s.ready, s.bind, quoted)
	if err != nil {
		t.Fatalf("the quote that came on the call: %v", err)
	}
	if err := receipt.Confirmed(att); err != nil {
		t.Fatalf("the quote does not confirm the receipt: %v", err)
	}
	// Asked again it is the same evidence, and the guest was asked nothing.
	if again, err := call.Quote(ctx(t)); err != nil || again != quoted {
		t.Fatalf("the quote, asked for again: %v", err)
	}
	if n := s.guest.Asked(session.PathState) - asked; n != 0 {
		t.Fatalf("the guest was asked %d times what it is while its binder waited for the quote", n)
	}
	// The call ends once the guest has said all it will.
	if _, _, err := call.SealedAnswer(); err != nil {
		t.Fatalf("the sealed answer, asked for again: %v", err)
	}

	// A quote the guest had when it answered comes with the answer, and its
	// binder waits for nothing.
	next := h.seals(c, o, "s2", false)
	second, err := c.BindWith(ctx(t), requestID(t), next.td, next.bind, next.seal(t).Sealed)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if len(second.Answer.Evidence) == 0 {
		t.Skip("this guest's quote was not there when it answered")
	}
	if quoted, err := second.Quote(ctx(t)); err != nil || quoted != second.Answer {
		t.Fatalf("the quote of an answer that carried it: %v", err)
	}
}
