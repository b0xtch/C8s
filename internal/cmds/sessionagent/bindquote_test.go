package sessionagent_test

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// answering is a bind's answer as its caller reads it, a document at a time.
type answering struct {
	t         *testing.T
	documents *json.Decoder
}

// reads posts bind to the guest, with sealed if it is not nil, as a caller
// that reads the answer to its end when follows is set, and returns the
// answer once its first document is there.
func (c *sealing) reads(t *testing.T, bind *session.SignedBind, sealed []byte, follows bool) (*answering, session.BindResponse) {
	t.Helper()
	body, err := json.Marshal(session.BindRequest{Bind: bind.Raw, Signature: bind.Signature, Sealed: sealed})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(ctxT(t), http.MethodPost, c.url+session.PathBind, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if follows {
		req.Header.Set(session.BindQuoteHeader, session.BindQuoteFollows)
	}
	client := insecureClient()
	t.Cleanup(client.CloseIdleConnections)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the bind was answered HTTP %d", resp.StatusCode)
	}
	a := &answering{t: t, documents: json.NewDecoder(resp.Body)}
	var first session.BindResponse
	if err := a.documents.Decode(&first); err != nil {
		t.Fatalf("the answer to the bind: %v", err)
	}
	return a, first
}

// next is the answer's next document: the guest's sealed answer, its state,
// or neither when the guest has said all it will.
func (a *answering) next() (*session.SealedReply, *session.StateResponse) {
	a.t.Helper()
	var raw json.RawMessage
	if err := a.documents.Decode(&raw); err != nil {
		if !errors.Is(err, io.EOF) {
			a.t.Fatalf("what follows the answer to a bind: %v", err)
		}
		return nil, nil
	}
	var kind struct {
		Sealed string `json:"sealed"`
	}
	if err := json.Unmarshal(raw, &kind); err != nil {
		a.t.Fatal(err)
	}
	if kind.Sealed != "" {
		var reply session.SealedReply
		if err := json.Unmarshal(raw, &reply); err != nil {
			a.t.Fatal(err)
		}
		return &reply, nil
	}
	var state session.StateResponse
	if err := json.Unmarshal(raw, &state); err != nil || state.Phase == "" {
		a.t.Fatalf("a document that is neither a sealed answer nor the guest's state: %s (%v)", raw, err)
	}
	return nil, &state
}

// ended requires that the guest has said all it will.
func (a *answering) ended(what string) {
	a.t.Helper()
	if reply, state := a.next(); reply != nil || state != nil {
		a.t.Fatalf("%s: the guest said more: a sealed answer %v, its state %v", what, reply != nil, state != nil)
	}
}

// A caller that reads a bind's answer on is sent the guest's state on it as
// soon as the quote over the bind's nonce is taken, so that it waits for
// that quote on its own call and asks nobody. The state is the one the guest
// serves to anyone: it says the quote is taken and carries it, and the quote
// confirms the receipt. It comes when the guest has it, before the sealed
// answer of a command that still runs.
func TestBindsQuoteFollowsItsReceiptBeforeACommandThatStillRuns(t *testing.T) {
	p, tee, _ := quoted(t)
	c := found(t, p)
	// A first command that ends when the test lets it.
	gate := filepath.Join(t.TempDir(), "go")
	message, err := session.SealWithBind(c.ready, c.bind, p.access, session.SealedParts{Command: &session.ExecRequest{
		Argv: []string{"/bin/sh", "-c", `until [ -e "$GATE" ]; do sleep 0.01; done; echo done`}, Env: map[string]string{"GATE": gate},
	}})
	if err != nil {
		t.Fatal(err)
	}
	release := tee.hold()
	defer release()
	answer, first := c.reads(t, c.bind, message.Sealed, true)
	if first.Receipt == nil || first.Attestation != nil || first.Sealed != session.SealedTaken {
		t.Fatalf("the bind's answer while the quoting service is slow: %+v", first)
	}
	bound := p.boundPolicy(c.ready, c.bind)
	receipt, err := session.VerifyBindReceipt(bound, c.ready.InstanceKey, c.ready.OneTime, c.bind, first.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	release()
	reply, state := answer.next()
	if reply != nil || state == nil {
		t.Fatal("the command still runs, and what followed the receipt was not the guest's state")
	}
	if state.BindQuote != session.BindQuoteTaken || state.Attestation == nil || state.Phase != session.PhaseRunning {
		t.Fatalf("the state that followed the receipt: quote %q, carried %v, phase %s", state.BindQuote, state.Attestation != nil, state.Phase)
	}
	att, err := session.VerifyAttestation(ctxT(t), bound, sessiontest.Engine{}, c.ready.InstanceKey, c.bind.Doc.EvidenceNonce(), state.Attestation)
	if err != nil {
		t.Fatalf("the quote that followed the receipt: %v", err)
	}
	if err := receipt.Confirmed(att); err != nil {
		t.Fatalf("the quote does not confirm the receipt: %v", err)
	}
	// It is what the guest serves to anyone who asks.
	if served := p.state(t); served.BindQuote != state.BindQuote || !bytes.Equal(served.Attestation.Evidence.Evidence, state.Attestation.Evidence.Evidence) {
		t.Fatal("the state on the bind's answer is not the state the guest serves")
	}
	if err := os.WriteFile(gate, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	reply, state = answer.next()
	if state != nil || reply == nil || reply.Sealed != session.SealedTaken {
		t.Fatalf("the sealed answer after the command ended: %+v", reply)
	}
	said, err := message.Open(reply.Answer)
	if err != nil || said.Command == nil || string(said.Command.Stdout) != "done\n" {
		t.Fatalf("the command's answer: %+v, %v", said, err)
	}
	answer.ended("after the quote and the sealed answer")
}

// The sealed answer of a command that ended does not wait for a quote the
// quoting service still holds: it follows the receipt at once, and the
// guest's state follows it when the quote is there.
func TestBindsSealedAnswerDoesNotWaitForItsQuote(t *testing.T) {
	p, tee, _ := quoted(t)
	c := found(t, p)
	release := tee.hold()
	defer release()
	message := c.seal(t, p.access, c.bind, true)
	answer, first := c.reads(t, c.bind, message.Sealed, true)
	if first.Receipt == nil || first.Attestation != nil || first.Sealed != session.SealedTaken {
		t.Fatalf("the bind's answer while the quoting service is slow: %+v", first)
	}
	reply, state := answer.next()
	if state != nil || reply == nil || reply.Sealed != session.SealedTaken {
		t.Fatal("the quote is not there, and what followed the receipt was not the command's sealed answer")
	}
	if said, err := message.Open(reply.Answer); err != nil || said.Command == nil {
		t.Fatalf("the command's answer: %+v, %v", said, err)
	}
	release()
	if reply, state = answer.next(); reply != nil || state == nil || state.BindQuote != session.BindQuoteTaken || state.Attestation == nil {
		t.Fatalf("the state that followed the sealed answer: %+v", state)
	}
	answer.ended("after the sealed answer and the quote")
}

// A guest whose quoting service gives it no quote says so on the bind's
// answer once it has given up, which is how its caller learns that it must
// ask for an attestation itself. That word and the sealed answer come in the
// order the guest has them, and nothing follows the two.
func TestBindsAnswerSaysWhenItsGuestGaveUpOnTheQuote(t *testing.T) {
	sessionagent.SetBindQuotePauses(t, 20*time.Millisecond, 20*time.Millisecond)
	p, tee, _ := quoted(t)
	c := found(t, p)
	events, err := session.ExpectedEvents(c.ready.Launch, c.bind, session.PhaseRunning)
	if err != nil {
		t.Fatal(err)
	}
	over, err := session.ReportData(c.ready.InstanceKey.(*ecdsa.PublicKey), c.bind.Doc.EvidenceNonce(), events)
	if err != nil {
		t.Fatal(err)
	}
	tee.failFor(over)
	message := c.seal(t, p.access, c.bind, true)
	answer, first := c.reads(t, c.bind, message.Sealed, true)
	if first.Receipt == nil || first.Attestation != nil || first.Sealed != session.SealedTaken {
		t.Fatalf("the bind's answer: %+v", first)
	}
	var reply *session.SealedReply
	var state *session.StateResponse
	for range 2 {
		sealed, said := answer.next()
		if sealed != nil {
			reply = sealed
		}
		if said != nil {
			state = said
		}
	}
	if reply == nil || reply.Sealed != session.SealedTaken {
		t.Fatalf("the sealed answer of the command that ran: %+v", reply)
	}
	if state == nil || state.BindQuote != session.BindQuoteGivenUp || state.Attestation != nil {
		t.Fatalf("the state of a guest that gave up on its quote: %+v", state)
	}
	answer.ended("after the guest gave up")
}

// A caller that does not say it reads on is sent no state: one that hands a
// guest its bind over a connection of its own reads the receipt, at most a
// sealed answer after it, and no further. A guest that had the quote when it
// answered sends it with the receipt and no state after it, to either kind
// of caller.
func TestBindsAnswerCarriesNoStateForACallerThatDoesNotReadOn(t *testing.T) {
	for name, follows := range map[string]bool{"a caller that reads on": true, "a caller that does not": false} {
		t.Run("the quote with the receipt, "+name, func(t *testing.T) {
			c := newSealing(t)
			answer, first := c.reads(t, c.bind, c.seal(t, c.access, c.bind, false).Sealed, follows)
			if first.Receipt == nil || first.Sealed != session.SealedTaken {
				t.Fatalf("the bind's answer: %+v", first)
			}
			if first.Attestation == nil {
				t.Skip("this guest's quote was not there when it answered")
			}
			if reply, state := answer.next(); reply == nil || state != nil {
				t.Fatal("what followed the receipt and its quote was not the sealed answer")
			}
			answer.ended("after the sealed answer")
		})
	}
	t.Run("the quote after the receipt", func(t *testing.T) {
		p, tee, _ := quoted(t)
		c := found(t, p)
		release := tee.hold()
		defer release()
		answer, first := c.reads(t, c.bind, c.seal(t, p.access, c.bind, false).Sealed, false)
		if first.Receipt == nil || first.Attestation != nil || first.Sealed != session.SealedTaken {
			t.Fatalf("the bind's answer while the quoting service is slow: %+v", first)
		}
		if reply, state := answer.next(); reply == nil || state != nil {
			t.Fatal("what followed the receipt was not the sealed answer")
		}
		answer.ended("with the quote still to come")
		release()
		// The quote is in the state the guest serves, as before.
		for deadline := time.Now().Add(5 * time.Second); p.state(t).BindQuote != session.BindQuoteTaken; time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("the guest's state never served the quote over the bind's nonce")
			}
		}
	})
}
