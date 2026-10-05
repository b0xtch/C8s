package sessionagent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/disclosure"
)

// commanded is a pool guest whose owner sends the session's first command
// with its bind: the guest as its owner found it ready, the bind for it, and
// a file the command leaves a line in each time it runs.
type commanded struct {
	*pool
	ready  *session.ReadyTD
	bind   *session.SignedBind
	marker string
}

func newCommanded(t *testing.T) *commanded {
	t.Helper()
	p := newPool(t)
	p.start(t)
	return found(t, p)
}

// found is the owner finding p's guest ready and writing its bind.
func found(t *testing.T, p *pool) *commanded {
	t.Helper()
	ready, err := p.client(t, p.access).Ready(ctxT(t))
	if err != nil {
		t.Fatalf("Ready: %v", err)
	}
	return &commanded{pool: p, ready: ready, bind: p.bindFor(t, ready, nil), marker: filepath.Join(t.TempDir(), "ran")}
}

// request is a command that says it ran: a line in the marker, and what it
// was given on its standard input back.
func (c *commanded) request() session.ExecRequest {
	return session.ExecRequest{
		Argv:  []string{"/bin/sh", "-c", `echo ran >> "$MARKER"; cat`},
		Env:   map[string]string{"MARKER": c.marker},
		Stdin: []byte("first"),
	}
}

func (c *commanded) seal(t *testing.T, auth operatorauth.AudienceAuthorizer, bind *session.SignedBind) *session.FirstCommand {
	t.Helper()
	command, err := session.SealFirstCommand(c.ready, bind, auth, c.request())
	if err != nil {
		t.Fatalf("SealFirstCommand: %v", err)
	}
	return command
}

// runs is how many times the command ran.
func (c *commanded) runs(t *testing.T) int {
	t.Helper()
	data, err := os.ReadFile(c.marker)
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(data), "ran\n")
}

// bindAnswer is a guest's answer to a bind as it arrives: the answer to the
// bind, and the document that follows it for a command the guest took.
type bindAnswer struct {
	status  int
	bound   session.BindResponse
	command *session.CommandAnswer
}

// post sends the bind with a sealed command, as a stranger on the network
// could, and reads all the guest answers.
func (c *commanded) post(t *testing.T, bind *session.SignedBind, sealed []byte) bindAnswer {
	t.Helper()
	body, err := json.Marshal(session.BindRequest{Bind: bind.Raw, Signature: bind.Signature, Command: sealed})
	if err != nil {
		t.Fatal(err)
	}
	return c.answered(t, session.PathBind, body)
}

// late sends a command after its bind.
func (c *commanded) late(t *testing.T, sealed []byte) bindAnswer {
	t.Helper()
	body, err := json.Marshal(session.CommandRequest{Command: sealed})
	if err != nil {
		t.Fatal(err)
	}
	return c.answered(t, session.PathBindCommand, body)
}

func (c *commanded) answered(t *testing.T, path string, body []byte) bindAnswer {
	t.Helper()
	req, err := http.NewRequestWithContext(ctxT(t), http.MethodPost, c.url+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	client := insecureClient()
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := bindAnswer{status: resp.StatusCode}
	if resp.StatusCode != http.StatusOK {
		return out
	}
	documents := json.NewDecoder(resp.Body)
	if path == session.PathBindCommand {
		out.command = &session.CommandAnswer{}
		if err := documents.Decode(out.command); err != nil {
			t.Fatalf("the answer to a command: %v", err)
		}
	} else {
		if err := documents.Decode(&out.bound); err != nil {
			t.Fatalf("the answer to a bind: %v", err)
		}
		var next session.CommandAnswer
		switch err := documents.Decode(&next); {
		case err == nil:
			out.command = &next
		case !errors.Is(err, io.EOF):
			t.Fatalf("what follows the answer to a bind: %v", err)
		}
	}
	if documents.More() {
		t.Fatal("the guest answered with more documents than it has")
	}
	return out
}

// phase is the phase the guest says it is in, or none when it did not
// answer: a bind that arrives ends the connections from before it, one that
// asks for the guest's state among them.
func (c *commanded) phase(t *testing.T) session.Phase {
	t.Helper()
	req, err := http.NewRequestWithContext(ctxT(t), http.MethodGet, c.url+session.PathState, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := insecureClient()
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var state session.StateResponse
	if json.NewDecoder(resp.Body).Decode(&state) != nil {
		return ""
	}
	return state.Phase
}

// opened is the result of a command the guest took and ran.
func opened(t *testing.T, command *session.FirstCommand, answer bindAnswer) *session.ExecResponse {
	t.Helper()
	if answer.command == nil || answer.command.Command != session.CommandTaken {
		t.Fatalf("the guest did not take the command: %+v", answer.command)
	}
	result, err := command.Open(answer.command.Answer)
	if err != nil {
		t.Fatalf("the command's answer: %v", err)
	}
	return result
}

// A session's first command comes with its bind, sealed to the guest's
// one-time KEM key. The guest opens it while it takes the bind, runs it once
// its sandbox runs, and answers after its receipt, sealed to the command's
// sender. A bind sent again gets the same answers and runs nothing again, and
// no other command is opened: the key for one is gone.
func TestFirstCommandComesWithTheBindAndRunsOnce(t *testing.T) {
	c := newCommanded(t)
	c.runner.starting, c.runner.started = make(chan struct{}), make(chan struct{})
	command := c.seal(t, c.access, c.bind)

	first := make(chan bindAnswer, 1)
	go func() { first <- c.post(t, c.bind, command.Sealed) }()
	select {
	case <-c.runner.starting:
	case <-time.After(10 * time.Second):
		t.Fatal("the sandbox was never started")
	}
	// The sandbox is about to start: the command is opened, the key it
	// opened under is gone, and nothing has run.
	if !sessionagent.OneTimeKeysGone(c.agent) {
		t.Fatal("the guest still holds a one-time key as its sandbox starts")
	}
	if n := c.runs(t); n != 0 {
		t.Fatalf("the command ran %d times before the sandbox started", n)
	}
	close(c.runner.started)
	answer := <-first
	if answer.status != http.StatusOK || answer.bound.Phase != session.PhaseRunning || answer.bound.Command != session.CommandTaken {
		t.Fatalf("the bind's answer: %d %+v", answer.status, answer.bound)
	}
	if _, err := session.VerifyBindReceipt(c.boundPolicy(c.ready, c.bind), c.ready.InstanceKey, c.ready.OneTime, c.bind, answer.bound.Receipt); err != nil {
		t.Fatalf("the receipt that came before the command's answer: %v", err)
	}
	result := opened(t, command, answer)
	if result.ExitCode != 0 || string(result.Stdout) != "first" {
		t.Fatalf("the command's result: %+v", result)
	}
	if n := c.runs(t); n != 1 {
		t.Fatalf("the command ran %d times", n)
	}

	// The same bind and command again: the same answers, and nothing runs.
	again := c.post(t, c.bind, command.Sealed)
	if !again.bound.Replayed || again.bound.Command != session.CommandTaken || again.command == nil {
		t.Fatalf("the bind sent again: %+v, %+v", again.bound, again.command)
	}
	if !bytes.Equal(again.command.Answer, answer.command.Answer) {
		t.Fatal("the bind sent again got another answer to its command")
	}
	// The same bind with another command: that one came too late.
	other := c.seal(t, c.access, c.bind)
	if late := c.post(t, c.bind, other.Sealed); late.bound.Command != session.CommandTooLate || late.command != nil {
		t.Fatalf("another command with the bind sent again: %+v, %+v", late.bound, late.command)
	}
	if late := c.late(t, other.Sealed); late.command == nil || late.command.Command != session.CommandTooLate || late.command.Answer != nil {
		t.Fatalf("another command after the bind: %+v", late.command)
	}
	// The first one sent after the bind is told what the bind was.
	if same := c.late(t, command.Sealed); same.command == nil || !bytes.Equal(same.command.Answer, answer.command.Answer) {
		t.Fatalf("the command sent again after the bind: %+v", same.command)
	}
	// And with none, the answer says nothing of a command.
	if none := c.post(t, c.bind, nil); none.bound.Command != "" || none.command != nil {
		t.Fatalf("the bind sent again with no command: %+v, %+v", none.bound, none.command)
	}
	if n := c.runs(t); n != 1 {
		t.Fatalf("after the bind was sent again the command had run %d times", n)
	}
	// The session goes on over its own connection.
	exec, err := c.boundClient(t, c.ready, c.bind).Exec(ctxT(t), session.ExecRequest{Argv: []string{"/bin/echo", "next"}})
	if err != nil || string(exec.Stdout) != "next\n" {
		t.Fatalf("a command after the first: %+v, %v", exec, err)
	}
}

// What comes with a bind and does not open under the guest's one-time key
// and that bind is not a command: the guest takes the bind, says the command
// was not opened, and runs nothing. The key is gone all the same.
func TestCommandThatDoesNotOpenIsNotRun(t *testing.T) {
	for name, sealed := range map[string]func(t *testing.T, c *commanded) []byte{
		"sealed for another bind": func(t *testing.T, c *commanded) []byte {
			return c.seal(t, c.access, c.bindFor(t, c.ready, func(o *session.BindOptions) { o.Session = "sbx-2" })).Sealed
		},
		"sealed to another guest": func(t *testing.T, c *commanded) []byte {
			other := found(t, func() *pool { p := newPool(t); p.start(t); return p }())
			elsewhere := *c.ready
			elsewhere.OneTime = other.ready.OneTime
			command, err := session.SealFirstCommand(&elsewhere, c.bind, c.access, c.request())
			if err != nil {
				t.Fatal(err)
			}
			return command.Sealed
		},
		"changed on its way": func(t *testing.T, c *commanded) []byte {
			changed := c.seal(t, c.access, c.bind).Sealed
			changed[len(changed)-1] ^= 1
			return changed
		},
		"no sealed command at all": func(*testing.T, *commanded) []byte { return []byte("run this") },
	} {
		t.Run(name, func(t *testing.T) {
			c := newCommanded(t)
			answer := c.post(t, c.bind, sealed(t, c))
			if answer.status != http.StatusOK || answer.bound.Phase != session.PhaseRunning {
				t.Fatalf("the bind's answer: %d %+v", answer.status, answer.bound)
			}
			if answer.bound.Command != session.CommandUnopened || answer.command != nil {
				t.Fatalf("the guest says of the command: %q, %+v", answer.bound.Command, answer.command)
			}
			if !sessionagent.OneTimeKeysGone(c.agent) {
				t.Fatal("the guest kept a one-time key")
			}
			// The command its owner meant comes too late now, and goes over
			// the session's own connection.
			real := c.seal(t, c.access, c.bind)
			if late := c.late(t, real.Sealed); late.command == nil || late.command.Command != session.CommandTooLate {
				t.Fatalf("a command after one that did not open: %+v", late.command)
			}
			if n := c.runs(t); n != 0 {
				t.Fatalf("the command ran %d times", n)
			}
		})
	}
}

// misdirected signs a command's token as its owner would sign one for another
// guest, route or body.
type misdirected struct {
	signer         *operatorauth.Signer
	audience, path string
	body           []byte
}

func (e misdirected) AuthorizationFor(audience, method, path string, body []byte) (string, error) {
	if e.audience != "" {
		audience = e.audience
	}
	if e.path != "" {
		path = e.path
	}
	if e.body != nil {
		body = e.body
	}
	return e.signer.AuthorizationFor(audience, method, path, body)
}

// A command that opens is run only under a token the guest's exec route
// would take: of a key the bind grants that route, for this guest, that
// route and those bytes. The guest tells its sender otherwise, under the
// same seal, and runs nothing.
func TestFirstCommandNeedsAKeyTheBindGrants(t *testing.T) {
	stranger, _ := newSigner(t)
	for name, auth := range map[string]func(c *commanded) operatorauth.AudienceAuthorizer{
		"a key the bind does not grant": func(*commanded) operatorauth.AudienceAuthorizer { return stranger },
		"a token for another guest": func(c *commanded) operatorauth.AudienceAuthorizer {
			return misdirected{signer: c.access, audience: "sha256:" + strings.Repeat("0", 64)}
		},
		"a token for another route": func(c *commanded) operatorauth.AudienceAuthorizer {
			return misdirected{signer: c.access, path: session.PathAttest}
		},
		"a token over other bytes": func(c *commanded) operatorauth.AudienceAuthorizer {
			return misdirected{signer: c.access, body: []byte(`{"id":"00000000000000000000000000000000","argv":["/bin/true"]}`)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := newCommanded(t)
			command := c.seal(t, auth(c), c.bind)
			answer := c.post(t, c.bind, command.Sealed)
			if answer.status != http.StatusOK || answer.bound.Command != session.CommandTaken || answer.command == nil {
				t.Fatalf("the bind's answer: %d %+v", answer.status, answer.bound)
			}
			_, err := command.Open(answer.command.Answer)
			var refused *session.FirstCommandError
			if !errors.As(err, &refused) || refused.Reason != session.FirstCommandUnauthorized {
				t.Fatalf("the command's answer: %v, want it refused as unauthorized", err)
			}
			if n := c.runs(t); n != 0 {
				t.Fatalf("the command ran %d times", n)
			}
		})
	}
}

// A binder that had not sealed its command when it sent the bind sends it
// after: the guest opens it while it still takes the bind, and runs it once
// the sandbox runs. The same command sent again gets the same answer. Once
// the sandbox is about to start, the guest opens none.
func TestCommandSentAfterItsBindIsTakenWhileTheGuestTakesTheBind(t *testing.T) {
	p := newPool(t)
	p.runner.gate = make(chan struct{})
	p.start(t)
	c := found(t, p)
	command := c.seal(t, c.access, c.bind)

	bound := make(chan bindAnswer, 1)
	go func() { bound <- c.post(t, c.bind, nil) }()
	// The guest has measured the bind and is preparing its sandbox.
	until(t, "the guest took its bind", func() bool { return c.phase(t) == session.PhaseBound })
	if sessionagent.OneTimeKeysGone(c.agent) {
		t.Fatal("the guest erased its KEM key before its sandbox was prepared")
	}
	after := make(chan bindAnswer, 1)
	go func() { after <- c.late(t, command.Sealed) }()
	// It is opened on arrival, with the key, which is gone by it: long before
	// the sandbox is.
	until(t, "the guest opened the command", func() bool { return sessionagent.CommandState(c.agent) == session.CommandTaken })
	if !sessionagent.OneTimeKEMGone(c.agent) {
		t.Fatal("the guest kept its KEM key past the command it opened with it")
	}
	select {
	case early := <-after:
		t.Fatalf("the command was answered before the sandbox ran: %+v", early.command)
	default:
	}
	if n := c.runs(t); n != 0 {
		t.Fatalf("the command ran %d times before the sandbox started", n)
	}
	close(p.runner.gate)

	answer := <-bound
	if answer.status != http.StatusOK || answer.bound.Phase != session.PhaseRunning || answer.bound.Command != "" || answer.command != nil {
		t.Fatalf("the answer to a bind that came with no command: %d %+v, %+v", answer.status, answer.bound, answer.command)
	}
	late := <-after
	result := opened(t, command, late)
	if string(result.Stdout) != "first" || c.runs(t) != 1 {
		t.Fatalf("the command's result: %+v, after %d runs", result, c.runs(t))
	}
	if !sessionagent.OneTimeKeysGone(c.agent) {
		t.Fatal("the guest kept a one-time key")
	}
	// Sent again, it is answered as it was. Another comes too late.
	if again := c.late(t, command.Sealed); again.command == nil || !bytes.Equal(again.command.Answer, late.command.Answer) {
		t.Fatalf("the command sent again: %+v", again.command)
	}
	other := c.seal(t, c.access, c.bind)
	if answer := c.late(t, other.Sealed); answer.command == nil || answer.command.Command != session.CommandTooLate {
		t.Fatalf("a second command: %+v", answer.command)
	}
	if n := c.runs(t); n != 1 {
		t.Fatalf("the command ran %d times", n)
	}
}

// A command that reaches the guest once its sandbox runs is refused
// unopened: the key it was sealed to went before anything of the tenant ran.
func TestCommandAfterTheSandboxStartedIsTooLate(t *testing.T) {
	c := newCommanded(t)
	if answer := c.post(t, c.bind, nil); answer.status != http.StatusOK || answer.bound.Phase != session.PhaseRunning {
		t.Fatalf("the bind: %d %+v", answer.status, answer.bound)
	}
	command := c.seal(t, c.access, c.bind)
	answer := c.late(t, command.Sealed)
	if answer.command == nil || answer.command.Command != session.CommandTooLate || len(answer.command.Answer) != 0 {
		t.Fatalf("a command after the sandbox started: %+v", answer.command)
	}
	if n := c.runs(t); n != 0 {
		t.Fatalf("the command ran %d times", n)
	}
}

// A guest that no bind has reached reads no command: one sent to it is
// refused on its headers, the guest stays as it was booted with the keys it
// had, and takes its bind and a command with it after.
func TestCommandBeforeAnyBindIsRefusedUnread(t *testing.T) {
	c := newCommanded(t)
	command := c.seal(t, c.access, c.bind)
	body, err := json.Marshal(session.CommandRequest{Command: command.Sealed})
	if err != nil {
		t.Fatal(err)
	}
	unread := &countingReader{Reader: bytes.NewReader(body)}
	rec := httptest.NewRecorder()
	c.agent.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, session.PathBindCommand, unread))
	if rec.Code != http.StatusConflict || refusalCode(rec.Body.Bytes()) != disclosure.Fenced {
		t.Fatalf("a command before any bind: %d %s", rec.Code, rec.Body)
	}
	if unread.n != 0 {
		t.Fatalf("the agent read %d bytes of a command it refused", unread.n)
	}
	if rec.Header().Get("Connection") != "close" {
		t.Errorf("the refusal's headers: %v", rec.Header())
	}
	// Over the server too, and handed to the agent past it.
	if answer := c.late(t, command.Sealed); answer.status != http.StatusConflict {
		t.Fatalf("a command over the server before any bind: %d", answer.status)
	}
	if answer, err := c.agent.LateCommand(ctxT(t), command.Sealed); err != nil || answer.Command != session.CommandTooLate {
		t.Fatalf("a command handed to the agent before any bind: %+v, %v", answer, err)
	}
	if sessionagent.OneTimeKeysGone(c.agent) || c.state(t).Phase != session.PhaseReady {
		t.Fatal("a command the guest did not read changed the guest")
	}
	// The same command with the bind is the guest's first.
	answer := c.post(t, c.bind, command.Sealed)
	if result := opened(t, command, answer); string(result.Stdout) != "first" || c.runs(t) != 1 {
		t.Fatalf("the command with its bind: %+v, after %d runs", result, c.runs(t))
	}
	// One from a connection the fence ended is refused unread as well.
	unread = &countingReader{Reader: bytes.NewReader(body)}
	req := httptest.NewRequest(http.MethodPost, session.PathBindCommand, unread)
	rec = httptest.NewRecorder()
	c.agent.Handler().ServeHTTP(rec, req.WithContext(sessionagent.EndedConnContext(req.Context(), c.agent)))
	if rec.Code != http.StatusConflict || refusalCode(rec.Body.Bytes()) != disclosure.Fenced || unread.n != 0 {
		t.Fatalf("a command on a connection from before the bind: %d %s, %d bytes read", rec.Code, rec.Body, unread.n)
	}
}

// A guest whose sandbox cannot be admitted ends, and runs no command that
// came with its bind.
func TestCommandOfABindThatFailsIsNotRun(t *testing.T) {
	p := newPool(t)
	p.runner.fail = errors.New("the image does not unpack")
	p.start(t)
	c := found(t, p)
	command := c.seal(t, c.access, c.bind)
	answer := c.post(t, c.bind, command.Sealed)
	if answer.status == http.StatusOK {
		t.Fatalf("a bind whose sandbox was not admitted was answered: %+v", answer.bound)
	}
	if err := p.fatal(t); err == nil {
		t.Fatal("the guest carries on")
	}
	if n := c.runs(t); n != 0 {
		t.Fatalf("the command ran %d times", n)
	}
}

// A command whose sender went away runs all the same, since the guest took
// it, and its answer is kept for the bind sent again.
func TestCommandOfASenderThatWentAwayIsKept(t *testing.T) {
	c := newCommanded(t)
	c.runner.starting, c.runner.started = make(chan struct{}), make(chan struct{})
	command := c.seal(t, c.access, c.bind)
	body, err := json.Marshal(session.BindRequest{Bind: c.bind.Raw, Signature: c.bind.Signature, Command: command.Sealed})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(ctxT(t))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+session.PathBind, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	client := insecureClient()
	defer client.CloseIdleConnections()
	gone := make(chan struct{})
	go func() {
		defer close(gone)
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	select {
	case <-c.runner.starting:
	case <-time.After(10 * time.Second):
		t.Fatal("the sandbox was never started")
	}
	cancel()
	<-gone
	close(c.runner.started)
	until(t, "the command ran", func() bool { return c.runs(t) == 1 })
	again := c.post(t, c.bind, command.Sealed)
	if result := opened(t, command, again); string(result.Stdout) != "first" || c.runs(t) != 1 {
		t.Fatalf("the bind sent again: %+v, after %d runs", result, c.runs(t))
	}
}
