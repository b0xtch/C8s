package sessiond_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/sessiond/sessiondtest"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/daemon"
)

const commandImage = "ghcr.io/acme/agent@sha256:1111111111111111111111111111111111111111111111111111111111111111"

// commanding is a binder that has claimed a TD, found it ready and written
// its bind, and means to send the session's first command with it.
type commanding struct {
	td     string
	guest  *sessiondtest.TD
	ready  *session.ReadyTD
	bind   *session.SignedBind
	signer *operatorauth.Signer
	// marker is a file the command leaves a line in each time it runs.
	marker string
}

// commands claims a TD for the session and writes its bind, which names a
// sandbox image if image is set.
func (h *host) commands(c *daemon.Client, o *owner, name string, image bool) *commanding {
	h.t.Helper()
	claimed, err := c.Claim(ctx(h.t), requestID(h.t), sessiondtest.Pool, name, 10*time.Second)
	if err != nil {
		h.t.Fatal(err)
	}
	policy := session.Policy{Image: h.Identity, LaunchKey: h.LaunchKey, Authority: o.authorityPub, AllowReady: true}
	ready, err := session.VerifyReady(ctx(h.t), policy, h.Engine, claimed.Evidence, time.Now())
	if err != nil {
		h.t.Fatal(err)
	}
	opts := session.BindOptions{
		Authority: o.authority, InstanceKey: ready.InstanceKey, Tenant: "acme", Session: name, NotAfter: time.Now().Add(time.Minute),
		Policy: session.BindPolicy{Access: session.Access{Exec: []string{o.accessPub}}},
	}
	if image {
		opts.Policy.Sandbox = &session.Sandbox{Image: commandImage}
	}
	bind, err := session.NewBind(opts)
	if err != nil {
		h.t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(o.accessPEM)
	if err != nil {
		h.t.Fatal(err)
	}
	var guest *sessiondtest.TD
	for _, td := range h.Runner.All() {
		if td.Asked("") > 0 && guest == nil {
			guest = td
		}
	}
	return &commanding{
		td: claimed.TD, guest: guest, ready: ready, bind: bind, signer: signer,
		marker: filepath.Join(h.t.TempDir(), "ran"),
	}
}

// seal seals a command that says it ran: a line in the marker, and what it
// was given on its standard input back.
func (c *commanding) seal(t *testing.T) *session.FirstCommand {
	t.Helper()
	command, err := session.SealFirstCommand(c.ready, c.bind, c.signer, session.ExecRequest{
		Argv:  []string{"/bin/sh", "-c", `echo ran >> "$MARKER"; cat`},
		Env:   map[string]string{"MARKER": c.marker},
		Stdin: []byte("first"),
	})
	if err != nil {
		t.Fatalf("SealFirstCommand: %v", err)
	}
	return command
}

func (c *commanding) runs(t *testing.T) int {
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

// result is the answer of a command the call carried, opened by its sender.
func result(t *testing.T, call *daemon.BindCall, command *session.FirstCommand) ([]byte, *session.ExecResponse) {
	t.Helper()
	sealed, state, err := call.Result()
	if err != nil || state != session.CommandTaken {
		t.Fatalf("the command: %q, %v, want it taken", state, err)
	}
	opened, err := command.Open(sealed)
	if err != nil {
		t.Fatalf("the command's answer: %v", err)
	}
	return sealed, opened
}

// A session's first command travels with its bind: the daemon carries it to
// the guest sealed and its answer back sealed, in the one call that binds
// the TD, after the receipt. The guest is asked for no exec over its own
// route. The call repeated gets the same answers, and nothing runs again.
func TestFirstCommandTravelsWithTheBind(t *testing.T) {
	h := newHost(t, 1, nil)
	c, o := h.AsOrchestrator(), newOwner(t)
	s := h.commands(c, o, "s1", false)
	command := s.seal(t)

	id := requestID(t)
	call, err := c.BindWith(ctx(t), id, s.td, s.bind, command.Sealed)
	if err != nil {
		t.Fatalf("the bind with its command: %v", err)
	}
	defer call.Close()
	if call.Command != session.CommandTaken {
		t.Fatalf("the guest says of the command: %q", call.Command)
	}
	// The receipt came first, and the session is the binder's to judge as
	// any other.
	started, err := h.judge(c, s.td, s.ready, s.bind, call.Answer)
	if err != nil {
		t.Fatalf("the bind's answer: %v", err)
	}
	sealed, opened := result(t, call, command)
	if opened.ExitCode != 0 || string(opened.Stdout) != "first" || s.runs(t) != 1 {
		t.Fatalf("the command's result: %+v, after %d runs", opened, s.runs(t))
	}
	if n := s.guest.Asked(session.PathExec); n != 0 {
		t.Fatalf("the guest was asked for %d commands over its own route", n)
	}
	if n := s.guest.Asked(session.PathBind); n != 1 {
		t.Fatalf("the guest was sent %d binds", n)
	}

	// The same call again: the guest answers as it did, and runs nothing.
	again, err := c.BindWith(ctx(t), id, s.td, s.bind, command.Sealed)
	if err != nil {
		t.Fatalf("the call repeated: %v", err)
	}
	defer again.Close()
	if again.Command != session.CommandTaken || again.Answer.Receipt == nil ||
		!bytes.Equal(again.Answer.Receipt.Receipt, call.Answer.Receipt.Receipt) {
		t.Fatalf("the call repeated was answered differently: %q", again.Command)
	}
	if repeated, _ := result(t, again, command); !bytes.Equal(repeated, sealed) {
		t.Fatal("the call repeated got another answer to its command")
	}
	// With another command, that one came too late: its sender sends it
	// over a connection of its own.
	other := s.seal(t)
	late, err := c.BindWith(ctx(t), id, s.td, s.bind, other.Sealed)
	if err != nil {
		t.Fatal(err)
	}
	defer late.Close()
	if answer, state, err := late.Result(); err != nil || state != session.CommandTooLate || answer != nil || late.Command != session.CommandTooLate {
		t.Fatalf("another command with the call repeated: %q, %q, %v", late.Command, state, err)
	}
	// With none, the daemon answers from its record and says nothing of a
	// command.
	sent := s.guest.Asked(session.PathBind)
	if relayed, err := c.Bind(ctx(t), id, s.td, s.bind); err != nil || relayed.Receipt == nil {
		t.Fatalf("the call repeated with no command: %v", err)
	}
	if n := s.guest.Asked(session.PathBind); n != sent {
		t.Fatalf("the guest was asked again for a bind the daemon has the answer to")
	}
	if n := s.runs(t); n != 1 {
		t.Fatalf("after the repeats the command had run %d times", n)
	}

	// The sender that is not sure its command ran sends the same request
	// over its own connection, and the guest answers with the first run's
	// result.
	guest := h.drive(o, started)
	rerun, err := guest.Exec(ctx(t), command.Request)
	if err != nil || string(rerun.Stdout) != "first" || s.runs(t) != 1 {
		t.Fatalf("the same request over the session's connection: %+v, %v, after %d runs", rerun, err, s.runs(t))
	}
	if next, err := guest.Exec(ctx(t), session.ExecRequest{Argv: []string{"/bin/echo", "next"}}); err != nil || string(next.Stdout) != "next\n" {
		t.Fatalf("a command after the first: %+v, %v", next, err)
	}
}

// held is a sandbox whose guest waits, while it prepares the image its bind
// names, until the test lets it go on.
type held struct {
	preparing chan struct{}
	release   chan struct{}
}

func newHeld() *held {
	return &held{preparing: make(chan struct{}, 8), release: make(chan struct{})}
}

func (s *held) Prepare(ctx context.Context, _ *session.Sandbox) error {
	s.preparing <- struct{}{}
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (*held) Start(context.Context, *session.Sandbox, string) error { return nil }

func (*held) Dial(context.Context, int) (net.Conn, error) {
	return nil, errors.New("the sandbox listens on no port")
}

// A binder that sends its bind before it has sealed its command sends the
// command in the call's next message. The daemon carries it to the guest
// after the bind, on a connection the guest's fence lets in, and the guest
// opens it while it still takes the bind. Its answer follows the receipt.
func TestCommandFollowsItsBindOnTheSameCall(t *testing.T) {
	sandbox := newHeld()
	h := &host{Host: sessiondtest.NewHostWithSandbox(t, 1, sandbox), t: t}
	c, o := h.AsOrchestrator(), newOwner(t)
	s := h.commands(c, o, "s1", true)

	call, err := c.StartBind(ctx(t), requestID(t), s.td, s.bind, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer call.Close()
	select {
	case <-sandbox.preparing:
	case <-time.After(20 * time.Second):
		t.Fatal("the guest never prepared its sandbox")
	}
	// The guest has measured the bind, and the binder's check has passed.
	command := s.seal(t)
	if err := call.SendCommand(command.Sealed); err != nil {
		t.Fatal(err)
	}
	if err := call.SendCommand(command.Sealed); err == nil {
		t.Fatal("a call carried its command twice")
	}
	eventually(t, "the guest opens the command", func() bool { return s.guest.Logged("a first command came") == 1 })
	if n := s.runs(t); n != 0 {
		t.Fatalf("the command ran %d times before the sandbox started", n)
	}
	close(sandbox.release)
	if err := call.Await(); err != nil {
		t.Fatalf("the bind's answer: %v", err)
	}
	if call.Command != "" || call.Answer.Receipt == nil {
		t.Fatalf("the answer to a bind that came with no command says %q of one", call.Command)
	}
	if _, err := h.judge(c, s.td, s.ready, s.bind, call.Answer); err != nil {
		t.Fatalf("the bind's answer: %v", err)
	}
	if _, opened := result(t, call, command); string(opened.Stdout) != "first" || s.runs(t) != 1 {
		t.Fatalf("the command's result: %+v, after %d runs", opened, s.runs(t))
	}
	if n := s.guest.Asked(session.PathBindCommand); n != 1 {
		t.Fatalf("the guest was sent %d commands after its bind", n)
	}
	if n := s.guest.Asked(session.PathExec); n != 0 {
		t.Fatalf("the guest was asked for %d commands over its own route", n)
	}
}

// A command that follows its bind too late is refused unopened: the guest
// erased the key it was sealed to before its sandbox started. The call says
// so, and the binder sends the same request over the session's connection,
// where it runs once.
func TestCommandThatFollowsTooLateRunsOverTheSessionsConnection(t *testing.T) {
	h := newHost(t, 1, nil)
	c, o := h.AsOrchestrator(), newOwner(t)
	s := h.commands(c, o, "s1", false)

	call, err := c.StartBind(ctx(t), requestID(t), s.td, s.bind, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer call.Close()
	if err := call.Await(); err != nil {
		t.Fatalf("the bind's answer: %v", err)
	}
	started, err := h.judge(c, s.td, s.ready, s.bind, call.Answer)
	if err != nil {
		t.Fatal(err)
	}
	// The guest runs its sandbox: the command comes after.
	command := s.seal(t)
	if err := call.SendCommand(command.Sealed); err != nil {
		t.Fatal(err)
	}
	answer, state, err := call.Result()
	if err != nil || state != session.CommandTooLate || answer != nil {
		t.Fatalf("a command after the guest answered its bind: %q, %v", state, err)
	}
	if n := s.runs(t); n != 0 {
		t.Fatalf("the command ran %d times", n)
	}
	ran, err := h.drive(o, started).Exec(ctx(t), command.Request)
	if err != nil || string(ran.Stdout) != "first" || s.runs(t) != 1 {
		t.Fatalf("the command over the session's connection: %+v, %v, after %d runs", ran, err, s.runs(t))
	}
}

// A call that carries no command and one whose caller goes away both end:
// the daemon holds no call open for a command that will not come.
func TestBindCallEndsWithItsCaller(t *testing.T) {
	h := newHost(t, 1, nil)
	c, o := h.AsOrchestrator(), newOwner(t)
	s := h.commands(c, o, "s1", false)
	id := requestID(t)
	call, err := c.StartBind(ctx(t), id, s.td, s.bind, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := call.Await(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := call.Result(); err == nil {
		t.Fatal("a call that carried no command has a result for one")
	}
	// Its caller goes away with its side open.
	call.Close()
	// The TD is the session's, and the same request is answered again.
	if again, err := c.Bind(ctx(t), id, s.td, s.bind); err != nil || again.Receipt == nil {
		t.Fatalf("the bind repeated after its caller left: %v", err)
	}
	h.Stop()
}
