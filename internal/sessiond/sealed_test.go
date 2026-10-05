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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/confidential-dot-ai/c8s/internal/sessiond/sessiondtest"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/daemon"
)

const sealedImage = "ghcr.io/acme/agent@sha256:1111111111111111111111111111111111111111111111111111111111111111"

// sealing is a binder that has claimed a TD, found it ready and written its
// bind, and means to send the session's first command and a credential it
// holds with it.
type sealing struct {
	td     string
	guest  *sessiondtest.TD
	ready  *session.ReadyTD
	bind   *session.SignedBind
	signer *operatorauth.Signer
	// marker is a file the command leaves a line in each time it runs.
	marker string
}

// credential is the credential the binder of these tests holds.
var credential = []byte("s3cr3t")

// seals claims a TD for the session and writes its bind, which declares the
// binder's credential and names a sandbox image if image is set.
func (h *host) seals(c *daemon.Client, o *owner, name string, image bool) *sealing {
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
		Policy: session.BindPolicy{
			Access:      session.Access{Exec: []string{o.accessPub}, Credentials: []string{o.accessPub}},
			Credentials: []session.Credential{{Name: "api-token", Source: session.SourceBinder, MaxBytes: 64}},
		},
	}
	if image {
		opts.Policy.Sandbox = &session.Sandbox{Image: sealedImage}
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
	return &sealing{
		td: claimed.TD, guest: guest, ready: ready, bind: bind, signer: signer,
		marker: filepath.Join(h.t.TempDir(), "ran"),
	}
}

// seal seals the binder's credential with a command that says it ran: a
// line in the marker, the credential it finds in place, and what it was
// given on its standard input back.
func (c *sealing) seal(t *testing.T) *session.SealedMessage {
	t.Helper()
	message, err := session.SealWithBind(c.ready, c.bind, c.signer, session.SealedParts{
		Command: &session.ExecRequest{
			Argv:  []string{"/bin/sh", "-c", `echo ran >> "$MARKER"; cat "$C8S_CREDENTIALS_DIR/api-token" 2>/dev/null; cat`},
			Env:   map[string]string{"MARKER": c.marker},
			Stdin: []byte("first"),
		},
		Credentials: map[string][]byte{"api-token": credential},
	})
	if err != nil {
		t.Fatalf("SealWithBind: %v", err)
	}
	return message
}

func (c *sealing) runs(t *testing.T) int {
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

// result is the guest's answer to a sealed message the call carried, opened
// by its sender: the command's result, with the credential held.
func result(t *testing.T, call *daemon.BindCall, message *session.SealedMessage) ([]byte, *session.ExecResponse) {
	t.Helper()
	sealed, status, err := call.SealedAnswer()
	if err != nil || status != session.SealedTaken {
		t.Fatalf("the sealed message: %q, %v, want it taken", status, err)
	}
	opened, err := message.Open(sealed)
	if err != nil {
		t.Fatalf("the sealed answer: %v", err)
	}
	if opened.Command == nil || opened.Credentials["api-token"] != session.SealedHeld {
		t.Fatalf("the sealed answer says: command %q, credentials %v", opened.CommandError, opened.Credentials)
	}
	return sealed, opened.Command
}

// A session's first command and its binder's credential travel with its
// bind: the daemon carries them to the guest sealed and the guest's answer
// back sealed, in the one call that binds the TD, after the receipt. The
// guest is asked for nothing over its own routes. The call repeated gets the
// same answers, and nothing is done again.
func TestSealedMessageTravelsWithTheBind(t *testing.T) {
	h := newHost(t, 1, nil)
	c, o := h.AsOrchestrator(), newOwner(t)
	s := h.seals(c, o, "s1", false)
	message := s.seal(t)

	id := requestID(t)
	call, err := c.BindWith(ctx(t), id, s.td, s.bind, message.Sealed)
	if err != nil {
		t.Fatalf("the bind with its sealed message: %v", err)
	}
	defer call.Close()
	if call.SealedStatus != session.SealedTaken {
		t.Fatalf("the guest says of the sealed message: %q", call.SealedStatus)
	}
	// The receipt came first, and the session is the binder's to judge as
	// any other.
	started, err := h.judge(c, s.td, s.ready, s.bind, call.Answer)
	if err != nil {
		t.Fatalf("the bind's answer: %v", err)
	}
	sealed, opened := result(t, call, message)
	// The command found the credential in place.
	if opened.ExitCode != 0 || string(opened.Stdout) != "s3cr3tfirst" || s.runs(t) != 1 {
		t.Fatalf("the command's result: %+v, after %d runs", opened, s.runs(t))
	}
	if n := s.guest.Asked(session.PathExec) + s.guest.Asked(session.PathCredentials+"api-token"); n != 0 {
		t.Fatalf("the guest was asked %d times over its own routes", n)
	}
	if n := s.guest.Asked(session.PathBind); n != 1 {
		t.Fatalf("the guest was sent %d binds", n)
	}

	// The same call again: the guest answers as it did, and does nothing.
	again, err := c.BindWith(ctx(t), id, s.td, s.bind, message.Sealed)
	if err != nil {
		t.Fatalf("the call repeated: %v", err)
	}
	defer again.Close()
	if again.SealedStatus != session.SealedTaken || again.Answer.Receipt == nil ||
		!bytes.Equal(again.Answer.Receipt.Receipt, call.Answer.Receipt.Receipt) {
		t.Fatalf("the call repeated was answered differently: %q", again.SealedStatus)
	}
	if repeated, _ := result(t, again, message); !bytes.Equal(repeated, sealed) {
		t.Fatal("the call repeated got another answer to its sealed message")
	}
	// With another message, that one came too late: its sender sends what
	// it holds over a connection of its own.
	other := s.seal(t)
	late, err := c.BindWith(ctx(t), id, s.td, s.bind, other.Sealed)
	if err != nil {
		t.Fatal(err)
	}
	defer late.Close()
	if answer, status, err := late.SealedAnswer(); err != nil || status != session.SealedTooLate || answer != nil || late.SealedStatus != session.SealedTooLate {
		t.Fatalf("another message with the call repeated: %q, %q, %v", late.SealedStatus, status, err)
	}
	// With none, the daemon answers from its record and says nothing of a
	// sealed message.
	sent := s.guest.Asked(session.PathBind)
	if relayed, err := c.Bind(ctx(t), id, s.td, s.bind); err != nil || relayed.Receipt == nil {
		t.Fatalf("the call repeated with no sealed message: %v", err)
	}
	if n := s.guest.Asked(session.PathBind); n != sent {
		t.Fatalf("the guest was asked again for a bind the daemon has the answer to")
	}
	if n := s.runs(t); n != 1 {
		t.Fatalf("after the repeats the command had run %d times", n)
	}

	// The sender that is not sure the guest acted on its message sends what
	// it sealed over its own connection: the guest holds the credential, and
	// answers the command with the first run's result.
	guest := h.drive(o, started)
	if _, err := guest.PutCredential(ctx(t), "api-token", credential); err != nil {
		t.Fatalf("the credential again over the session's connection: %v", err)
	}
	rerun, err := guest.Exec(ctx(t), *message.Command)
	if err != nil || string(rerun.Stdout) != "s3cr3tfirst" || s.runs(t) != 1 {
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

// A binder that sends its bind before it has sealed its message sends the
// message in the call's next message. The daemon carries it to the guest
// after the bind, on a connection the guest's fence lets in, and the guest
// opens it while it still takes the bind. Its answer follows the receipt.
func TestSealedMessageFollowsItsBindOnTheSameCall(t *testing.T) {
	sandbox := newHeld()
	h := &host{Host: sessiondtest.NewHostWithSandbox(t, 1, sandbox), t: t}
	c, o := h.AsOrchestrator(), newOwner(t)
	s := h.seals(c, o, "s1", true)

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
	message := s.seal(t)
	if err := call.SendSealed(message.Sealed); err != nil {
		t.Fatal(err)
	}
	if err := call.SendSealed(message.Sealed); err == nil {
		t.Fatal("a call carried its sealed message twice")
	}
	eventually(t, "the guest opens the message", func() bool { return s.guest.Logged("a sealed message came") == 1 })
	if n := s.runs(t); n != 0 {
		t.Fatalf("the command ran %d times before the sandbox started", n)
	}
	close(sandbox.release)
	if err := call.Await(); err != nil {
		t.Fatalf("the bind's answer: %v", err)
	}
	if call.SealedStatus != "" || call.Answer.Receipt == nil {
		t.Fatalf("the answer to a bind that came with no sealed message says %q of one", call.SealedStatus)
	}
	if _, err := h.judge(c, s.td, s.ready, s.bind, call.Answer); err != nil {
		t.Fatalf("the bind's answer: %v", err)
	}
	if _, opened := result(t, call, message); string(opened.Stdout) != "s3cr3tfirst" || s.runs(t) != 1 {
		t.Fatalf("the command's result: %+v, after %d runs", opened, s.runs(t))
	}
	if n := s.guest.Asked(session.PathBindSealed); n != 1 {
		t.Fatalf("the guest was sent %d sealed messages after its bind", n)
	}
	if n := s.guest.Asked(session.PathExec) + s.guest.Asked(session.PathCredentials+"api-token"); n != 0 {
		t.Fatalf("the guest was asked %d times over its own routes", n)
	}
}

// A sealed message that follows its bind too late is refused unopened: the
// guest erased the key it was sealed to before its sandbox started. The call
// says so, and the binder sends what it sealed over the session's
// connection: the credential, and the command, which runs once.
func TestSealedMessageThatFollowsTooLateGoesOverTheSessionsConnection(t *testing.T) {
	h := newHost(t, 1, nil)
	c, o := h.AsOrchestrator(), newOwner(t)
	s := h.seals(c, o, "s1", false)

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
	// The guest runs its sandbox: the message comes after.
	message := s.seal(t)
	if err := call.SendSealed(message.Sealed); err != nil {
		t.Fatal(err)
	}
	answer, status, err := call.SealedAnswer()
	if err != nil || status != session.SealedTooLate || answer != nil {
		t.Fatalf("a sealed message after the guest answered its bind: %q, %v", status, err)
	}
	if n := s.runs(t); n != 0 {
		t.Fatalf("the command ran %d times", n)
	}
	guest := h.drive(o, started)
	if _, err := guest.PutCredential(ctx(t), "api-token", credential); err != nil {
		t.Fatalf("the credential over the session's connection: %v", err)
	}
	ran, err := guest.Exec(ctx(t), *message.Command)
	if err != nil || string(ran.Stdout) != "s3cr3tfirst" || s.runs(t) != 1 {
		t.Fatalf("the command over the session's connection: %+v, %v, after %d runs", ran, err, s.runs(t))
	}
}

// A call that carries no sealed message and one whose caller goes away both
// end: the daemon holds no call open for a message that will not come.
func TestBindCallEndsWithItsCaller(t *testing.T) {
	h := newHost(t, 1, nil)
	c, o := h.AsOrchestrator(), newOwner(t)
	s := h.seals(c, o, "s1", false)
	id := requestID(t)
	call, err := c.StartBind(ctx(t), id, s.td, s.bind, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := call.Await(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := call.SealedAnswer(); err == nil {
		t.Fatal("a call that carried no sealed message has an answer to one")
	}
	// Its caller goes away with its side open.
	call.Close()
	// The TD is the session's, and the same request is answered again.
	if again, err := c.Bind(ctx(t), id, s.td, s.bind); err != nil || again.Receipt == nil {
		t.Fatalf("the bind repeated after its caller left: %v", err)
	}
	h.Stop()
}

// A guest that took a sealed message owes its answer. A call whose guest is
// cut off before the answer came ends as one to send again, and the same
// request again brings the answer of the command that ran once.
func TestBindCallWhoseSealedAnswerWasLostIsOneToSendAgain(t *testing.T) {
	h := newHost(t, 1, nil)
	c, o := h.AsOrchestrator(), newOwner(t)
	s := h.seals(c, o, "s1", false)
	// A command that ends when the test lets it.
	gate := filepath.Join(t.TempDir(), "go")
	message, err := session.SealWithBind(s.ready, s.bind, s.signer, session.SealedParts{Command: &session.ExecRequest{
		Argv: []string{"/bin/sh", "-c", `echo ran >> "$MARKER"; until [ -e "$GATE" ]; do sleep 0.01; done; echo done`},
		Env:  map[string]string{"MARKER": s.marker, "GATE": gate},
	}})
	if err != nil {
		t.Fatal(err)
	}
	id := requestID(t)
	call, err := c.BindWith(ctx(t), id, s.td, s.bind, message.Sealed)
	if err != nil {
		t.Fatalf("the bind with its sealed message: %v", err)
	}
	defer call.Close()
	if call.Answer.Receipt == nil || call.SealedStatus != session.SealedTaken {
		t.Fatalf("the answer to the bind: receipt %v, sealed message %q", call.Answer.Receipt != nil, call.SealedStatus)
	}
	eventually(t, "the command runs", func() bool { return s.runs(t) == 1 })
	s.guest.Cut()
	if _, _, err := call.SealedAnswer(); status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "send the same request again") {
		t.Fatalf("a call whose guest was cut off before its sealed answer: %v", err)
	}
	if err := os.WriteFile(gate, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	again, err := c.BindWith(ctx(t), id, s.td, s.bind, message.Sealed)
	if err != nil {
		t.Fatalf("the same request again: %v", err)
	}
	defer again.Close()
	sealed, taken, err := again.SealedAnswer()
	if err != nil || taken != session.SealedTaken {
		t.Fatalf("the sealed answer of the request sent again: %q, %v", taken, err)
	}
	opened, err := message.Open(sealed)
	if err != nil || opened.Command == nil || string(opened.Command.Stdout) != "done\n" || s.runs(t) != 1 {
		t.Fatalf("the command's answer: %+v, %v, after %d runs", opened, err, s.runs(t))
	}
}
