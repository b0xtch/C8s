package sessionagent_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
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

// sealing is a pool guest whose owner sends a sealed message with its bind:
// the guest as its owner found it ready, the bind for it, and a file the
// message's command leaves a line in each time it runs. The bind declares
// two credentials its binder holds, beside the one a key hands over.
type sealing struct {
	*pool
	ready  *session.ReadyTD
	bind   *session.SignedBind
	marker string
}

func newSealing(t *testing.T) *sealing {
	t.Helper()
	p := newPool(t)
	p.start(t)
	return found(t, p)
}

// found is the owner finding p's guest ready and writing its bind.
func found(t *testing.T, p *pool) *sealing {
	t.Helper()
	ready, err := p.client(t, p.access).Ready(ctxT(t))
	if err != nil {
		t.Fatalf("Ready: %v", err)
	}
	c := &sealing{pool: p, ready: ready, marker: filepath.Join(t.TempDir(), "ran")}
	c.bind = c.declaring(t, nil)
	return c
}

// declaring is a bind for the guest that declares the binder's credentials,
// with a change of the caller's.
func (c *sealing) declaring(t *testing.T, mutate func(*session.BindOptions)) *session.SignedBind {
	t.Helper()
	return c.bindFor(t, c.ready, func(o *session.BindOptions) {
		o.Policy.Credentials = []session.Credential{
			{Name: "api-token", Source: session.SourceBinder, MaxBytes: 16},
			{Name: "signing-key", Source: session.SourceBinder},
			{Name: "test-token", MaxBytes: 64},
		}
		if mutate != nil {
			mutate(o)
		}
	})
}

// request is a command that says it ran: a line in the marker, the
// credential it finds in place, and what it was given on its standard input
// back.
func (c *sealing) request() *session.ExecRequest {
	return &session.ExecRequest{
		Argv:  []string{"/bin/sh", "-c", `echo ran >> "$MARKER"; cat "$C8S_CREDENTIALS_DIR/api-token" 2>/dev/null; cat`},
		Env:   map[string]string{"MARKER": c.marker},
		Stdin: []byte("first"),
	}
}

// held are the credentials the binder of these tests holds.
func held() map[string][]byte {
	return map[string][]byte{"api-token": []byte("s3cr3t"), "signing-key": []byte("-----BEGIN KEY-----")}
}

// seal seals the command, with the binder's credentials when withCredentials
// is set.
func (c *sealing) seal(t *testing.T, auth operatorauth.AudienceAuthorizer, bind *session.SignedBind, withCredentials bool) *session.SealedMessage {
	t.Helper()
	parts := session.SealedParts{Command: c.request()}
	if withCredentials {
		parts.Credentials = held()
	}
	message, err := session.SealWithBind(c.ready, bind, auth, parts)
	if err != nil {
		t.Fatalf("SealWithBind: %v", err)
	}
	return message
}

// runs is how many times the command ran.
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

// inPlace is the credential the sandbox finds under name, or nil.
func (c *sealing) inPlace(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(c.credDir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// bindAnswer is a guest's answer to a bind as it arrives: the answer to the
// bind, and the document that follows it for a sealed message the guest
// took.
type bindAnswer struct {
	status int
	bound  session.BindResponse
	sealed *session.SealedReply
}

// post sends the bind with a sealed message, as a stranger on the network
// could, and reads all the guest answers.
func (c *sealing) post(t *testing.T, bind *session.SignedBind, sealed []byte) bindAnswer {
	t.Helper()
	body, err := json.Marshal(session.BindRequest{Bind: bind.Raw, Signature: bind.Signature, Sealed: sealed})
	if err != nil {
		t.Fatal(err)
	}
	return c.answered(t, session.PathBind, body)
}

// late sends a sealed message after its bind.
func (c *sealing) late(t *testing.T, sealed []byte) bindAnswer {
	t.Helper()
	body, err := json.Marshal(session.SealedRequest{Sealed: sealed})
	if err != nil {
		t.Fatal(err)
	}
	return c.answered(t, session.PathBindSealed, body)
}

func (c *sealing) answered(t *testing.T, path string, body []byte) bindAnswer {
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
	if path == session.PathBindSealed {
		out.sealed = &session.SealedReply{}
		if err := documents.Decode(out.sealed); err != nil {
			t.Fatalf("the answer to a sealed message: %v", err)
		}
	} else {
		if err := documents.Decode(&out.bound); err != nil {
			t.Fatalf("the answer to a bind: %v", err)
		}
		var next session.SealedReply
		switch err := documents.Decode(&next); {
		case err == nil:
			out.sealed = &next
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
func (c *sealing) phase(t *testing.T) session.Phase {
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

// opened is the guest's sealed answer to a message it took, as its sender
// opens it.
func opened(t *testing.T, message *session.SealedMessage, answer bindAnswer) *session.SealedAnswer {
	t.Helper()
	if answer.sealed == nil || answer.sealed.Sealed != session.SealedTaken {
		t.Fatalf("the guest did not take the sealed message: %+v", answer.sealed)
	}
	said, err := message.Open(answer.sealed.Answer)
	if err != nil {
		t.Fatalf("the sealed answer: %v", err)
	}
	return said
}

// ran is the result of the command of a message the guest took and acted on.
func ran(t *testing.T, message *session.SealedMessage, answer bindAnswer) *session.ExecResponse {
	t.Helper()
	said := opened(t, message, answer)
	if said.Command == nil {
		t.Fatalf("the guest did not run the command: %s", said.CommandError)
	}
	return said.Command
}

// A session's first command and the credentials its binder holds come with
// its bind, in one message sealed to the guest's one-time KEM key. The guest
// opens it while it takes the bind, has the credentials in place before its
// sandbox starts, runs the command once the sandbox runs, and answers after
// its receipt, sealed to the message's sender. A bind sent again gets the
// same answers and does nothing again, and no other message is opened: the
// key for one is gone.
func TestSealedMessageComesWithTheBindAndIsActedOnOnce(t *testing.T) {
	c := newSealing(t)
	c.runner.starting, c.runner.started = make(chan struct{}), make(chan struct{})
	message := c.seal(t, c.access, c.bind, true)

	first := make(chan bindAnswer, 1)
	go func() { first <- c.post(t, c.bind, message.Sealed) }()
	select {
	case <-c.runner.starting:
	case <-time.After(10 * time.Second):
		t.Fatal("the sandbox was never started")
	}
	// The sandbox is about to start: the message is opened, the key it
	// opened under is gone, its credentials are where the sandbox finds
	// them, and nothing has run.
	if !sessionagent.OneTimeKeysGone(c.agent) {
		t.Fatal("the guest still holds a one-time key as its sandbox starts")
	}
	for name, value := range held() {
		if got := c.inPlace(t, name); !bytes.Equal(got, value) {
			t.Fatalf("as the sandbox starts, credential %s is %q", name, got)
		}
		if info, err := os.Stat(filepath.Join(c.credDir, name)); err != nil || info.Mode().Perm() != 0o400 {
			t.Fatalf("credential %s as the sandbox finds it: %v, %v", name, info, err)
		}
	}
	if n := c.runs(t); n != 0 {
		t.Fatalf("the command ran %d times before the sandbox started", n)
	}
	close(c.runner.started)
	answer := <-first
	if answer.status != http.StatusOK || answer.bound.Phase != session.PhaseRunning || answer.bound.Sealed != session.SealedTaken {
		t.Fatalf("the bind's answer: %d %+v", answer.status, answer.bound)
	}
	if _, err := session.VerifyBindReceipt(c.boundPolicy(c.ready, c.bind), c.ready.InstanceKey, c.ready.OneTime, c.bind, answer.bound.Receipt); err != nil {
		t.Fatalf("the receipt that came before the sealed answer: %v", err)
	}
	said := opened(t, message, answer)
	// The command found the credential in place.
	if said.Command == nil || said.Command.ExitCode != 0 || string(said.Command.Stdout) != "s3cr3tfirst" {
		t.Fatalf("the command's result: %+v, %s", said.Command, said.CommandError)
	}
	if len(said.Credentials) != 2 || said.Credentials["api-token"] != session.SealedHeld || said.Credentials["signing-key"] != session.SealedHeld {
		t.Fatalf("the guest says of the credentials: %v", said.Credentials)
	}
	if n := c.runs(t); n != 1 {
		t.Fatalf("the command ran %d times", n)
	}

	// The same bind and message again: the same answers, and nothing runs.
	again := c.post(t, c.bind, message.Sealed)
	if !again.bound.Replayed || again.bound.Sealed != session.SealedTaken || again.sealed == nil {
		t.Fatalf("the bind sent again: %+v, %+v", again.bound, again.sealed)
	}
	if !bytes.Equal(again.sealed.Answer, answer.sealed.Answer) {
		t.Fatal("the bind sent again got another answer to its sealed message")
	}
	// The same bind with another message: that one came too late.
	other := c.seal(t, c.access, c.bind, true)
	if late := c.post(t, c.bind, other.Sealed); late.bound.Sealed != session.SealedTooLate || late.sealed != nil {
		t.Fatalf("another message with the bind sent again: %+v, %+v", late.bound, late.sealed)
	}
	if late := c.late(t, other.Sealed); late.sealed == nil || late.sealed.Sealed != session.SealedTooLate || late.sealed.Answer != nil {
		t.Fatalf("another message after the bind: %+v", late.sealed)
	}
	// The first one sent after the bind is told what the bind was.
	if same := c.late(t, message.Sealed); same.sealed == nil || !bytes.Equal(same.sealed.Answer, answer.sealed.Answer) {
		t.Fatalf("the message sent again after the bind: %+v", same.sealed)
	}
	// And with none, the answer says nothing of a sealed message.
	if none := c.post(t, c.bind, nil); none.bound.Sealed != "" || none.sealed != nil {
		t.Fatalf("the bind sent again with no sealed message: %+v, %+v", none.bound, none.sealed)
	}
	if n := c.runs(t); n != 1 {
		t.Fatalf("after the bind was sent again the command had run %d times", n)
	}
	// The session goes on over its own connection. What the guest took with
	// its bind it holds: the same credential again is answered as held, and
	// another value under its name is refused. The command again, under its
	// id, is answered with the first run's result.
	client := c.boundClient(t, c.ready, c.bind)
	exec, err := client.Exec(ctxT(t), session.ExecRequest{Argv: []string{"/bin/echo", "next"}})
	if err != nil || string(exec.Stdout) != "next\n" {
		t.Fatalf("a command after the first: %+v, %v", exec, err)
	}
	if _, err := client.PutCredential(ctxT(t), "api-token", held()["api-token"]); err != nil {
		t.Fatalf("the credential put again over the session's connection: %v", err)
	}
	if _, err := client.PutCredential(ctxT(t), "api-token", []byte("another")); err == nil {
		t.Fatal("the guest took another value under a name it holds")
	}
	if got := c.inPlace(t, "api-token"); !bytes.Equal(got, held()["api-token"]) {
		t.Fatalf("after another value was sent, the credential is %q", got)
	}
	repeat, err := client.Exec(ctxT(t), *message.Command)
	if err != nil || string(repeat.Stdout) != "s3cr3tfirst" || c.runs(t) != 1 {
		t.Fatalf("the first command again under its id: %+v, %v, after %d runs", repeat, err, c.runs(t))
	}
}

// A message may hold credentials and no command: the guest puts them in
// place and its answer says so.
func TestSealedMessageMayHoldCredentialsAlone(t *testing.T) {
	c := newSealing(t)
	message, err := session.SealWithBind(c.ready, c.bind, c.access, session.SealedParts{Credentials: held()})
	if err != nil {
		t.Fatal(err)
	}
	answer := c.post(t, c.bind, message.Sealed)
	said := opened(t, message, answer)
	if said.Command != nil || said.CommandError != "" || said.Credentials["api-token"] != session.SealedHeld || said.Credentials["signing-key"] != session.SealedHeld {
		t.Fatalf("the answer to credentials alone: %+v", said)
	}
	if got := c.inPlace(t, "signing-key"); !bytes.Equal(got, held()["signing-key"]) {
		t.Fatalf("the credential in place: %q", got)
	}
	if n := c.runs(t); n != 0 {
		t.Fatalf("a message with no command ran one %d times", n)
	}
}

// What comes with a bind and does not open under the guest's one-time key
// and that bind is not a message: the guest takes the bind, says the message
// was not opened, and acts on nothing. The key is gone all the same.
func TestSealedMessageThatDoesNotOpenIsNotActedOn(t *testing.T) {
	for name, sealed := range map[string]func(t *testing.T, c *sealing) []byte{
		"sealed for another bind": func(t *testing.T, c *sealing) []byte {
			return c.seal(t, c.access, c.declaring(t, func(o *session.BindOptions) { o.Session = "sbx-2" }), true).Sealed
		},
		"sealed to another guest": func(t *testing.T, c *sealing) []byte {
			other := found(t, func() *pool { p := newPool(t); p.start(t); return p }())
			elsewhere := *c.ready
			elsewhere.OneTime = other.ready.OneTime
			message, err := session.SealWithBind(&elsewhere, c.bind, c.access, session.SealedParts{Command: c.request(), Credentials: held()})
			if err != nil {
				t.Fatal(err)
			}
			return message.Sealed
		},
		"changed on its way": func(t *testing.T, c *sealing) []byte {
			changed := c.seal(t, c.access, c.bind, true).Sealed
			changed[len(changed)-1] ^= 1
			return changed
		},
		"no sealed message at all": func(*testing.T, *sealing) []byte { return []byte("run this") },
	} {
		t.Run(name, func(t *testing.T) {
			c := newSealing(t)
			answer := c.post(t, c.bind, sealed(t, c))
			if answer.status != http.StatusOK || answer.bound.Phase != session.PhaseRunning {
				t.Fatalf("the bind's answer: %d %+v", answer.status, answer.bound)
			}
			if answer.bound.Sealed != session.SealedUnopened || answer.sealed != nil {
				t.Fatalf("the guest says of the message: %q, %+v", answer.bound.Sealed, answer.sealed)
			}
			if !sessionagent.OneTimeKeysGone(c.agent) {
				t.Fatal("the guest kept a one-time key")
			}
			// The message its owner meant comes too late now, and what it
			// holds goes over the session's own connection.
			real := c.seal(t, c.access, c.bind, true)
			if late := c.late(t, real.Sealed); late.sealed == nil || late.sealed.Sealed != session.SealedTooLate {
				t.Fatalf("a message after one that did not open: %+v", late.sealed)
			}
			if n := c.runs(t); n != 0 {
				t.Fatalf("the command ran %d times", n)
			}
			if got := c.inPlace(t, "api-token"); got != nil {
				t.Fatalf("a credential of a message that did not open is in place: %q", got)
			}
			client := c.boundClient(t, c.ready, c.bind)
			if _, err := client.PutCredential(ctxT(t), "api-token", held()["api-token"]); err != nil {
				t.Fatalf("the credential over the session's connection: %v", err)
			}
			result, err := client.Exec(ctxT(t), *real.Command)
			if err != nil || string(result.Stdout) != "s3cr3tfirst" || c.runs(t) != 1 {
				t.Fatalf("the command over the session's connection: %+v, %v", result, err)
			}
		})
	}
}

// misdirected signs a part's token as its owner would sign one for another
// guest, route or body. With only set, it does so for the routes only
// accepts and signs the others as they are.
type misdirected struct {
	signer         operatorauth.AudienceAuthorizer
	only           func(path string) bool
	audience, path string
	body           []byte
}

func (e misdirected) AuthorizationFor(audience, method, path string, body []byte) (string, error) {
	if e.only != nil && !e.only(path) {
		return e.signer.AuthorizationFor(audience, method, path, body)
	}
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

// signedBy signs the parts for the routes only accepts with other, and the
// rest with signer.
type signedBy struct {
	signer, other operatorauth.AudienceAuthorizer
	only          func(path string) bool
}

func (s signedBy) AuthorizationFor(audience, method, path string, body []byte) (string, error) {
	if s.only(path) {
		return s.other.AuthorizationFor(audience, method, path, body)
	}
	return s.signer.AuthorizationFor(audience, method, path, body)
}

func isExec(path string) bool { return path == session.PathExec }

func isCredential(name string) func(string) bool {
	return func(path string) bool { return path == session.PathCredentials+name }
}

// A sealed command is run only under a token the guest's exec route would
// take: of a key the bind grants that route, for this guest, that route and
// those bytes. The guest tells its sender otherwise, under the same seal,
// and runs nothing. The credentials beside it stand on their own tokens.
func TestSealedCommandNeedsAKeyTheBindGrants(t *testing.T) {
	stranger, _ := newSigner(t)
	releaser, releaserPub := newSigner(t)
	for name, tc := range map[string]struct {
		auth func(c *sealing) operatorauth.AudienceAuthorizer
		bind func(o *session.BindOptions)
	}{
		"a key the bind does not grant": {auth: func(c *sealing) operatorauth.AudienceAuthorizer {
			return signedBy{signer: c.access, other: stranger, only: isExec}
		}},
		"a key the bind grants credentials alone": {
			auth: func(*sealing) operatorauth.AudienceAuthorizer { return releaser },
			bind: func(o *session.BindOptions) { o.Policy.Access.Credentials = []string{releaserPub} },
		},
		"a token for another guest": {auth: func(c *sealing) operatorauth.AudienceAuthorizer {
			return misdirected{signer: c.access, only: isExec, audience: "sha256:" + strings.Repeat("0", 64)}
		}},
		"a token for another route": {auth: func(c *sealing) operatorauth.AudienceAuthorizer {
			return misdirected{signer: c.access, only: isExec, path: session.PathAttest}
		}},
		"a token over other bytes": {auth: func(c *sealing) operatorauth.AudienceAuthorizer {
			return misdirected{signer: c.access, only: isExec, body: []byte(`{"id":"00000000000000000000000000000000","argv":["/bin/true"]}`)}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			c := newSealing(t)
			bind := c.bind
			if tc.bind != nil {
				bind = c.declaring(t, tc.bind)
			}
			message := c.seal(t, tc.auth(c), bind, true)
			answer := c.post(t, bind, message.Sealed)
			if answer.status != http.StatusOK || answer.bound.Sealed != session.SealedTaken || answer.sealed == nil {
				t.Fatalf("the bind's answer: %d %+v", answer.status, answer.bound)
			}
			said := opened(t, message, answer)
			if said.Command != nil || said.CommandError != session.SealedUnauthorized {
				t.Fatalf("the command's fate: %+v, %q, want it refused as unauthorized", said.Command, said.CommandError)
			}
			if n := c.runs(t); n != 0 {
				t.Fatalf("the command ran %d times", n)
			}
			if said.Credentials["api-token"] != session.SealedHeld || !bytes.Equal(c.inPlace(t, "api-token"), held()["api-token"]) {
				t.Fatalf("the credential beside a command that was refused: %v", said.Credentials)
			}
		})
	}
}

// A sealed credential is put in place only under a token its own route would
// take: of a key the bind lets release credentials, for this guest, that
// name and those bytes. The guest tells its sender otherwise, under the same
// seal, and puts nothing under that name. The other parts of the message
// stand on their own.
func TestSealedCredentialNeedsAKeyTheBindGrants(t *testing.T) {
	stranger, _ := newSigner(t)
	runner, runnerPub := newSigner(t)
	token := isCredential("api-token")
	for name, tc := range map[string]struct {
		auth func(c *sealing) operatorauth.AudienceAuthorizer
		bind func(o *session.BindOptions)
	}{
		"a key the bind does not grant": {auth: func(c *sealing) operatorauth.AudienceAuthorizer {
			return signedBy{signer: c.access, other: stranger, only: token}
		}},
		"a key the bind grants commands alone": {
			auth: func(c *sealing) operatorauth.AudienceAuthorizer {
				return signedBy{signer: c.access, other: runner, only: token}
			},
			bind: func(o *session.BindOptions) { o.Policy.Access.Exec = append(o.Policy.Access.Exec, runnerPub) },
		},
		"a token for another guest": {auth: func(c *sealing) operatorauth.AudienceAuthorizer {
			return misdirected{signer: c.access, only: token, audience: "sha256:" + strings.Repeat("0", 64)}
		}},
		"a token for another credential": {auth: func(c *sealing) operatorauth.AudienceAuthorizer {
			return misdirected{signer: c.access, only: token, path: session.PathCredentials + "signing-key"}
		}},
		"a token for another route": {auth: func(c *sealing) operatorauth.AudienceAuthorizer {
			return misdirected{signer: c.access, only: token, path: session.PathExec}
		}},
		"a token over another value": {auth: func(c *sealing) operatorauth.AudienceAuthorizer {
			return misdirected{signer: c.access, only: token, body: []byte(`{"value":"b3RoZXI="}`)}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			c := newSealing(t)
			bind := c.bind
			if tc.bind != nil {
				bind = c.declaring(t, tc.bind)
			}
			message := c.seal(t, tc.auth(c), bind, true)
			said := opened(t, message, c.post(t, bind, message.Sealed))
			if said.Credentials["api-token"] != session.SealedUnauthorized {
				t.Fatalf("the credential's fate: %q, want it refused as unauthorized", said.Credentials["api-token"])
			}
			if got := c.inPlace(t, "api-token"); got != nil {
				t.Fatalf("a credential the guest refused is in place: %q", got)
			}
			// The credential beside it is held, and the command ran without
			// the one that was refused.
			if said.Credentials["signing-key"] != session.SealedHeld || !bytes.Equal(c.inPlace(t, "signing-key"), held()["signing-key"]) {
				t.Fatalf("the credential beside one that was refused: %v", said.Credentials)
			}
			if said.Command == nil || string(said.Command.Stdout) != "first" || c.runs(t) != 1 {
				t.Fatalf("the command beside a credential that was refused: %+v, %q", said.Command, said.CommandError)
			}
		})
	}
}

// sealedInfo and sealedExport are the labels of a sealed message's HPKE
// context, as another implementation of a binder would write them.
const (
	sealedInfo   = "c8s-session sealed with a bind/v1\x00"
	sealedExport = "c8s-session sealed with a bind/v1 answer"
)

// handSealed is a message a binder of another making sealed for the guest,
// which this package's own sealing would have refused to write.
type handSealed struct {
	sealed []byte
	enc    []byte
	sender *hpke.Sender
}

// sealByHand seals plain to the guest's one-time KEM key under bind.
func (c *sealing) sealByHand(t *testing.T, bind *session.SignedBind, plain string) *handSealed {
	t.Helper()
	key, err := hpke.MLKEM768X25519().NewPublicKey(c.ready.OneTime.KEM)
	if err != nil {
		t.Fatal(err)
	}
	info := append([]byte(sealedInfo), session.DocumentDigest(bind.Raw)...)
	enc, sender, err := hpke.NewSender(key, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := sender.Seal(nil, []byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	return &handSealed{sealed: append(bytes.Clone(enc), ciphertext...), enc: enc, sender: sender}
}

// open opens the guest's sealed answer as its format says, with nothing of
// the session package's.
func (h *handSealed) open(t *testing.T, answer bindAnswer) string {
	t.Helper()
	if answer.sealed == nil || answer.sealed.Sealed != session.SealedTaken {
		t.Fatalf("the guest did not take the sealed message: %+v", answer.sealed)
	}
	sealed := answer.sealed.Answer
	secret, err := h.sender.Export(sealedExport, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) < 32 {
		t.Fatalf("an answer of %d bytes", len(sealed))
	}
	prk, err := hkdf.Extract(sha256.New, secret, append(bytes.Clone(h.enc), sealed[:32]...))
	if err != nil {
		t.Fatal(err)
	}
	key, err := hkdf.Expand(sha256.New, prk, "key", 32)
	if err != nil {
		t.Fatal(err)
	}
	iv, err := hkdf.Expand(sha256.New, prk, "nonce", 12)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := aead.Open(nil, iv, sealed[32:], nil)
	if err != nil {
		t.Fatalf("the answer does not open as its format says: %v", err)
	}
	return string(plain)
}

// part is one credential of a message written by hand: put under name, with
// the token the owner's key signs for exactly that.
func (c *sealing) part(t *testing.T, name, put string) string {
	t.Helper()
	audience, err := session.InstanceKeyDigest(c.ready.InstanceKey)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := c.access.AuthorizationFor(audience, http.MethodPut, session.PathCredentials+name, []byte(put))
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`{"name":%q,"authorization":%q,"put":%s}`, name, authorization, put)
}

// A sealed credential is taken only under a name the bind says comes from
// its binder, and only as that credential's own route would take it: a value
// of its declared size, and nothing else in what is put. The token may be in
// order all the same, since whoever holds a key the bind grants can write
// one. The guest tells its sender, and the credential beside it is held.
func TestSealedCredentialIsTakenOnlyAsItsBindDeclaresIt(t *testing.T) {
	for name, tc := range map[string]struct {
		credential, put, want string
	}{
		"a name a key hands over":          {"test-token", `{"value":"eA=="}`, session.SealedUndeclared},
		"a name the bind does not know":    {"unheard-of", `{"value":"eA=="}`, session.SealedUndeclared},
		"a value beyond its size":          {"api-token", `{"value":"MDEyMzQ1Njc4OWFiY2RlZmc="}`, session.SealedInvalid},
		"no value":                         {"api-token", `{"value":""}`, session.SealedInvalid},
		"no value at all":                  {"api-token", `{}`, session.SealedInvalid},
		"a member its route does not know": {"api-token", `{"value":"eA==","mode":"0644"}`, session.SealedInvalid},
		"what is no document":              {"api-token", `"eA=="`, session.SealedInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			c := newSealing(t)
			message := c.sealByHand(t, c.bind, `{"credentials":[`+c.part(t, tc.credential, tc.put)+`,`+c.part(t, "signing-key", `{"value":"eA=="}`)+`]}`)
			got := message.open(t, c.post(t, c.bind, message.sealed))
			want := fmt.Sprintf(`{"credentials":[{"name":%q,"status":%q},{"name":"signing-key","status":"held"}]}`, tc.credential, tc.want)
			if got != want {
				t.Fatalf("the guest's answer holds %s, want %s", got, want)
			}
			if in := c.inPlace(t, tc.credential); in != nil {
				t.Fatalf("a credential the guest refused is in place: %q", in)
			}
			if in := c.inPlace(t, "signing-key"); string(in) != "x" {
				t.Fatalf("the credential beside it: %q", in)
			}
		})
	}
}

// A credential the bind has come from its key service is taken from there
// alone: one sealed with the bind under its name is refused, whoever signed
// for it.
func TestSealedCredentialDoesNotStandInForTheKeyServices(t *testing.T) {
	c := newSealing(t)
	audience, err := session.InstanceKeyDigest(c.ready.InstanceKey)
	if err != nil {
		t.Fatal(err)
	}
	put := []byte(`{"value":"eA=="}`)
	authorization, err := c.access.AuthorizationFor(audience, http.MethodPut, session.PathCredentials+"stored-token", put)
	if err != nil {
		t.Fatal(err)
	}
	granted := (session.Access{Credentials: []string{c.accessPub}}).CredentialKeys()
	sealed := &session.OpenedCredential{Name: "stored-token", Authorization: authorization, Put: put}
	// The same credential is taken under a name its bind says comes from its
	// binder, so it is the name's source that refuses it.
	for source, want := range map[string]string{session.SourceKeyService: session.SealedUndeclared, session.SourceBinder: session.SealedHeld} {
		declared := []session.Credential{{Name: "stored-token", Source: source}}
		if got := sessionagent.PutSealedCredential(c.agent, sealed, granted, declared); got != want {
			t.Errorf("a sealed credential under a name that comes from %q: %s, want %s", source, got, want)
		}
	}
}

// A binder that had not sealed its message when it sent the bind sends it
// after: the guest opens it while it still takes the bind, has its
// credentials in place before the sandbox starts, and runs its command once
// the sandbox runs. The same message sent again gets the same answer. Once
// the sandbox is about to start, the guest opens none.
func TestSealedMessageSentAfterItsBindIsTakenWhileTheGuestTakesTheBind(t *testing.T) {
	p := newPool(t)
	p.runner.gate = make(chan struct{})
	p.runner.starting, p.runner.started = make(chan struct{}), make(chan struct{})
	p.start(t)
	c := found(t, p)
	message := c.seal(t, c.access, c.bind, true)

	bound := make(chan bindAnswer, 1)
	go func() { bound <- c.post(t, c.bind, nil) }()
	// The guest has measured the bind and is preparing its sandbox.
	until(t, "the guest took its bind", func() bool { return c.phase(t) == session.PhaseBound })
	if sessionagent.OneTimeKeysGone(c.agent) {
		t.Fatal("the guest erased its KEM key before its sandbox was prepared")
	}
	after := make(chan bindAnswer, 1)
	go func() { after <- c.late(t, message.Sealed) }()
	// It is opened on arrival, with the key, which is gone by it: long before
	// the sandbox is.
	until(t, "the guest opened the message", func() bool { return sessionagent.SealedState(c.agent) == session.SealedTaken })
	if !sessionagent.OneTimeKEMGone(c.agent) {
		t.Fatal("the guest kept its KEM key past the message it opened with it")
	}
	select {
	case early := <-after:
		t.Fatalf("the message was answered before the sandbox ran: %+v", early.sealed)
	default:
	}
	if n := c.runs(t); n != 0 {
		t.Fatalf("the command ran %d times before the sandbox started", n)
	}
	close(p.runner.gate)
	select {
	case <-p.runner.starting:
	case <-time.After(10 * time.Second):
		t.Fatal("the sandbox was never started")
	}
	// The sandbox is about to start, and finds the credentials in place.
	if got := c.inPlace(t, "api-token"); !bytes.Equal(got, held()["api-token"]) {
		t.Fatalf("as the sandbox starts, the credential sent after the bind is %q", got)
	}
	close(p.runner.started)

	answer := <-bound
	if answer.status != http.StatusOK || answer.bound.Phase != session.PhaseRunning || answer.bound.Sealed != "" || answer.sealed != nil {
		t.Fatalf("the answer to a bind that came with no sealed message: %d %+v, %+v", answer.status, answer.bound, answer.sealed)
	}
	late := <-after
	said := opened(t, message, late)
	if said.Command == nil || string(said.Command.Stdout) != "s3cr3tfirst" || c.runs(t) != 1 || said.Credentials["signing-key"] != session.SealedHeld {
		t.Fatalf("the sealed answer: %+v, after %d runs", said, c.runs(t))
	}
	if !sessionagent.OneTimeKeysGone(c.agent) {
		t.Fatal("the guest kept a one-time key")
	}
	// Sent again, it is answered as it was. Another comes too late.
	if again := c.late(t, message.Sealed); again.sealed == nil || !bytes.Equal(again.sealed.Answer, late.sealed.Answer) {
		t.Fatalf("the message sent again: %+v", again.sealed)
	}
	other := c.seal(t, c.access, c.bind, true)
	if answer := c.late(t, other.Sealed); answer.sealed == nil || answer.sealed.Sealed != session.SealedTooLate {
		t.Fatalf("a second message: %+v", answer.sealed)
	}
	if n := c.runs(t); n != 1 {
		t.Fatalf("the command ran %d times", n)
	}
}

// A sealed message that reaches the guest once its sandbox runs is refused
// unopened: the key it was sealed to went before anything of the tenant ran.
func TestSealedMessageAfterTheSandboxStartedIsTooLate(t *testing.T) {
	c := newSealing(t)
	if answer := c.post(t, c.bind, nil); answer.status != http.StatusOK || answer.bound.Phase != session.PhaseRunning {
		t.Fatalf("the bind: %d %+v", answer.status, answer.bound)
	}
	message := c.seal(t, c.access, c.bind, true)
	answer := c.late(t, message.Sealed)
	if answer.sealed == nil || answer.sealed.Sealed != session.SealedTooLate || len(answer.sealed.Answer) != 0 {
		t.Fatalf("a message after the sandbox started: %+v", answer.sealed)
	}
	if n := c.runs(t); n != 0 {
		t.Fatalf("the command ran %d times", n)
	}
	if got := c.inPlace(t, "api-token"); got != nil {
		t.Fatalf("a credential of a message that came too late is in place: %q", got)
	}
}

// A guest that no bind has reached reads no sealed message: one sent to it
// is refused on its headers, the guest stays as it was booted with the keys
// it had, and takes its bind and a message with it after.
func TestSealedMessageBeforeAnyBindIsRefusedUnread(t *testing.T) {
	c := newSealing(t)
	message := c.seal(t, c.access, c.bind, false)
	body, err := json.Marshal(session.SealedRequest{Sealed: message.Sealed})
	if err != nil {
		t.Fatal(err)
	}
	unread := &countingReader{Reader: bytes.NewReader(body)}
	rec := httptest.NewRecorder()
	c.agent.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, session.PathBindSealed, unread))
	if rec.Code != http.StatusConflict || refusalCode(rec.Body.Bytes()) != disclosure.Fenced {
		t.Fatalf("a sealed message before any bind: %d %s", rec.Code, rec.Body)
	}
	if unread.n != 0 {
		t.Fatalf("the agent read %d bytes of a message it refused", unread.n)
	}
	if rec.Header().Get("Connection") != "close" {
		t.Errorf("the refusal's headers: %v", rec.Header())
	}
	// Over the server too, and handed to the agent past it.
	if answer := c.late(t, message.Sealed); answer.status != http.StatusConflict {
		t.Fatalf("a sealed message over the server before any bind: %d", answer.status)
	}
	if answer, err := c.agent.LateSealed(ctxT(t), message.Sealed); err != nil || answer.Sealed != session.SealedTooLate {
		t.Fatalf("a sealed message handed to the agent before any bind: %+v, %v", answer, err)
	}
	if sessionagent.OneTimeKeysGone(c.agent) || c.state(t).Phase != session.PhaseReady {
		t.Fatal("a message the guest did not read changed the guest")
	}
	// The same message with the bind is the guest's one.
	answer := c.post(t, c.bind, message.Sealed)
	if result := ran(t, message, answer); string(result.Stdout) != "first" || c.runs(t) != 1 {
		t.Fatalf("the message with its bind: %+v, after %d runs", result, c.runs(t))
	}
	// One from a connection the fence ended is refused unread as well.
	unread = &countingReader{Reader: bytes.NewReader(body)}
	req := httptest.NewRequest(http.MethodPost, session.PathBindSealed, unread)
	rec = httptest.NewRecorder()
	c.agent.Handler().ServeHTTP(rec, req.WithContext(sessionagent.EndedConnContext(req.Context(), c.agent)))
	if rec.Code != http.StatusConflict || refusalCode(rec.Body.Bytes()) != disclosure.Fenced || unread.n != 0 {
		t.Fatalf("a sealed message on a connection from before the bind: %d %s, %d bytes read", rec.Code, rec.Body, unread.n)
	}
}

// A guest whose sandbox cannot be admitted ends, and acts on no message that
// came with its bind.
func TestSealedMessageOfABindThatFailsIsNotActedOn(t *testing.T) {
	p := newPool(t)
	p.runner.fail = errors.New("the image does not unpack")
	p.start(t)
	c := found(t, p)
	message := c.seal(t, c.access, c.bind, true)
	answer := c.post(t, c.bind, message.Sealed)
	if answer.status == http.StatusOK {
		t.Fatalf("a bind whose sandbox was not admitted was answered: %+v", answer.bound)
	}
	if err := p.fatal(t); err == nil {
		t.Fatal("the guest carries on")
	}
	if n := c.runs(t); n != 0 {
		t.Fatalf("the command ran %d times", n)
	}
	if got := c.inPlace(t, "api-token"); got != nil {
		t.Fatalf("a guest that admitted no sandbox put a credential in place: %q", got)
	}
}

// A message whose sender went away is acted on all the same, since the guest
// took it, and its answer is kept for the bind sent again.
func TestSealedMessageOfASenderThatWentAwayIsKept(t *testing.T) {
	c := newSealing(t)
	c.runner.starting, c.runner.started = make(chan struct{}), make(chan struct{})
	message := c.seal(t, c.access, c.bind, true)
	body, err := json.Marshal(session.BindRequest{Bind: c.bind.Raw, Signature: c.bind.Signature, Sealed: message.Sealed})
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
	again := c.post(t, c.bind, message.Sealed)
	said := opened(t, message, again)
	if said.Command == nil || string(said.Command.Stdout) != "s3cr3tfirst" || c.runs(t) != 1 || said.Credentials["api-token"] != session.SealedHeld {
		t.Fatalf("the bind sent again: %+v, after %d runs", said, c.runs(t))
	}
}
