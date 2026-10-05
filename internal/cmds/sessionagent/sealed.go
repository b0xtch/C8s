package sessionagent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"net/http"
	"sync"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// sealedMessage is the one sealed message a guest may take with its bind:
// sealed to its one-time KEM key, opened while the guest takes the bind, and
// answered under a key only its sender shares. Its credentials are put in
// place before the sandbox starts, and its command is run once the sandbox
// runs. It is taken once and acted on once: the same message sent again is
// answered with what the first was.
type sealedMessage struct {
	mu sync.Mutex
	// state is what became of it: empty while one may still come, then
	// session.SealedTaken, SealedUnopened or SealedTooLate. The last also
	// stands for a guest whose bind came with none.
	state  string
	opened *session.OpenedSealed
	// came says a message has come, and digest is its digest, which the
	// same message sent again is told apart from another by.
	came   bool
	digest [sha256.Size]byte
	// credentials is what became of each credential the message carried,
	// once the guest has acted on them.
	credentials []session.CredentialOutcome
	// answer is its sealed answer, from when done is closed.
	answer []byte
	done   chan struct{}
}

// takeSealed opens sealed as the guest's one sealed message, if the guest
// still holds the key for one, and says what became of it. Whatever the
// outcome, the key is gone after it: a guest tries one message or none. The
// same message sent again is told what became of it the first time, and any
// other that it came too late.
func (a *Agent) takeSealed(bind *session.SignedBind, sealed []byte) string {
	s := &a.sealed
	digest := sha256.Sum256(sealed)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != "" {
		if s.came && s.digest == digest {
			return s.state
		}
		return session.SealedTooLate
	}
	s.came, s.digest = true, digest
	opened, err := a.oneTime.open(bind, sealed)
	switch {
	case errors.Is(err, errKEMGone):
		s.state = session.SealedTooLate
	case err != nil:
		s.state = session.SealedUnopened
	default:
		s.state, s.opened, s.done = session.SealedTaken, opened, make(chan struct{})
	}
	// What the message holds stays out of the log: it is the tenant's.
	a.log.Info("a sealed message came", "sealed", s.state, "bytes", len(sealed))
	return s.state
}

// closeSealed ends the time in which a sealed message may come, and erases
// the key one would have opened under. The sandbox starts after it.
func (a *Agent) closeSealed() {
	s := &a.sealed
	s.mu.Lock()
	if s.state == "" {
		s.state = session.SealedTooLate
	}
	s.mu.Unlock()
	a.oneTime.eraseKEM()
}

// putSealedCredentials puts in place the credentials of the message the
// guest took, before its sandbox starts. Each is taken as its route would
// take it, and only under a name the bind says comes from its binder: the
// message may have been sealed by anyone who had the guest's evidence.
func (a *Agent) putSealedCredentials() {
	s := &a.sealed
	s.mu.Lock()
	opened := s.opened
	s.mu.Unlock()
	if opened == nil || len(opened.Credentials) == 0 {
		return
	}
	access, declared := a.grants()
	granted := access.CredentialKeys()
	outcomes := make([]session.CredentialOutcome, 0, len(opened.Credentials))
	for i := range opened.Credentials {
		c := &opened.Credentials[i]
		outcomes = append(outcomes, session.CredentialOutcome{Name: c.Name, Status: a.putSealedCredential(c, granted, declared)})
		// The value is in place, or was refused: no copy of it waits here.
		clear(c.Put)
	}
	s.mu.Lock()
	s.credentials = outcomes
	s.mu.Unlock()
}

func (a *Agent) putSealedCredential(c *session.OpenedCredential, granted []*ecdsa.PublicKey, declared []session.Credential) string {
	var decl *session.Credential
	for i := range declared {
		if declared[i].Name == c.Name {
			decl = &declared[i]
		}
	}
	if decl == nil || decl.Source != session.SourceBinder {
		return session.SealedUndeclared
	}
	if len(granted) == 0 {
		return session.SealedUnauthorized
	}
	// The token is the one the credential's own route takes: for this guest,
	// that name and these bytes, under a key the bind grants it.
	asked, err := http.NewRequest(http.MethodPut, session.PathCredentials+c.Name, bytes.NewReader(c.Put))
	if err != nil {
		return session.SealedInvalid
	}
	asked.Header.Set("Authorization", c.Authorization)
	if _, err := a.verifier(granted).AuthorizedBy(asked, c.Put); err != nil {
		a.log.Warn("a sealed credential was refused", "name", c.Name, "error", err)
		return session.SealedUnauthorized
	}
	var req session.CredentialRequest
	if !decodeStrict(c.Put, &req) || len(req.Value) == 0 || len(req.Value) > decl.Limit() {
		return session.SealedInvalid
	}
	size := len(req.Value)
	_, err = a.creds.put(c.Name, req.Value)
	clear(req.Value)
	if err != nil {
		a.log.Warn("a sealed credential was not put", "name", c.Name, "error", err)
		return session.SealedFailed
	}
	a.log.Info("credential released", "name", c.Name, "bytes", size, "sealed", true)
	return session.SealedHeld
}

// answerSealed runs the command of the message the guest took, if it holds
// one, and keeps the message's sealed answer. The sandbox runs by now. It is
// called once.
func (a *Agent) answerSealed(ctx context.Context) {
	s := &a.sealed
	s.mu.Lock()
	opened, credentials := s.opened, s.credentials
	s.opened = nil
	s.mu.Unlock()
	if opened == nil {
		return
	}
	outcome := session.SealedOutcome{Credentials: credentials}
	if opened.Command != nil {
		outcome.Command, outcome.CommandError = a.runSealedCommand(ctx, opened.Command)
	}
	answer, err := opened.Seal(outcome)
	opened.Forget()
	if err != nil {
		a.log.Warn("the answer to a sealed message could not be sealed", "error", err)
	}
	s.mu.Lock()
	s.answer = answer
	close(s.done)
	s.mu.Unlock()
}

// runSealedCommand authorizes and runs a sealed command as PathExec would.
// It returns the command's result, or the one word of why there is none.
func (a *Agent) runSealedCommand(ctx context.Context, command *session.OpenedCommand) (*session.ExecResponse, string) {
	access, _ := a.grants()
	granted := access.ExecKeys()
	if len(granted) == 0 {
		return nil, session.SealedUnauthorized
	}
	// The token is the one PathExec takes: for this guest, that route and
	// these bytes, under a key the bind grants it.
	asked, err := http.NewRequestWithContext(ctx, http.MethodPost, session.PathExec, bytes.NewReader(command.Exec))
	if err != nil {
		return nil, session.SealedInvalid
	}
	asked.Header.Set("Authorization", command.Authorization)
	if _, err := a.verifier(granted).AuthorizedBy(asked, command.Exec); err != nil {
		a.log.Warn("a sealed command was refused", "error", err)
		return nil, session.SealedUnauthorized
	}
	var req session.ExecRequest
	if !decodeStrict(command.Exec, &req) || req.Validate() != nil {
		return nil, session.SealedInvalid
	}
	result, err := a.execs.run(ctx, &req)
	if err != nil {
		// The command line and its output are tenant data: neither is logged.
		a.log.Warn("a sealed command failed", "id", req.ID, "error", err)
		return nil, session.SealedFailed
	}
	return result, ""
}

// sealedReply waits for the sealed answer of the message the guest took and
// returns it with what became of the message. A guest that took none answers
// at once.
func (a *Agent) sealedReply(ctx context.Context) (*session.SealedReply, error) {
	s := &a.sealed
	s.mu.Lock()
	state, done := s.state, s.done
	s.mu.Unlock()
	if state != session.SealedTaken {
		if state == "" {
			state = session.SealedTooLate
		}
		return &session.SealedReply{Sealed: state}, nil
	}
	select {
	case <-done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return &session.SealedReply{Sealed: session.SealedTaken, Answer: s.answer}, nil
}

// sealedFor is what a bind's answer says of the message that came with that
// bind. Empty for a bind that came with none. A bind sent again with the
// message the guest took is told so, and gets its answer. With another, it
// is told that one came too late.
func (a *Agent) sealedFor(sealed []byte) string {
	if len(sealed) == 0 {
		return ""
	}
	s := &a.sealed
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.came || s.digest != sha256.Sum256(sealed) {
		return session.SealedTooLate
	}
	return s.state
}

// LateSealed takes a sealed message that follows its bind instead of coming
// with it. The guest opens it if it is still taking that bind and has tried
// none, and answers once it has acted on it. One that comes after the guest
// erased its one-time KEM key is refused unopened.
func (a *Agent) LateSealed(ctx context.Context, sealed []byte) (*session.SealedReply, error) {
	// A bind that has arrived is measured or refused first, and has opened
	// the message that came with it.
	a.binding.Lock()
	a.measured.RLock()
	bind, retired := a.bind, a.retired
	a.measured.RUnlock()
	a.binding.Unlock()
	if bind == nil || retired {
		// No bind is measured, so there is nothing to open one under.
		return &session.SealedReply{Sealed: session.SealedTooLate}, nil
	}
	if state := a.takeSealed(bind, sealed); state != session.SealedTaken {
		return &session.SealedReply{Sealed: state}, nil
	}
	// The guest acts on it with the bind's own start.
	return a.sealedReply(ctx)
}

// writeDocument writes one more JSON document of an answer that has several.
func writeDocument(w http.ResponseWriter, body []byte) {
	_, _ = w.Write(body)
	if !bytes.HasSuffix(body, []byte("\n")) {
		_, _ = w.Write([]byte("\n"))
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}
