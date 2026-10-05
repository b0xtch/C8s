package sessionagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"sync"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// firstCommand is the one command a guest may take with its bind: sealed to
// its one-time KEM key, opened while the guest takes the bind, run once the
// sandbox runs, and answered under a key only its sender shares. It is taken
// once and run once: a bind sent again is answered with what the first was.
type firstCommand struct {
	mu sync.Mutex
	// state is what became of it: empty while one may still come, then
	// session.CommandTaken, CommandUnopened or CommandTooLate. The last also
	// stands for a guest whose bind came with none.
	state  string
	opened *session.OpenedFirstCommand
	// came says a command has come, and sealed is its digest, which the
	// same command sent again is told apart from another by.
	came   bool
	sealed [sha256.Size]byte
	// answer is its sealed answer, from when done is closed.
	answer []byte
	done   chan struct{}
}

// takeCommand opens sealed as the guest's first command, if the guest still
// holds the key for one, and says what became of it. Whatever the outcome,
// the key is gone after it: a guest opens one command or none. The same
// command sent again is told what became of it the first time, and any other
// that it came too late.
func (a *Agent) takeCommand(bind *session.SignedBind, sealed []byte) string {
	c := &a.command
	digest := sha256.Sum256(sealed)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != "" {
		if c.came && c.sealed == digest {
			return c.state
		}
		return session.CommandTooLate
	}
	c.came, c.sealed = true, digest
	opened, err := a.oneTime.open(bind, sealed)
	switch {
	case errors.Is(err, errKEMGone):
		c.state = session.CommandTooLate
	case err != nil:
		c.state = session.CommandUnopened
	default:
		c.state, c.opened, c.done = session.CommandTaken, opened, make(chan struct{})
	}
	// What the command is stays out of the log: it is the tenant's.
	a.log.Info("a first command came", "command", c.state, "bytes", len(sealed))
	return c.state
}

// closeCommand ends the time in which a first command may come, and erases
// the key one would have opened under. The sandbox starts after it.
func (a *Agent) closeCommand() {
	c := &a.command
	c.mu.Lock()
	if c.state == "" {
		c.state = session.CommandTooLate
	}
	c.mu.Unlock()
	a.oneTime.eraseKEM()
}

// runCommand runs the first command the guest took, if it took one, and
// keeps its sealed answer. The sandbox runs by now. It is called once.
func (a *Agent) runCommand(ctx context.Context) {
	c := &a.command
	c.mu.Lock()
	opened := c.opened
	c.opened = nil
	c.mu.Unlock()
	if opened == nil {
		return
	}
	answer, err := a.answerCommand(ctx, opened)
	opened.Forget()
	if err != nil {
		a.log.Warn("the first command's answer could not be sealed", "error", err)
	}
	c.mu.Lock()
	c.answer = answer
	close(c.done)
	c.mu.Unlock()
}

// answerCommand authorizes and runs an opened first command as PathExec
// would, and seals what came of it for its sender.
func (a *Agent) answerCommand(ctx context.Context, opened *session.OpenedFirstCommand) ([]byte, error) {
	if len(opened.Exec) == 0 {
		return opened.Refuse(session.FirstCommandInvalid)
	}
	access, _ := a.grants()
	granted := access.ExecKeys()
	// The token is the one PathExec takes: for this guest, that route and
	// these bytes, under a key the bind grants it.
	asked, err := http.NewRequestWithContext(ctx, http.MethodPost, session.PathExec, bytes.NewReader(opened.Exec))
	if err != nil {
		return nil, err
	}
	asked.Header.Set("Authorization", opened.Authorization)
	if len(granted) == 0 {
		return opened.Refuse(session.FirstCommandUnauthorized)
	}
	if _, err := a.verifier(granted).AuthorizedBy(asked, opened.Exec); err != nil {
		a.log.Warn("the first command was refused", "error", err)
		return opened.Refuse(session.FirstCommandUnauthorized)
	}
	var req session.ExecRequest
	if !decodeStrict(opened.Exec, &req) || req.Validate() != nil {
		return opened.Refuse(session.FirstCommandInvalid)
	}
	result, err := a.execs.run(ctx, &req)
	if err != nil {
		// The command line and its output are tenant data: neither is logged.
		a.log.Warn("the first command failed", "id", req.ID, "error", err)
		return opened.Refuse(session.FirstCommandFailed)
	}
	return opened.Seal(result)
}

// commandAnswer waits for the first command's sealed answer and returns it
// with what became of the command. A guest that took none answers at once.
func (a *Agent) commandAnswer(ctx context.Context) (*session.CommandAnswer, error) {
	c := &a.command
	c.mu.Lock()
	state, done := c.state, c.done
	c.mu.Unlock()
	if state != session.CommandTaken {
		if state == "" {
			state = session.CommandTooLate
		}
		return &session.CommandAnswer{Command: state}, nil
	}
	select {
	case <-done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return &session.CommandAnswer{Command: session.CommandTaken, Answer: c.answer}, nil
}

// commandFor is what a bind's answer says of the first command: what became
// of sealed, the command that came with that bind. Empty for a bind that
// came with none. A bind sent again with the command the guest took is told
// so, and gets its answer. With another, it is told that one came too late.
func (a *Agent) commandFor(sealed []byte) string {
	if len(sealed) == 0 {
		return ""
	}
	c := &a.command
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.came || c.sealed != sha256.Sum256(sealed) {
		return session.CommandTooLate
	}
	return c.state
}

// LateCommand takes a first command that follows its bind instead of coming
// with it. The guest opens it if it is still taking that bind and has opened
// none, and answers once the command has run. One that comes after the guest
// erased its one-time KEM key is refused unopened.
func (a *Agent) LateCommand(ctx context.Context, sealed []byte) (*session.CommandAnswer, error) {
	// A bind that has arrived is measured or refused first, and has opened
	// the command that came with it.
	a.binding.Lock()
	a.measured.RLock()
	bind, retired := a.bind, a.retired
	a.measured.RUnlock()
	a.binding.Unlock()
	if bind == nil || retired {
		// No bind is measured, so there is nothing to open one under.
		return &session.CommandAnswer{Command: session.CommandTooLate}, nil
	}
	if state := a.takeCommand(bind, sealed); state != session.CommandTaken {
		return &session.CommandAnswer{Command: state}, nil
	}
	// The command runs once the sandbox does, with the one that came with
	// the bind's own start.
	return a.commandAnswer(ctx)
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
