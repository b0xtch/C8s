//go:build unix

// Package sandboxinit is the first process of a session's sandbox until its
// session is bound.
//
// A guest's agent makes the sandbox's container before any bind arrives, with
// this program as its process: the container's namespaces, mounts and limits
// then exist, and nothing of an image has run. When the bind says what the
// sandbox runs, the agent sends one message, and this program becomes the
// image's process in place: same process, same id, no runtime in between.
//
// The runtime preserves two descriptors for it. ProgramFD is this program's
// own file, which is how a container that does not hold the file starts it.
// ControlFD is one end of a socket pair. The agent writes a Process to it and
// shuts its side down. This program answers with one line, Taken, once it
// has the message and has found the command, and then becomes the process.
// If it cannot, it says why on a line and exits. Neither descriptor outlives
// it: the image's process inherits no way back to the agent.
//
// The agent also starts this program for a command, ahead of the command
// (see the agent's warmCommand). A process that ends without a word, before
// it took its message, has started nothing, and its command is started
// another way.
package sandboxinit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	// ProgramFD and ControlFD are the descriptors the runtime preserves.
	ProgramFD = 3
	ControlFD = 4
	// MaxMessage bounds the agent's message.
	MaxMessage = 1 << 20
	// FailureStatus is the status this program exits with when it could not
	// become the process: a shell's for a command that was not run.
	FailureStatus = 127
	// Taken is the line this program writes when it has its message and has
	// found the command: the exec is what follows.
	Taken = "ok"
	// MaxAnswer bounds what the agent reads of this program's answer.
	MaxAnswer = 4096
	// defaultPath is searched for a command named without a directory when
	// the process's environment sets no PATH.
	defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

// Process is what the sandbox's first process becomes.
type Process struct {
	// Argv is the command and its arguments. A command named without a
	// directory is looked up in the PATH that Env sets.
	Argv []string `json:"argv"`
	// Env is the whole environment, as NAME=value.
	Env []string `json:"env"`
	// Cwd is the working directory.
	Cwd string `json:"cwd"`
}

// Main reads the agent's message and becomes the process it names. It
// returns only if it could not, with the status to exit with.
func Main() int {
	// Before anything else: a process this one starts by mistake inherits
	// neither.
	unix.CloseOnExec(ProgramFD)
	unix.CloseOnExec(ControlFD)
	// While it waits, this process holds a socket to the agent, and other
	// code may run beside it under its user. Undumpable, it is one such
	// code cannot attach to, and whose descriptors and memory it cannot
	// open. The process it becomes is an ordinary one again.
	undumpable()
	control := os.NewFile(ControlFD, "control")
	if control == nil {
		return FailureStatus
	}
	err := become(control)
	// Reached only when the exec did not happen.
	fmt.Fprintf(control, "%v\n", err)
	return FailureStatus
}

func become(control io.ReadWriter) error {
	p, err := Read(control)
	if err != nil {
		return err
	}
	if p.Cwd != "" {
		if err := os.Chdir(p.Cwd); err != nil {
			return fmt.Errorf("working directory: %w", err)
		}
	}
	path, err := Lookup(p.Argv[0], p.Env)
	if err != nil {
		return err
	}
	// From here the message is taken: whatever becomes of this process is
	// the outcome of the command it was for.
	if _, err := io.WriteString(control, Taken+"\n"); err != nil {
		return fmt.Errorf("tell the agent the command is taken: %w", err)
	}
	err = unix.Exec(path, p.Argv, p.Env)
	if errors.Is(err, unix.ENOENT) {
		// The file, or the interpreter its first line names.
		return fmt.Errorf("%s: command not found", path)
	}
	return fmt.Errorf("run %s: %w", path, err)
}

// ReadAnswer reads what an init said on its way, from the agent's end of its
// socket: whether it took its message, and why it could not become the
// process, if it could not. It returns when the init's end has closed, which
// is at its exec or at its end. An init that says nothing and took nothing
// ended before it was told anything.
func ReadAnswer(control io.Reader) (taken bool, reason string) {
	data, _ := io.ReadAll(io.LimitReader(control, MaxAnswer))
	text := string(data)
	if rest, ok := strings.CutPrefix(text, Taken+"\n"); ok {
		taken, text = true, rest
	}
	return taken, strings.TrimSpace(text)
}

// Read reads one message, which ends where its sender stops writing.
func Read(control io.Reader) (*Process, error) {
	data, err := io.ReadAll(io.LimitReader(control, MaxMessage+1))
	if err != nil {
		return nil, fmt.Errorf("read the process to become: %w", err)
	}
	if len(data) > MaxMessage {
		return nil, fmt.Errorf("the process to become is described in more than %d bytes", MaxMessage)
	}
	var p Process
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("the process to become: %w", err)
	}
	if len(p.Argv) == 0 || p.Argv[0] == "" {
		return nil, errors.New("the process to become names no command")
	}
	return &p, nil
}

// Lookup finds the file a command names, as execvp does: a name with a
// directory in it is that path, and any other is searched for in the PATH
// that env sets.
func Lookup(command string, env []string) (string, error) {
	if strings.Contains(command, "/") {
		return command, nil
	}
	path := defaultPath
	for _, kv := range env {
		if value, ok := strings.CutPrefix(kv, "PATH="); ok {
			path = value
		}
	}
	for _, dir := range filepath.SplitList(path) {
		if dir == "" {
			dir = "."
		}
		candidate := filepath.Join(dir, command)
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && unix.Access(candidate, unix.X_OK) == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("%s: command not found in %s", command, path)
}
