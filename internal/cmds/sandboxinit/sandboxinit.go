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
// shuts its side down. This program answers only if it cannot become the
// process, with the reason on one line, and then exits. Neither descriptor
// outlives it: the image's process inherits no way back to the agent.
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
	control := os.NewFile(ControlFD, "control")
	if control == nil {
		return FailureStatus
	}
	err := become(control)
	// Reached only when the exec did not happen.
	fmt.Fprintf(control, "%v\n", err)
	return FailureStatus
}

func become(control io.Reader) error {
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
	err = unix.Exec(path, p.Argv, p.Env)
	if errors.Is(err, unix.ENOENT) {
		// The file, or the interpreter its first line names.
		return fmt.Errorf("%s: command not found", path)
	}
	return fmt.Errorf("run %s: %w", path, err)
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
