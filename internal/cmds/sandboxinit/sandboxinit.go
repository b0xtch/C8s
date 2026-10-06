//go:build unix

// Package sandboxinit is the first process of a session's sandbox: all of it
// until the session is bound, and from then on too unless the bind names a
// process for the session.
//
// A guest's agent makes the sandbox's container before any bind arrives, with
// this program as its process: the container's namespaces, mounts and limits
// then exist, and nothing of an image has run. When the bind says what the
// sandbox runs, the agent sends one message. For a session that names no
// process of its own, the message says to stay: this program remains the
// sandbox's first process and reaps what the session's commands leave behind.
// For one that names its image's command, this program becomes that process
// in place: same process, same id, no runtime in between.
//
// The runtime preserves two descriptors for it. ProgramFD is this program's
// own file, which is how a container that does not hold the file starts it.
// ControlFD is one end of a socket pair. The agent writes a Process to it and
// shuts its side down. This program answers with one line, Taken, once it
// has the message and has found the command, and then becomes the process,
// or stays. If it cannot, it says why on a line and exits. Neither descriptor
// outlives its answer: the image's process inherits no way back to the
// agent, and a program that stays closes both.
//
// The agent may pass one more descriptor with its message, the write end of
// a pipe. This program does nothing with it but keep it, closed at its exec
// or when it stays: the agent's end then reads the end of the pipe the
// moment this process has become the image's, stays, or is gone, and need
// not look for any of them.
//
// The agent also starts this program for a command, ahead of the command
// (see the agent's warmCommand). A process that ends without a word, before
// it took its message, has started nothing, and its command is started
// another way.
//
// Started with SpawnArg as its one argument, this program is the sandbox's
// spawner instead: it stays, and starts a copy of itself for a command each
// time the agent asks, so that the runtime starts one process in a sandbox
// for all of its commands and none for each. See spawn.
package sandboxinit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
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
	// maxPassed is how many descriptors this program keeps of those that
	// come with its message. Any more are closed as they arrive.
	maxPassed = 1
	// defaultPath is searched for a command named without a directory when
	// the process's environment sets no PATH.
	defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	// SpawnArg is the argument that starts this program as a spawner.
	SpawnArg = "spawn"
	// The words of a spawner's packets to the agent, each followed by the
	// number of the request it answers, counted from 0: a process was
	// started for it, with a descriptor for the process; none was, with the
	// reason; the process it started has ended, with its exit status and the
	// signal that ended it, of which one is 0.
	Spawned     = "started"
	SpawnFailed = "failed"
	SpawnEnded  = "ended"
	// SpawnRequest is how many descriptors come with a request: the control
	// socket of the process to start, its standard three, and the file that
	// puts a process in the cgroup made for this one.
	SpawnRequest = 5
	// MaxSpawnPacket bounds a packet of either side.
	MaxSpawnPacket = 512
)

// Process is what the sandbox's first process becomes, or that it stays.
type Process struct {
	// Stay has this program stay the sandbox's first process and reap what
	// ends under it. It goes with no command.
	Stay bool `json:"stay,omitempty"`
	// Argv is the command and its arguments. A command named without a
	// directory is looked up in the PATH that Env sets.
	Argv []string `json:"argv"`
	// Env is the whole environment, as NAME=value.
	Env []string `json:"env"`
	// Cwd is the working directory.
	Cwd string `json:"cwd"`
}

// errStays is how become says that the message was to stay, and was taken.
var errStays = errors.New("stay")

// Main reads the agent's message and becomes the process it names, or stays
// as the sandbox's first process until the sandbox is ended. It returns only
// if it could do neither, with the status to exit with.
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
	if len(os.Args) == 2 && os.Args[1] == SpawnArg {
		return spawn()
	}
	control := os.NewFile(ControlFD, "control")
	if control == nil {
		return FailureStatus
	}
	taken := &taking{fd: ControlFD}
	err := become(struct {
		io.Reader
		io.Writer
	}{taken, control})
	if errors.Is(err, errStays) {
		// Nothing more is said to the agent, and nothing of it is kept.
		_ = control.Close()
		_ = unix.Close(ProgramFD)
		taken.release()
		stay()
	}
	// Reached only when the exec did not happen.
	fmt.Fprintf(control, "%v\n", err)
	return FailureStatus
}

// stay reaps every process that ends as this one's child, which for a
// sandbox's first process is every orphan in it. It does not return: the
// sandbox ends when its agent kills it.
func stay() {
	ended := make(chan os.Signal, 1)
	signal.Notify(ended, unix.SIGCHLD)
	for {
		for {
			pid, err := unix.Wait4(-1, nil, unix.WNOHANG, nil)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if pid <= 0 || err != nil {
				break
			}
		}
		<-ended
	}
}

func become(control io.ReadWriter) error {
	p, err := Read(control)
	if err != nil {
		return err
	}
	if p.Stay {
		if _, err := io.WriteString(control, Taken+"\n"); err != nil {
			return fmt.Errorf("tell the agent the message is taken: %w", err)
		}
		return errStays
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
	// The session's own code runs on every processor of its guest.
	everyProcessor()
	err = unix.Exec(path, p.Argv, p.Env)
	if errors.Is(err, unix.ENOENT) {
		// The file, or the interpreter its first line names.
		return fmt.Errorf("%s: command not found", path)
	}
	return fmt.Errorf("run %s: %w", path, err)
}

// taking reads the agent's message off the control socket, and keeps the
// descriptors that come with it, closed at this program's exec.
type taking struct {
	fd   int
	kept []int
}

// release closes the descriptors that came with the message.
func (t *taking) release() {
	for _, fd := range t.kept {
		_ = unix.Close(fd)
	}
	t.kept = nil
}

func (t *taking) Read(p []byte) (int, error) {
	oob := make([]byte, unix.CmsgSpace(4*8))
	for {
		n, oobn, _, _, err := unix.Recvmsg(t.fd, p, oob, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		t.keep(oob[:oobn])
		if n == 0 {
			return 0, io.EOF
		}
		return n, nil
	}
}

// keep holds on to the descriptors in one message's control data, up to
// maxPassed of them, and closes the rest. None survives this program's exec.
func (t *taking) keep(control []byte) {
	messages, err := unix.ParseSocketControlMessage(control)
	if err != nil {
		return
	}
	for i := range messages {
		passed, err := unix.ParseUnixRights(&messages[i])
		if err != nil {
			continue
		}
		for _, fd := range passed {
			if len(t.kept) >= maxPassed {
				_ = unix.Close(fd)
				continue
			}
			unix.CloseOnExec(fd)
			t.kept = append(t.kept, fd)
		}
	}
}

// ReadAnswer reads what an init said on its way, from the agent's end of its
// socket: whether it took its message, and why it could not become the
// process, if it could not. It returns when the init's end has closed, which
// is at its exec or at its end. An init that says nothing and took nothing
// ended before it was told anything.
func ReadAnswer(control io.Reader) (taken bool, reason string) {
	data, _ := io.ReadAll(io.LimitReader(control, MaxAnswer))
	return ParseAnswer(data)
}

// ParseAnswer reads what an init has said so far: whether it took its
// message, and its reason if it gave one after or instead.
func ParseAnswer(said []byte) (taken bool, reason string) {
	text := string(said)
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
	if p.Stay {
		if len(p.Argv) > 0 {
			return nil, errors.New("a process that stays is told no command")
		}
		return &p, nil
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
