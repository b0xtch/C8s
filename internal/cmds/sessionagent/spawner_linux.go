//go:build linux

package sessionagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sandboxinit"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// spawnWait bounds the spawner's answer to one request. A fork and an exec
// take it well under a millisecond: one that has not answered by then is
// stopped or gone, and its sandbox's commands are started by the runtime
// from there on.
const spawnWait = 2 * time.Second

// spawner is the agent's end of a sandbox's spawner: the sandbox init,
// started once by the runtime in the sandbox's container, which starts the
// init again for each command to come (see sandboxinit). The runtime's part
// of starting a command is then done once for the sandbox, where a waiting
// process started by the runtime costs the runtime's own start each time.
//
// A spawner runs as the image's user, beside the tenant's code. It is
// undumpable, so that code cannot attach to it or open its socket, and
// nothing a session is promised rests on its word. The agent acts on a
// process it names only through the descriptor that came for it, never by a
// number alone: in the agent's namespace a number can name another process
// once its own has ended. So the spawner puts each process in its command's
// cgroup itself, through a file the agent hands it that can do nothing else,
// and the agent takes the process for the command's only once it has read
// that the process runs the init's own file in that cgroup and the
// descriptor still names it. It kills by that cgroup, and learns how a
// process ended from the kernel, through the same descriptor: a spawner
// says nothing of an end, and a command it started goes on without it. Code
// that kills its sandbox's spawner has later commands start the slow way.
type spawner struct {
	conn  *net.UnixConn
	group *processGroup
	dir   string
	// exited is closed when the runtime that started the spawner has ended.
	exited chan struct{}

	mu sync.Mutex
	// asked counts the requests sent, which is how the spawner numbers them.
	asked   int
	answers map[int]chan spawnAnswer
	// gone is closed when the spawner's socket has failed or been closed:
	// nothing more comes from it.
	gone     chan struct{}
	goneOnce sync.Once
}

// spawnAnswer is the spawner's answer to one request: a descriptor for the
// process it started, or why it started none.
type spawnAnswer struct {
	process *os.File
	reason  string
}

// spawnEnd is how a process the spawner started ended, as the kernel says:
// its exit status, or the signal that ended it.
type spawnEnd struct{ status, signal int }

// code is the exit status a shell would give.
func (e spawnEnd) code() int {
	if e.signal != 0 {
		return 128 + e.signal
	}
	return e.status
}

// startSpawner has the runtime start the sandbox's spawner: as it starts a
// command's process, in a cgroup of its own, with a socket of packets where
// a command's process has its control socket.
func (r *ImageRunner) startSpawner(image *specs.Process) (_ *spawner, err error) {
	const id = "spawner"
	s := &spawner{
		dir: filepath.Join(r.cfg.RunDir, "exec-"+id), exited: make(chan struct{}),
		answers: map[int]chan spawnAnswer{}, gone: make(chan struct{}),
	}
	if !kernelSaysEnds() {
		return nil, errors.New("this kernel does not say through a process's descriptor how the process ended")
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			if s.conn != nil {
				_ = s.conn.Close()
			}
			if s.group != nil {
				s.group.close()
			}
			_ = os.RemoveAll(s.dir)
		}
	}()
	init := *image
	init.Args = []string{fmt.Sprintf("/proc/self/fd/%d", sandboxinit.ProgramFD), sandboxinit.SpawnArg}
	init.Env = []string{"PATH=" + defaultSandboxPath}
	init.Cwd = "/"
	process, err := json.Marshal(&init)
	if err != nil {
		return nil, err
	}
	processPath := filepath.Join(s.dir, "process.json")
	if err := os.WriteFile(processPath, process, 0o600); err != nil {
		return nil, err
	}
	if s.group, err = newProcessGroup(r.cgroupDir(), id); err != nil {
		return nil, err
	}
	program, err := os.Open(r.cfg.SandboxInit)
	if err != nil {
		return nil, fmt.Errorf("the sandbox's init: %w", err)
	}
	defer program.Close()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("the spawner's socket: %w", err)
	}
	ours, theirs := os.NewFile(uintptr(pair[0]), "spawner-control"), os.NewFile(uintptr(pair[1]), "spawner")
	defer theirs.Close()
	conn, err := net.FileConn(ours)
	_ = ours.Close()
	if err != nil {
		return nil, fmt.Errorf("the spawner's socket: %w", err)
	}
	var packets bool
	if s.conn, packets = conn.(*net.UnixConn); !packets {
		_ = conn.Close()
		return nil, errors.New("the spawner's socket is no unix socket")
	}
	// Not under a context: the spawner lives as long as its sandbox.
	cmd := r.crun(context.Background(), "--log", "file:"+filepath.Join(s.dir, "crun.log"), "exec", "--process", processPath,
		"--cgroup", filepath.Base(s.group.dir), "--preserve-fds", "2", sandboxID)
	cmd.ExtraFiles = []*os.File{program, theirs}
	cmd.SysProcAttr = s.group.sysProcAttr(-1, -1)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start crun: %w", err)
	}
	// What a spawner starts inherits this: no command needs it set again.
	s.group.started(cmd.Process)
	go func() {
		_ = cmd.Wait()
		close(s.exited)
		s.fail()
	}()
	go s.read()
	return s, nil
}

// fail marks the spawner as gone, once: every wait on it ends.
func (s *spawner) fail() { s.goneOnce.Do(func() { close(s.gone) }) }

// read takes the spawner's packets until its socket fails, and hands each to
// whoever waits for it.
func (s *spawner) read() {
	defer s.fail()
	packet, control := make([]byte, sandboxinit.MaxSpawnPacket), make([]byte, unix.CmsgSpace(4*4))
	for {
		n, controlled, _, _, err := s.conn.ReadMsgUnix(packet, control)
		if err != nil || n == 0 {
			return
		}
		passed := passedFiles(control[:controlled])
		words := strings.Fields(string(packet[:n]))
		if len(words) < 2 {
			closeAll(passed)
			continue
		}
		of, err := strconv.Atoi(words[1])
		if err != nil {
			closeAll(passed)
			continue
		}
		s.mu.Lock()
		switch words[0] {
		case sandboxinit.Spawned, sandboxinit.SpawnFailed:
			answer := s.answers[of]
			delete(s.answers, of)
			switch {
			case answer == nil:
			case words[0] == sandboxinit.Spawned && len(passed) == 1:
				answer <- spawnAnswer{process: passed[0]}
				passed = nil
			case words[0] == sandboxinit.Spawned:
				answer <- spawnAnswer{reason: "the spawner named no process"}
			default:
				answer <- spawnAnswer{reason: strings.Join(words[2:], " ")}
			}
		}
		s.mu.Unlock()
		closeAll(passed)
	}
}

// passedFiles is every descriptor in one packet's control data. The kernel
// marks them close-on-exec as it hands them over.
func passedFiles(control []byte) []*os.File {
	messages, err := unix.ParseSocketControlMessage(control)
	if err != nil {
		return nil
	}
	var files []*os.File
	for i := range messages {
		fds, err := unix.ParseUnixRights(&messages[i])
		if err != nil {
			continue
		}
		for _, fd := range fds {
			files = append(files, os.NewFile(uintptr(fd), "passed"))
		}
	}
	return files
}

func closeAll(files []*os.File) {
	for _, f := range files {
		_ = f.Close()
	}
}

// start asks the spawner for one process with these descriptors as its
// control socket and its standard three, put in the cgroup whose file of
// processes group is. It returns a descriptor for the process.
func (s *spawner) start(control, stdin, stdout, stderr, group *os.File) (*os.File, error) {
	answer := make(chan spawnAnswer, 1)
	rights := unix.UnixRights(int(control.Fd()), int(stdin.Fd()), int(stdout.Fd()), int(stderr.Fd()), int(group.Fd()))
	s.mu.Lock()
	n := s.asked
	_, _, err := s.conn.WriteMsgUnix([]byte("start"), rights, nil)
	if err == nil {
		// The spawner counts what it receives: a request that did not
		// leave has no number.
		s.asked++
		s.answers[n] = answer
	}
	s.mu.Unlock()
	if err != nil {
		s.fail()
		return nil, fmt.Errorf("ask the sandbox's spawner: %w", err)
	}
	forget := func() {
		s.mu.Lock()
		delete(s.answers, n)
		s.mu.Unlock()
	}
	select {
	case said := <-answer:
		if said.process == nil {
			return nil, fmt.Errorf("the sandbox's spawner started no process: %s", said.reason)
		}
		return said.process, nil
	case <-s.gone:
		forget()
		return nil, errors.New("the sandbox's spawner is gone")
	case <-time.After(spawnWait):
		forget()
		s.fail()
		return nil, fmt.Errorf("the sandbox's spawner had not answered after %s", spawnWait)
	}
}

// alive reports whether the spawner still answers.
func (s *spawner) alive() bool {
	select {
	case <-s.gone:
		return false
	default:
		return true
	}
}

// end ends the spawner and removes what was made for it. A spawner ends by
// itself when the agent's end of its socket closes, and the cgroup's kill
// switch reaches it if it does not.
func (s *spawner) end() {
	_ = s.conn.Close()
	s.fail()
	_ = s.group.kill(nil)
	select {
	case <-s.exited:
	case <-time.After(stopTimeout):
	}
	s.group.close()
	_ = os.RemoveAll(s.dir)
}

// kernelSaysEnds reports whether this kernel says, through a descriptor for
// a process, which cgroup the process is in and how it ended once it has:
// Linux 6.15 and later.
func kernelSaysEnds() bool {
	var name unix.Utsname
	if err := unix.Uname(&name); err != nil {
		return false
	}
	var major, minor int
	if n, _ := fmt.Sscanf(unix.ByteSliceToString(name.Release[:]), "%d.%d", &major, &minor); n != 2 {
		return false
	}
	return major > 6 || major == 6 && minor >= 15
}

// asked asks the kernel about the process a descriptor names: its number as
// this process's namespace has it, and its cgroup.
func asked(process *os.File) (*unix.PidfdInfo, error) {
	info := &unix.PidfdInfo{Mask: unix.PIDFD_INFO_PID | unix.PIDFD_INFO_CGROUPID}
	if err := unix.IoctlPidfdInfo(int(process.Fd()), info); err != nil {
		return nil, fmt.Errorf("the descriptor names no living process: %w", err)
	}
	if info.Mask&unix.PIDFD_INFO_PID == 0 || info.Mask&unix.PIDFD_INFO_CGROUPID == 0 || info.Pid == 0 {
		return nil, errors.New("the kernel does not say which process the descriptor names, or where it is")
	}
	return info, nil
}

// endWait bounds how long the kernel is asked how a process ended once it
// has: the answer is there when the process's parent has reaped it, which a
// spawner does at once, and the sandbox's first process for one it left.
const endWait = 200 * time.Millisecond

// awaitEnd waits until the process a descriptor names has ended, and then
// asks the kernel how. ok is false for a process nobody reaped in time: how
// it ended is then not known.
func awaitEnd(process *os.File) (end spawnEnd, ok bool) {
	fd := int(process.Fd())
	readable := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(readable, -1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || n == 0 {
			return end, false
		}
		break
	}
	for pause, waited := 50*time.Microsecond, time.Duration(0); ; pause, waited = 2*pause, waited+pause {
		info := unix.PidfdInfo{Mask: unix.PIDFD_INFO_EXIT}
		if err := unix.IoctlPidfdInfo(fd, &info); err == nil && info.Mask&unix.PIDFD_INFO_EXIT != 0 {
			status := unix.WaitStatus(info.Exit_code)
			if status.Signaled() {
				return spawnEnd{signal: int(status.Signal())}, true
			}
			return spawnEnd{status: status.ExitStatus()}, true
		}
		if waited >= endWait {
			return end, false
		}
		time.Sleep(pause)
	}
}

// spawnWarm has the sandbox's spawner start a command's process: the init,
// waiting to be told what to become, as startWarm has the runtime start
// one. The agent makes the process's cgroup, and the process is there before
// anything is told it.
func (r *ImageRunner) spawnWarm(s *spawner, id string) (_ *warmCommand, err error) {
	warm := &warmCommand{done: make(chan struct{})}
	if warm.group, err = newProcessGroup(r.cgroupDir(), id); err != nil {
		return nil, err
	}
	if warm.group.dir == "" {
		return nil, errors.New("this guest has no cgroup to put a spawned process in")
	}
	var ours, theirs []*os.File
	defer func() {
		closeAll(theirs)
		if err != nil {
			closeAll(ours)
			_ = warm.group.kill(nil)
			warm.group.close()
		}
	}()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("the init's control socket: %w", err)
	}
	warm.control = os.NewFile(uintptr(pair[0]), "command-init-control")
	ours, theirs = append(ours, warm.control), append(theirs, os.NewFile(uintptr(pair[1]), "command-init"))
	var pipes [3][2]*os.File
	for i := range pipes {
		if pipes[i][0], pipes[i][1], err = os.Pipe(); err != nil {
			return nil, err
		}
		// The process reads its input and writes the other two.
		mine, its := pipes[i][0], pipes[i][1]
		if i == 0 {
			mine, its = its, mine
		}
		ours, theirs = append(ours, mine), append(theirs, its)
	}
	warm.stdin = ours[1]
	warm.stdout, warm.stderr = &cappedBuffer{limit: session.MaxExecOutput}, &cappedBuffer{limit: session.MaxExecOutput}
	// Opened by the agent, the file lets whoever writes to it put processes
	// of its own namespace in this one cgroup, and do nothing else.
	procs, err := os.OpenFile(filepath.Join(warm.group.dir, "cgroup.procs"), os.O_WRONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("the command's cgroup: %w", err)
	}
	process, err := s.start(theirs[0], theirs[1], theirs[2], theirs[3], procs)
	_ = procs.Close()
	if err != nil {
		return nil, err
	}
	if err := r.confirm(process, warm.group); err != nil {
		if _, gone := asked(process); gone == nil {
			// It lives, and is not what a spawner starts: nothing more is
			// asked of a spawner that names such a process. Nor is the
			// process the agent's to end: an init that was started for this
			// command ends when its control socket closes, below.
			s.fail()
		}
		_ = process.Close()
		return nil, fmt.Errorf("the process the sandbox's spawner started: %w", err)
	}
	copied := make(chan struct{})
	var copies sync.WaitGroup
	for i, into := range []*cappedBuffer{warm.stdout, warm.stderr} {
		copies.Go(func() { _, _ = io.Copy(into, ours[2+i]) })
	}
	go func() {
		copies.Wait()
		close(copied)
	}()
	go func() {
		defer close(warm.done)
		defer process.Close()
		// The kernel says when it has ended and how, whatever has become
		// of its spawner. One that nobody reaped is ended by its cgroup,
		// and counts as killed.
		if end, ok := awaitEnd(process); ok {
			warm.exit = end.code()
		} else {
			_ = warm.group.kill(nil)
			warm.exit = 128 + int(unix.SIGKILL)
		}
		// What the command's descendants still hold open delays its result
		// no longer than it does a command's the runtime started.
		select {
		case <-copied:
		case <-time.After(waitDelay):
		}
		_ = ours[2].Close()
		_ = ours[3].Close()
	}()
	return warm, nil
}

// confirm takes a process the spawner started for a command's, and none of
// it on the spawner's word. The kernel says, through the descriptor, which
// process it names and that the process is in the command's cgroup, where a
// process that was given to another command is not. That it runs the init's
// own file is read by its number, which passes to another process once its
// own has ended, so the descriptor is asked again after that: it named a
// living process by that number before and after, and so what was read was
// read of it.
func (r *ImageRunner) confirm(process *os.File, group *processGroup) error {
	before, err := asked(process)
	if err != nil {
		return err
	}
	var cgroup unix.Stat_t
	if err := unix.Stat(group.dir, &cgroup); err != nil {
		return fmt.Errorf("the command's cgroup: %w", err)
	}
	if before.Cgroupid != cgroup.Ino {
		return errors.New("it is not in the command's cgroup")
	}
	program, err := os.Stat(r.cfg.SandboxInit)
	if err != nil {
		return err
	}
	if exe, err := os.Stat(filepath.Join("/proc", strconv.FormatUint(uint64(before.Pid), 10), "exe")); err != nil || !os.SameFile(exe, program) {
		return errors.New("it is not the sandbox's init")
	}
	if after, err := asked(process); err != nil || after.Pid != before.Pid {
		return errors.New("it ended before it was the command's")
	}
	return nil
}

// command is the process the runtime started for this one, and nil for one
// the sandbox's spawner started: that one is reached by its cgroup alone.
func (w *warmCommand) command() *os.Process {
	if w.cmd == nil {
		return nil
	}
	return w.cmd.Process
}

// exitCode is the command's exit status, once done is closed.
func (w *warmCommand) exitCode() int {
	if w.cmd == nil {
		return w.exit
	}
	return exitStatus(w.cmd.ProcessState)
}
