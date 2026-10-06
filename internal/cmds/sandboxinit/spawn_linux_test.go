//go:build linux

package sandboxinit_test

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sandboxinit"
)

// spawner runs this binary as a sandbox's spawner, with its own file and one
// end of a socket of packets where a runtime would preserve them, and
// returns the agent's end.
func spawner(t *testing.T) (*exec.Cmd, int) {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	// A packet that never comes fails its test and hangs none.
	if err := unix.SetsockoptTimeval(pair[0], unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 10}); err != nil {
		t.Fatal(err)
	}
	theirs := os.NewFile(uintptr(pair[1]), "spawner")
	self, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	cmd := exec.Command(os.Args[0], sandboxinit.SpawnArg)
	cmd.Env = []string{asInit + "=1"}
	cmd.ExtraFiles = []*os.File{self, theirs}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	theirs.Close()
	t.Cleanup(func() {
		_ = unix.Close(pair[0])
		_ = cmd.Wait()
	})
	return cmd, pair[0]
}

// asked is one process a test asked a spawner for: the agent's ends of what
// the process was started with, and of a pipe that stands for the file of
// its cgroup, which reads what the spawner wrote there.
type asked struct {
	control, stdin, stdout, stderr, procs *os.File
}

// ask sends a spawner one request with the first n of the descriptors a
// request carries, and returns the agent's ends. cgroup, when given, goes in
// place of the pipe that stands for the cgroup's file.
func ask(t *testing.T, agent int, n int, cgroup ...*os.File) *asked {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	a := &asked{control: os.NewFile(uintptr(pair[0]), "control")}
	theirs := []*os.File{os.NewFile(uintptr(pair[1]), "their control")}
	var in, out, errs, procs *os.File
	if in, a.stdin, err = os.Pipe(); err != nil {
		t.Fatal(err)
	}
	if a.stdout, out, err = os.Pipe(); err != nil {
		t.Fatal(err)
	}
	if a.stderr, errs, err = os.Pipe(); err != nil {
		t.Fatal(err)
	}
	if a.procs, procs, err = os.Pipe(); err != nil {
		t.Fatal(err)
	}
	theirs = append(theirs, in, out, errs, procs)
	t.Cleanup(func() {
		for _, f := range []*os.File{a.control, a.stdin, a.stdout, a.stderr, a.procs} {
			f.Close()
		}
	})
	fds := make([]int, 0, n)
	for _, f := range theirs[:n] {
		fds = append(fds, int(f.Fd()))
	}
	if len(cgroup) > 0 && n == sandboxinit.SpawnRequest {
		fds[n-1] = int(cgroup[0].Fd())
	}
	if err := unix.Sendmsg(agent, []byte("spawn"), unix.UnixRights(fds...), nil, 0); err != nil {
		t.Fatal(err)
	}
	for _, f := range theirs {
		f.Close()
	}
	return a
}

// written reads what a spawner wrote to the pipe that stands for a cgroup's
// file, which is there before the spawner's answer is.
func (a *asked) written(t *testing.T) string {
	t.Helper()
	if err := a.procs.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	wrote := make([]byte, 64)
	n, err := a.procs.Read(wrote)
	if err != nil {
		t.Fatalf("nothing was written to the cgroup's file: %v", err)
	}
	return string(wrote[:n])
}

// said reads one packet of a spawner's: its words, and the descriptor that
// came with it, or -1.
func said(t *testing.T, agent int) ([]string, int) {
	t.Helper()
	packet, control := make([]byte, sandboxinit.MaxSpawnPacket), make([]byte, unix.CmsgSpace(4*4))
	size, controlled, _, _, err := unix.Recvmsg(agent, packet, control, unix.MSG_CMSG_CLOEXEC)
	if err != nil {
		t.Fatalf("no packet from the spawner: %v", err)
	}
	passed := -1
	if messages, err := unix.ParseSocketControlMessage(control[:controlled]); err == nil {
		for i := range messages {
			if fds, err := unix.ParseUnixRights(&messages[i]); err == nil && len(fds) == 1 {
				passed = fds[0]
			}
		}
	}
	return strings.Fields(string(packet[:size])), passed
}

// pidOf asks the kernel which process a descriptor for one names.
func pidOf(t *testing.T, process int) int {
	t.Helper()
	info := unix.PidfdInfo{Mask: unix.PIDFD_INFO_PID}
	if err := unix.IoctlPidfdInfo(process, &info); err != nil || info.Pid == 0 {
		t.Fatalf("the descriptor names no process: %v", err)
	}
	return int(info.Pid)
}

// endOf waits for the process a descriptor names to end and to be reaped,
// as only its spawner can reap it, and returns the exit status and the
// signal the kernel says it ended with. The spawner says neither.
func endOf(t *testing.T, process int) (status, signal int) {
	t.Helper()
	readable := []unix.PollFd{{Fd: int32(process), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(readable, 10_000)
		if err == unix.EINTR {
			continue
		}
		if err != nil || n == 0 {
			t.Fatalf("the process did not end: %v", err)
		}
		break
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		info := unix.PidfdInfo{Mask: unix.PIDFD_INFO_EXIT}
		if err := unix.IoctlPidfdInfo(process, &info); err == nil && info.Mask&unix.PIDFD_INFO_EXIT != 0 {
			how := unix.WaitStatus(info.Exit_code)
			if how.Signaled() {
				return 0, int(how.Signal())
			}
			return how.ExitStatus(), 0
		}
		if time.Now().After(deadline) {
			t.Fatal("the process ended and its spawner never reaped it")
		}
	}
}

// reapable skips a test on a kernel that does not say through a process's
// descriptor how the process ended: Linux before 6.15.
func reapable(t *testing.T) {
	t.Helper()
	var name unix.Utsname
	var major, minor int
	if err := unix.Uname(&name); err != nil {
		t.Skip(err)
	}
	if n, _ := fmt.Sscanf(unix.ByteSliceToString(name.Release[:]), "%d.%d", &major, &minor); n != 2 || major < 6 || major == 6 && minor < 15 {
		t.Skipf("Linux %s does not say how a process ended through its descriptor", unix.ByteSliceToString(name.Release[:]))
	}
}

// A spawner starts this program again for each request, with the request's
// descriptors where a runtime would put them, and hands the agent a
// descriptor for the process. It reaps the process when it ends, which is
// when the kernel says through that descriptor how it ended. The process is
// an init like any other: it becomes the command it is told.
func TestSpawnerStartsAnInitForEachRequest(t *testing.T) {
	reapable(t)
	_, agent := spawner(t)
	for n := range 3 {
		a := ask(t, agent, sandboxinit.SpawnRequest)
		words, process := said(t, agent)
		if len(words) != 2 || words[0] != sandboxinit.Spawned || words[1] != strconv.Itoa(n) || process < 0 {
			t.Fatalf("request %d was answered %q with descriptor %d", n, words, process)
		}
		pid := pidOf(t, process)
		if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err != nil || !strings.HasSuffix(exe, ".test") {
			t.Fatalf("the process a spawner named runs %q, %v", exe, err)
		}
		// The spawner put the process in its cgroup by the process's own
		// number, and had done so before it answered.
		if got := a.written(t); got != strconv.Itoa(pid) {
			t.Fatalf("the spawner wrote %q to the cgroup's file for process %d", got, pid)
		}
		script := fmt.Sprintf(`read line; echo "out %d $line $(ls /proc/self/fd | tr '\n' ' ')"; echo "err %d" >&2; exit %d`, n, n, 3+n)
		if n == 2 {
			script = `kill -9 $$`
		}
		send(t, a.control, sandboxinit.Process{Argv: []string{"sh", "-c", script}, Env: []string{"PATH=/usr/bin:/bin"}, Cwd: "/"})
		if _, err := io.WriteString(a.stdin, "typed\n"); err != nil {
			t.Fatal(err)
		}
		a.stdin.Close()
		if taken, reason := sandboxinit.ReadAnswer(a.control); !taken || reason != "" {
			t.Fatalf("process %d answered taken %v, reason %q", n, taken, reason)
		}
		out, _ := io.ReadAll(a.stdout)
		errs, _ := io.ReadAll(a.stderr)
		status, signal := endOf(t, process)
		_ = unix.Close(process)
		if n == 2 {
			if status != 0 || signal != 9 {
				t.Fatalf("a process that was killed ended with status %d, signal %d", status, signal)
			}
			continue
		}
		if status != 3+n || signal != 0 {
			t.Fatalf("process %d ended with status %d, signal %d", n, status, signal)
		}
		// Its standard three, and the descriptor ls reads the directory by:
		// nothing of the spawner's, and no way back to the agent.
		if got := strings.TrimSpace(string(out)); got != fmt.Sprintf("out %d typed 0 1 2 3", n) {
			t.Errorf("process %d wrote %q", n, got)
		}
		if got := strings.TrimSpace(string(errs)); got != fmt.Sprintf("err %d", n) {
			t.Errorf("process %d wrote %q to its standard error", n, got)
		}
	}
}

// A process the spawner cannot put in its cgroup is none it hands over: the
// spawner says why, ends the process, says nothing of that end, and serves
// the next request.
func TestSpawnerEndsAProcessItCannotPutInItsCgroup(t *testing.T) {
	reapable(t)
	_, agent := spawner(t)
	unwritable, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer unwritable.Close()
	a := ask(t, agent, sandboxinit.SpawnRequest, unwritable)
	words, process := said(t, agent)
	if len(words) < 3 || words[0] != sandboxinit.SpawnFailed || words[1] != "0" || process >= 0 || !strings.Contains(strings.Join(words, " "), "in its cgroup") {
		t.Fatalf("a request whose cgroup could not be entered was answered %q, descriptor %d", words, process)
	}
	// The process is gone: its end of the control socket is closed, with
	// nothing said on it. A read that waits out its bound says otherwise.
	if err := unix.SetsockoptTimeval(int(a.control.Fd()), unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 10}); err != nil {
		t.Fatal(err)
	}
	began := time.Now()
	if taken, reason := sandboxinit.ReadAnswer(a.control); taken || reason != "" || time.Since(began) > 5*time.Second {
		t.Fatalf("a process that was ended answered taken %v, reason %q, after %s", taken, reason, time.Since(began))
	}
	b := ask(t, agent, sandboxinit.SpawnRequest)
	words, process = said(t, agent)
	if len(words) != 2 || words[0] != sandboxinit.Spawned || words[1] != "1" || process < 0 {
		t.Fatalf("the request after it was answered %q", words)
	}
	// It waits for a command that never comes, ends when the agent's end of
	// its socket closes, and is reaped as any other.
	b.control.Close()
	if status, signal := endOf(t, process); status != sandboxinit.FailureStatus || signal != 0 {
		t.Fatalf("an init whose agent went away ended with status %d, signal %d", status, signal)
	}
	_ = unix.Close(process)
}

// A request that carries another number of descriptors starts nothing, and
// the spawner serves the next. It ends when the agent closes the socket.
func TestSpawnerRefusesARequestItCannotStart(t *testing.T) {
	cmd, agent := spawner(t)
	ask(t, agent, 2)
	if words, process := said(t, agent); len(words) < 2 || words[0] != sandboxinit.SpawnFailed || words[1] != "0" || process >= 0 {
		t.Fatalf("a request with two descriptors was answered %q, descriptor %d", words, process)
	}
	a := ask(t, agent, sandboxinit.SpawnRequest)
	words, process := said(t, agent)
	if len(words) != 2 || words[0] != sandboxinit.Spawned || words[1] != "1" || process < 0 {
		t.Fatalf("the request after it was answered %q", words)
	}
	_ = unix.Close(process)
	a.control.Close()
	_ = unix.Close(agent)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the spawner ended with %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the spawner outlived its agent's socket")
	}
}
