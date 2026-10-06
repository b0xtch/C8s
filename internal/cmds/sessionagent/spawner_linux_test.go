//go:build linux

package sessionagent

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sandboxinit"
)

// spoken is the agent's end of a spawner whose other end a test speaks for:
// a socket of packets, with nothing started by any runtime. The other end is
// a file, so that a test that closes it and the cleanup that closes it again
// close one descriptor between them.
func spoken(t *testing.T) (*spawner, int) {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.SetsockoptTimeval(pair[1], unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 10}); err != nil {
		t.Fatal(err)
	}
	ours := os.NewFile(uintptr(pair[0]), "spawner-control")
	conn, err := net.FileConn(ours)
	_ = ours.Close()
	if err != nil {
		t.Fatal(err)
	}
	s := &spawner{
		conn: conn.(*net.UnixConn), exited: make(chan struct{}),
		answers: map[int]chan spawnAnswer{}, gone: make(chan struct{}),
	}
	go s.read()
	theirs := os.NewFile(uintptr(pair[1]), "spawner")
	hangUp[pair[1]] = theirs
	t.Cleanup(func() {
		_ = s.conn.Close()
		_ = theirs.Close()
		delete(hangUp, pair[1])
	})
	return s, pair[1]
}

// hangUp holds the spawner's end of each socket a test speaks on, by its
// descriptor: closing it there is how a test's spawner goes away.
var hangUp = map[int]*os.File{}

// requested reads one request as a spawner does, and returns how many
// descriptors came with it, closed.
func requested(t *testing.T, theirs int) int {
	t.Helper()
	packet, control := make([]byte, sandboxinit.MaxSpawnPacket), make([]byte, unix.CmsgSpace(4*8))
	size, controlled, _, _, err := unix.Recvmsg(theirs, packet, control, unix.MSG_CMSG_CLOEXEC)
	if err != nil || size == 0 {
		t.Fatalf("no request reached the spawner: %d bytes, %v", size, err)
	}
	passed := 0
	if messages, err := unix.ParseSocketControlMessage(control[:controlled]); err == nil {
		for i := range messages {
			if fds, err := unix.ParseUnixRights(&messages[i]); err == nil {
				passed += len(fds)
				for _, fd := range fds {
					_ = unix.Close(fd)
				}
			}
		}
	}
	return passed
}

// descriptors is what a request carries: any descriptors will do for a test
// that starts nothing with them.
func descriptors(t *testing.T) []*os.File {
	t.Helper()
	files := make([]*os.File, sandboxinit.SpawnRequest)
	for i := range files {
		f, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		files[i] = f
	}
	return files
}

// child is a process of the test's own with a descriptor for it, as a
// spawner hands the agent one for a process it started.
func child(t *testing.T) (*exec.Cmd, int) {
	t.Helper()
	var process int
	cmd := exec.Command("sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{PidFD: &process}
	if err := cmd.Start(); err != nil {
		t.Skipf("no sleep to start here: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd, process
}

// knowsEnds skips a test on a kernel that does not say through a process's
// descriptor how the process ended.
func knowsEnds(t *testing.T) {
	t.Helper()
	if !kernelSaysEnds() {
		t.Skip("this kernel does not say how a process ended through its descriptor")
	}
}

// A request carries its descriptors, and the spawner's answer brings a
// descriptor for the process it started, which names that process and no
// other.
func TestSpawnerStartsAProcessAndNamesIt(t *testing.T) {
	knowsEnds(t)
	s, theirs := spoken(t)
	cmd, process := child(t)
	type started struct {
		process *os.File
		err     error
	}
	done := make(chan started, 1)
	files := descriptors(t)
	go func() {
		process, err := s.start(files[0], files[1], files[2], files[3], files[4])
		done <- started{process, err}
	}()
	if got := requested(t, theirs); got != sandboxinit.SpawnRequest {
		t.Fatalf("a request carried %d descriptors", got)
	}
	if err := unix.Sendmsg(theirs, []byte(sandboxinit.Spawned+" 0"), unix.UnixRights(process), nil, 0); err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(process)
	got := <-done
	if got.err != nil {
		t.Fatalf("start: %v", got.err)
	}
	defer got.process.Close()
	if info, err := asked(got.process); err != nil || int(info.Pid) != cmd.Process.Pid {
		t.Fatalf("the descriptor names %+v (%v), and the spawner started %d", info, err, cmd.Process.Pid)
	}
}

// How a process ended is the kernel's to say, through a descriptor for it
// and once its parent has reaped it: its exit status, or the signal that
// ended it. Of one that ended and that nobody reaps, it is not known.
func TestEndOfAProcessIsTheKernelsWord(t *testing.T) {
	knowsEnds(t)
	start := func(script string) (*exec.Cmd, *os.File) {
		t.Helper()
		var process int
		cmd := exec.Command("sh", "-c", script)
		cmd.SysProcAttr = &syscall.SysProcAttr{PidFD: &process}
		if err := cmd.Start(); err != nil {
			t.Skipf("no shell to start here: %v", err)
		}
		named := os.NewFile(uintptr(process), "process")
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			named.Close()
		})
		return cmd, named
	}
	for script, want := range map[string]spawnEnd{"exit 7": {status: 7}, "exit 0": {}, "kill -9 $$": {signal: 9}} {
		cmd, process := start(script)
		reaped := make(chan struct{})
		go func() {
			_ = cmd.Wait()
			close(reaped)
		}()
		end, ok := awaitEnd(process)
		if !ok || end != want {
			t.Errorf("%q ended as %+v, known %v; want %+v", script, end, ok, want)
		}
		<-reaped
	}
	// One that is still running is waited for.
	cmd, process := start("sleep 30")
	waited := make(chan spawnEnd, 1)
	go func() {
		end, _ := awaitEnd(process)
		waited <- end
	}()
	select {
	case end := <-waited:
		t.Fatalf("a process that runs was said to have ended: %+v", end)
	case <-time.After(100 * time.Millisecond):
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if end := <-waited; end.signal != 9 {
		t.Errorf("a process that was killed ended as %+v", end)
	}
	// One that has ended and is not reaped: the wait is bounded.
	_, process = start("exit 3")
	began := time.Now()
	if end, ok := awaitEnd(process); ok {
		t.Errorf("a process nobody reaped is said to have ended as %+v", end)
	} else if took := time.Since(began); took < endWait || took > endWait+5*time.Second {
		t.Errorf("the kernel was asked for %s about a process nobody reaped, and the bound is %s", took, endWait)
	}
	if (spawnEnd{signal: 9}).code() != 137 || (spawnEnd{status: 3}).code() != 3 {
		t.Error("a signal's status is 128 and the signal, and an exit's is its own")
	}
}

// A spawner that starts nothing says why, one that names no process started
// none, and what is said of a request nobody waits for reaches nobody and
// leaves no descriptor open.
func TestSpawnerThatStartsNothing(t *testing.T) {
	s, theirs := spoken(t)
	_, process := child(t)
	for n, answer := range []struct{ said, want string }{
		{sandboxinit.SpawnFailed + " 0 fork: resource temporarily unavailable", "resource temporarily unavailable"},
		{sandboxinit.Spawned + " 1", "named no process"},
	} {
		done := make(chan error, 1)
		files := descriptors(t)
		go func() {
			process, err := s.start(files[0], files[1], files[2], files[3], files[4])
			if process != nil {
				process.Close()
			}
			done <- err
		}()
		requested(t, theirs)
		if err := unix.Sendmsg(theirs, []byte(answer.said), nil, nil, 0); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err == nil || !strings.Contains(err.Error(), answer.want) {
			t.Errorf("request %d, answered %q: %v", n, answer.said, err)
		}
	}
	// Words of no request, and an end nobody asked about, with a descriptor.
	for _, said := range []string{sandboxinit.Spawned + " 41", sandboxinit.SpawnFailed + " 41 late", "started", "started soon", "ended 0 0 0"} {
		if err := unix.Sendmsg(theirs, []byte(said), unix.UnixRights(process), nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	if !s.alive() {
		t.Fatal("a spawner's stray words ended it")
	}
	s.mu.Lock()
	waiting := len(s.answers)
	s.mu.Unlock()
	if waiting != 0 {
		t.Errorf("%d waits were left for requests that were answered with no process", waiting)
	}
}

// A spawner that is gone ends every wait on it: a start that was asked of it
// fails at once, and so does one asked after.
func TestSpawnerThatIsGone(t *testing.T) {
	s, theirs := spoken(t)
	done := make(chan error, 1)
	files := descriptors(t)
	go func() {
		_, err := s.start(files[0], files[1], files[2], files[3], files[4])
		done <- err
	}()
	requested(t, theirs)
	began := time.Now()
	_ = hangUp[theirs].Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a spawner that went away started a process")
		}
	case <-time.After(spawnWait):
		t.Fatal("a start waited out its bound on a spawner that was gone")
	}
	if s.alive() {
		t.Fatal("a spawner whose socket closed is taken for alive")
	}
	if _, err := s.start(files[0], files[1], files[2], files[3], files[4]); err == nil {
		t.Fatal("a spawner that is gone was asked for a process, and gave one")
	} else if time.Since(began) > spawnWait {
		t.Fatalf("it took %s to say so: %v", time.Since(began), err)
	}
}

// A descriptor that names no process is none the agent acts on.
func TestDescriptorThatNamesNoProcess(t *testing.T) {
	knowsEnds(t)
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if info, err := asked(f); err == nil {
		t.Fatalf("a file was taken for process %d", info.Pid)
	}
	cmd, process := child(t)
	named := os.NewFile(uintptr(process), "process")
	defer named.Close()
	if info, err := asked(named); err != nil || int(info.Pid) != cmd.Process.Pid {
		t.Fatalf("a living process is named %+v, %v", info, err)
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if info, err := asked(named); err == nil {
		t.Fatalf("a process that is gone was taken for process %d", info.Pid)
	}
}

// The agent takes a process for a command's on what it reads of the process
// and on nothing its spawner says: the process runs the init's own file, in
// the cgroup of that command and of no other, and is there still.
func TestProcessIsConfirmedByWhatItIs(t *testing.T) {
	groups := commandGroups(t, "a", "b")
	cmd, fd := child(t)
	process := os.NewFile(uintptr(fd), "process")
	defer process.Close()
	program, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip(err)
	}
	r := &ImageRunner{cfg: ImageRunnerConfig{SandboxInit: program}}
	if err := r.confirm(process, groups[0]); err == nil || !strings.Contains(err.Error(), "not in the command's cgroup") {
		t.Fatalf("a process its spawner left where it was born: %v", err)
	}
	if err := os.WriteFile(filepath.Join(groups[0].dir, "cgroup.procs"), []byte(strconv.Itoa(cmd.Process.Pid)), 0); err != nil {
		t.Fatal(err)
	}
	if err := r.confirm(process, groups[0]); err != nil {
		t.Fatalf("the init, in its command's cgroup: %v", err)
	}
	// Named for a second command, it is still the first one's.
	if err := r.confirm(process, groups[1]); err == nil || !strings.Contains(err.Error(), "not in the command's cgroup") {
		t.Fatalf("a process that another command has: %v", err)
	}
	// Any other program there is not the init.
	other := &ImageRunner{cfg: ImageRunnerConfig{SandboxInit: "/proc/self/exe"}}
	if err := other.confirm(process, groups[0]); err == nil || !strings.Contains(err.Error(), "not the sandbox's init") {
		t.Fatalf("a process that runs another program: %v", err)
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if err := r.confirm(process, groups[0]); err == nil {
		t.Fatal("a process that is gone was taken for a command's")
	}
}
