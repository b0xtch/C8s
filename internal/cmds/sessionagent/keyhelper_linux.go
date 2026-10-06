//go:build linux

package sessionagent

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

// keyHelperFD is where the helper finds its connection to the agent.
const keyHelperFD = 3

// startKeyHelper starts the program argv names as the guest's key helper,
// with one end of a socket pair as its only way to the agent, and returns
// the agent's end of it. The agent waits for it by the descriptor the
// runtime holds on the process, so the one it reaps is the one it started.
func startKeyHelper(argv []string) (*keyHelper, error) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	ours, theirs := os.NewFile(uintptr(pair[0]), "key helper"), os.NewFile(uintptr(pair[1]), "agent")
	defer ours.Close()
	defer theirs.Close()
	conn, err := net.FileConn(ours)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	// Nothing of the agent's environment, and no descriptor but the socket.
	cmd.Env = []string{}
	cmd.ExtraFiles = []*os.File{theirs}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	helper := newKeyHelper(conn, cmd.Wait)
	helper.pid = cmd.Process.Pid
	return helper, nil
}

// RunKeyHelper is the key helper's whole life: it keeps its memory out of
// swap and out of a core, makes the guest's one-time keys, serves the agent
// on the descriptor it was started with, and returns, for its caller to
// exit. Whatever it returns, the keys go with the process.
func RunKeyHelper() error {
	// Before there is a key. Pages are locked as they are first touched:
	// locking a runtime's whole address space would hold memory it never
	// uses.
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE | unix.MCL_ONFAULT); err != nil {
		return fmt.Errorf("keep the key helper's memory out of swap: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("keep the key helper out of a core: %w", err)
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return fmt.Errorf("keep the key helper out of a core: %w", err)
	}
	conn := os.NewFile(keyHelperFD, "agent")
	if conn == nil {
		return fmt.Errorf("the key helper was started with no way to its agent")
	}
	defer conn.Close()
	return serveKeys(conn)
}

// helperMemory is what the process pid holds in memory, in kilobytes: all
// of it, and the part that is its own and no file's, which is what it adds
// to its guest's. Zero where the kernel does not say.
func helperMemory(pid int) (resident, own int) {
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(status), "\n") {
		if value, ok := strings.CutPrefix(line, "VmRSS:"); ok {
			_, _ = fmt.Sscanf(strings.TrimSpace(value), "%d", &resident)
		} else if value, ok := strings.CutPrefix(line, "RssAnon:"); ok {
			_, _ = fmt.Sscanf(strings.TrimSpace(value), "%d", &own)
		}
	}
	return resident, own
}
