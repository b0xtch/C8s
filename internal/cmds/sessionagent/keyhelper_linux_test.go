//go:build linux

package sessionagent_test

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// helperProcess is a pool whose guest starts its key helper as a guest's
// agent does: its own program, run once more as a process of its own.
func helperProcess(t *testing.T) *pool {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("the key helper locks its memory, which takes root here")
	}
	if keysInHelper {
		t.Skip("these guests hold their one-time keys in a helper of this process's own")
	}
	p := newPool(t)
	p.cfg.KeyHelper = []string{"/proc/self/exe", "session-agent", "one-time-keys"}
	return p
}

var lockedMemory = regexp.MustCompile(`(?m)^VmLck:\s+(\d+) kB$`)

// The key helper is a process of its own, with its memory locked and no
// core to dump, and no descriptor but its way to the agent. It signs the
// guest's receipt and opens its sealed message, and the kernel has reaped
// it before the sandbox is started.
func TestKeyHelperProcessHoldsTheKeysAndIsReaped(t *testing.T) {
	p := helperProcess(t)
	p.start(t)
	c := found(t, p)
	pid := sessionagent.KeyHelperPID(c.agent)
	if pid <= 1 || pid == os.Getpid() {
		t.Fatalf("the key helper's process is %d", pid)
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatal(err)
	}
	if m := lockedMemory.FindSubmatch(status); m == nil || string(m[1]) == "0" {
		t.Fatalf("the key helper has no memory locked:\n%s", status)
	}
	limits, err := os.ReadFile(fmt.Sprintf("/proc/%d/limits", pid))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^Max core file size\s+0\s+0\s`).Match(limits) {
		t.Fatalf("the key helper may dump a core:\n%s", limits)
	}
	// Standard input, output and error, and the socket to its agent. What
	// else it holds its own runtime opened, which is no file of the agent's:
	// the kernel's event queues, and the limit of its cgroup's processors.
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		target, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
		own := strings.HasPrefix(target, "anon_inode:") || strings.HasPrefix(target, "/sys/fs/cgroup/") && strings.HasSuffix(target, "/cpu.max")
		if n, err := strconv.Atoi(fd.Name()); (err != nil || n > 3) && !own {
			t.Errorf("the key helper holds descriptor %s, which is %s", fd.Name(), target)
		}
	}

	c.runner.starting, c.runner.started = make(chan struct{}), make(chan struct{})
	var gone atomic.Bool
	c.runner.onStart = func() {
		// Reaped: the process is no more, not even as one that waits to be.
		gone.Store(syscall.Kill(pid, 0) == syscall.ESRCH && sessionagent.OneTimeKeysErased(c.agent))
	}
	message := c.seal(t, c.access, c.bind, true)
	first := make(chan bindAnswer, 1)
	go func() { first <- c.post(t, c.bind, message.Sealed) }()
	select {
	case <-c.runner.starting:
	case <-time.After(10 * time.Second):
		t.Fatal("the sandbox was never started")
	}
	if !gone.Load() {
		t.Fatal("the key helper's process is not reaped as the sandbox starts")
	}
	close(c.runner.started)
	answer := <-first
	if answer.status != http.StatusOK || answer.bound.Sealed != session.SealedTaken {
		t.Fatalf("the bind's answer: %d %+v", answer.status, answer.bound)
	}
	if _, err := session.VerifyBindReceipt(c.boundPolicy(c.ready, c.bind), c.ready.InstanceKey, c.ready.OneTime, c.bind, answer.bound.Receipt); err != nil {
		t.Fatalf("the receipt the helper signed: %v", err)
	}
	if result := ran(t, message, answer); result.ExitCode != 0 {
		t.Fatalf("the sealed command: %+v", result)
	}
}

// A key helper that is killed under a guest nobody has bound ends the guest.
func TestGuestEndsWhenItsKeyHelperProcessIsKilled(t *testing.T) {
	p := helperProcess(t)
	p.start(t)
	// A number that names no process of its own would name this one's whole
	// group, or every process there is.
	pid := sessionagent.KeyHelperPID(p.agent)
	if pid <= 1 || pid == os.Getpid() {
		t.Fatalf("the key helper's process is %d", pid)
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if err := p.fatal(t); err == nil || !strings.Contains(err.Error(), "key helper") {
		t.Fatalf("the guest ended with: %v", err)
	}
}
