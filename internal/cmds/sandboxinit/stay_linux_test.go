package sandboxinit_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sandboxinit"
)

// With the variable set, the program under test first adopts what is
// orphaned under it, as a sandbox's first process does, and starts a shell
// that ends at once and leaves a child of its own behind.
const withOrphan = "C8S_SANDBOXINIT_TEST_ORPHAN"

func init() {
	beforeInit = func() {
		if os.Getenv(withOrphan) != "1" {
			return
		}
		if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
			os.Exit(3)
		}
		if err := exec.Command("/bin/sh", "-c", "sleep 0.3 & exit 0").Start(); err != nil {
			os.Exit(3)
		}
	}
}

// children returns the processes whose parent is pid, each with its state.
func children(t *testing.T, pid int) map[int]string {
	t.Helper()
	found := map[int]string{}
	stats, err := filepath.Glob("/proc/[0-9]*/stat")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range stats {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		// After the name, which may hold anything: the state and the parent.
		_, rest, ok := strings.Cut(string(data), ") ")
		fields := strings.Fields(rest)
		if !ok || len(fields) < 2 || fields[1] != strconv.Itoa(pid) {
			continue
		}
		child, _ := strconv.Atoi(filepath.Base(filepath.Dir(path)))
		found[child] = fields[0]
	}
	return found
}

// An init that stays reaps what ends under it: its own child, and a process
// that was orphaned to it and ended later. Neither is left as a zombie.
func TestInitThatStaysReapsWhatEndsUnderIt(t *testing.T) {
	cmd, agent := startWith(t, withOrphan+"=1")
	send(t, agent, sandboxinit.Process{Stay: true})
	if taken, reason := sandboxinit.ReadAnswer(agent); !taken || reason != "" {
		t.Fatalf("the init answered taken %v, reason %q", taken, reason)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	// The shell ends at once and its child after 300 ms, as the init's own.
	deadline := time.Now().Add(10 * time.Second)
	for {
		left := children(t, cmd.Process.Pid)
		if len(left) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("processes left under an init that stays, by state: %v", left)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
