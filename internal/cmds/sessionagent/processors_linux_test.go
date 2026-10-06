//go:build linux

package sessionagent

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// first reports whether this process may run on the machine's first
// processors, as a guest's agent may, and how many it has.
func first(t *testing.T) int {
	t.Helper()
	var allowed unix.CPUSet
	if err := unix.SchedGetaffinity(0, &allowed); err != nil {
		t.Fatal(err)
	}
	n := runtime.NumCPU()
	if n < 2 || allowed.Count() != n || !allowed.IsSet(0) || !allowed.IsSet(n-1) {
		t.Skipf("needs the machine's first %d processors, and two or more of them", n)
	}
	return n
}

// An agent kept to its first processor has every one of its threads there,
// and so has whatever it starts.
func TestKeepToKeepsEveryThreadAndWhatTheAgentStarts(t *testing.T) {
	n := first(t)
	t.Cleanup(func() {
		if err := keepTo(n); err != nil {
			t.Errorf("give the test binary its processors back: %v", err)
		}
	})
	if err := keepTo(1); err != nil {
		t.Fatal(err)
	}
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range tasks {
		status, err := os.ReadFile("/proc/self/task/" + task.Name() + "/status")
		if err != nil {
			// A thread that ended since the listing.
			continue
		}
		if !strings.Contains(string(status), "Cpus_allowed_list:\t0\n") {
			t.Errorf("thread %s may run elsewhere than on the first processor", task.Name())
		}
	}
	out, err := exec.Command("nproc").Output()
	if err != nil {
		t.Skipf("no nproc here: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "1" {
		t.Errorf("a program the agent started has %s processors", got)
	}
}
