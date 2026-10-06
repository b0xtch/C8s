//go:build linux

package sessionagent

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/pkg/session"
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

// onTheFirst fails the test for each thread of this process that may run
// elsewhere than on the machine's first processor.
func onTheFirst(t *testing.T) {
	t.Helper()
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
	onTheFirst(t)
	out, err := exec.Command("nproc").Output()
	if err != nil {
		t.Skipf("no nproc here: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "1" {
		t.Errorf("a program the agent started has %s processors", got)
	}
}

// A command on the guest's own file system has every processor the agent was
// started with, whatever the agent keeps to since. Commands that start at
// once each have them, and no thread of the agent's keeps them after.
func TestACommandWithoutASandboxHasEveryProcessor(t *testing.T) {
	n := first(t)
	if _, err := exec.LookPath("nproc"); err != nil {
		t.Skipf("no nproc here: %v", err)
	}
	t.Cleanup(func() {
		if err := keepTo(n); err != nil {
			t.Errorf("give the test binary its processors back: %v", err)
		}
	})
	if err := keepTo(1); err != nil {
		t.Fatal(err)
	}
	runner, err := NewProcessRunner(RunnerConfig{UID: -1, GID: -1, Home: t.TempDir(), CredentialDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 4 {
				resp, err := runner.Exec(ctx, &session.ExecRequest{ID: "wide-" + strconv.Itoa(i) + "-" + strconv.Itoa(j), Argv: []string{"nproc"}})
				if err != nil {
					t.Error(err)
					return
				}
				if got := strings.TrimSpace(string(resp.Stdout)); resp.ExitCode != 0 || got != strconv.Itoa(n) {
					t.Errorf("a command has %q processors of %d (status %d: %s)", got, n, resp.ExitCode, resp.Stderr)
				}
			}
		}()
	}
	wg.Wait()
	onTheFirst(t)
}
