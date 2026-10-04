//go:build linux

package sessionagent_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
)

// fakeRuntimePrefix begins the name the test binary is run under to stand in
// for the container runtime. What follows it says how.
const fakeRuntimePrefix = "fake-crun-"

// fakeRuntime is a container runtime that makes no container. It names a
// process as the container's first, as a runtime does in its pid file, waits
// a moment and ends with status 7.
func fakeRuntime(mode string, args []string) int {
	var pidFile, bundle string
	for i := 0; i+1 < len(args); i++ {
		switch args[i] {
		case "--pid-file":
			pidFile = args[i+1]
		case "--bundle":
			bundle = args[i+1]
		}
	}
	if pidFile == "" {
		return 0
	}
	pid := os.Getpid()
	switch mode {
	case "outside", "elsewhere":
		// A process of this machine that is nothing of the container's.
		other := exec.Command("sleep", "5")
		if err := other.Start(); err != nil {
			return 1
		}
		defer func() { _ = other.Process.Kill(); _ = other.Wait() }()
		pid = other.Process.Pid
	}
	switch mode {
	case "itself", "elsewhere":
		// In the container's cgroup. "itself" is this process: what a
		// runtime's first process is until it runs the image's program.
		// "elsewhere" is another program there, started in the namespaces of
		// this machine and in none of the sandbox's.
		var config struct {
			Linux struct {
				CgroupsPath string `json:"cgroupsPath"`
			} `json:"linux"`
		}
		data, err := os.ReadFile(filepath.Join(bundle, "config.json"))
		if err != nil || json.Unmarshal(data, &config) != nil || config.Linux.CgroupsPath == "" {
			return 1
		}
		dir := filepath.Join("/sys/fs/cgroup", config.Linux.CgroupsPath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return 1
		}
		if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0); err != nil {
			return 1
		}
	}
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(pid)), 0o644); err != nil {
		return 1
	}
	time.Sleep(500 * time.Millisecond)
	return 7
}

// A sandbox runs once the container's first process runs the image's own
// program. The runtime says in a file which process that is, and the agent
// believes it only of a process in the container's cgroup that is the
// runtime no longer.
func TestSandboxRunsOnlyAsTheImagesOwnProgram(t *testing.T) {
	containerFixtures(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	notRunning := []string{"ended before it was running", "status 7"}
	for mode, tc := range map[string]struct {
		what string
		want []string
	}{
		"outside":   {"a process outside the container's cgroup", notRunning},
		"itself":    {"the runtime's own process, in the container's cgroup", notRunning},
		"elsewhere": {"a program in the container's cgroup and outside the sandbox's namespaces", []string{"does not run in the user namespace made for it"}},
	} {
		t.Run(tc.what, func(t *testing.T) {
			runtime := filepath.Join(t.TempDir(), fakeRuntimePrefix+mode)
			if err := os.Symlink(self, runtime); err != nil {
				t.Fatal(err)
			}
			c := newContainer(t, containerOptions{runtime: runtime})
			// A runtime removes the cgroup it made.
			t.Cleanup(func() { _ = os.Remove(filepath.Join(c.cgroup, "sandbox")) })
			err := c.admitErr(t)
			for _, want := range tc.want {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("the bind ended the guest with %v, want %q", err, want)
				}
			}
		})
	}
}

// A runner makes the namespaces of a sandbox before it knows of one. A guest
// whose document then names no sandbox image has no sandbox port for all
// that: a stream is refused as it is in a guest with no container runtime.
func TestRunnerWithoutASandboxHasNoPort(t *testing.T) {
	crun, _ := containerFixtures(t)
	runner, _, _ := imageRunner(t, newHarness(t, nil), crun, nil)
	conn, err := runner.Dial(ctxT(t), 9000)
	if err == nil {
		conn.Close()
		t.Fatal("a stream was opened in a guest with no sandbox")
	}
	if !strings.Contains(err.Error(), "no sandbox port") {
		t.Fatalf("Dial = %v, want the refusal of a guest that runs no sandbox image", err)
	}
}

// What the agent runs in the new namespaces does nothing, and ends with its
// input.
func TestHoldEndsWithItsInput(t *testing.T) {
	if err := sessionagent.Hold(strings.NewReader("anything")); err != nil {
		t.Fatal(err)
	}
}
