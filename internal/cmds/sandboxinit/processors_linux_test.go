//go:build linux

package sandboxinit_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sandboxinit"
)

// The process an init becomes has every processor of its machine, whichever
// ones the init was started on: an agent may keep to fewer, and what it
// starts inherits that until it is the session's own code.
func TestProcessAnInitBecomesHasEveryProcessor(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var was unix.CPUSet
	if err := unix.SchedGetaffinity(0, &was); err != nil {
		t.Fatal(err)
	}
	if was.Count() < 2 {
		t.Skip("one processor here")
	}
	// The init starts from a thread kept to one processor.
	var one unix.CPUSet
	for cpu := range len(was) * 64 {
		if was.IsSet(cpu) {
			one.Set(cpu)
			break
		}
	}
	if err := unix.SchedSetaffinity(0, &one); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.SchedSetaffinity(0, &was) }()
	out := filepath.Join(t.TempDir(), "out")
	cmd, agent := start(t)
	send(t, agent, sandboxinit.Process{
		Argv: []string{"sh", "-c", `nproc > "$OUT"`},
		Env:  []string{"PATH=/usr/bin:/bin", "OUT=" + out},
	})
	if err := cmd.Wait(); err != nil {
		t.Fatalf("the process ended with %v", err)
	}
	said, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := strconv.Atoi(strings.TrimSpace(string(said))); err != nil || got < was.Count() {
		t.Fatalf("the process had %q processors, and its machine gives this test %d", said, was.Count())
	}
}
