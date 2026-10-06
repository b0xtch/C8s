package sessionagent_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// A command with no cgroup leaves nothing behind either: what it started and
// did not wait for is ended with it. On Linux that is done once the command
// has ended and before it is waited for, while its number still names its
// group and no other, so a leftover that holds the command's output open
// does not hold up the command's result.
func TestBareCommandLeavesNothingBehind(t *testing.T) {
	runner, err := sessionagent.NewProcessRunner(sessionagent.RunnerConfig{UID: -1, GID: -1, Home: t.TempDir(), CredentialDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	mark := filepath.Join(t.TempDir(), "left")
	began := time.Now()
	resp, err := runner.Exec(ctxT(t), &session.ExecRequest{ID: "leaves", Argv: []string{"sh", "-c", "sleep 300 & echo $! > " + mark + "; echo said; exit 5"}})
	took := time.Since(began)
	if err != nil {
		t.Fatal(err)
	}
	if resp.ExitCode != 5 || string(resp.Stdout) != "said\n" {
		t.Fatalf("the command: %+v", resp)
	}
	if runtime.GOOS == "linux" && took > time.Second {
		t.Errorf("the command's result waited %s on what it left behind", took)
	}
	left, err := os.ReadFile(mark)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(left)))
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("process %d, which the command left behind, is still there", pid)
		}
	}
}
