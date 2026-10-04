//go:build linux && amd64

package imagestoretest

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

// The probe is a program the kernel runs, and its exit status is the kernel's
// answer: none for a family every machine has, and an error number for one
// that does not exist.
func TestSocketProbeRuns(t *testing.T) {
	run := func(family uint32) int {
		t.Helper()
		path := filepath.Join(t.TempDir(), "probe")
		if err := os.WriteFile(path, SocketProbe(family), 0o755); err != nil {
			t.Fatal(err)
		}
		err := exec.Command(path).Run()
		var exit *exec.ExitError
		switch {
		case err == nil:
			return 0
		case errors.As(err, &exit):
			return exit.ExitCode()
		}
		t.Fatalf("the probe did not run: %v", err)
		return -1
	}
	if got := run(afInet); got != 0 {
		t.Errorf("an inet socket: exit %d, want 0", got)
	}
	// No such family: the kernel says so, and the probe passes it on.
	if got := run(1000); got != int(syscall.EAFNOSUPPORT) && got != int(syscall.EINVAL) {
		t.Errorf("a family that does not exist: exit %d, want %d or %d", got, syscall.EAFNOSUPPORT, syscall.EINVAL)
	}
}
