//go:build linux

package sessionlauncher

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

// A tap is its guest's alone. A daemon starts many launchers, and a process
// started while a tap is open must not come away holding it: a tap lives as
// long as any descriptor of it, and one more attach to a tap that something
// still holds is refused, so the next guest of that slot would never launch.
func TestTapIsNotInheritedByOtherProcesses(t *testing.T) {
	const name = "c8sunit0"
	tap, err := OpenTap(name)
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, os.ErrNotExist) {
		t.Skipf("no tap can be made here: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	// Another launcher, as a daemon starts one: it is handed nothing.
	other := exec.Command("sleep", "30")
	if err := other.Start(); err != nil {
		_ = tap.Close()
		t.Fatal(err)
	}
	defer func() {
		_ = other.Process.Kill()
		_ = other.Wait()
	}()
	if err := tap.Close(); err != nil {
		t.Fatal(err)
	}
	// With its one descriptor closed the tap is gone, and the name is free.
	again, err := OpenTap(name)
	if err != nil {
		t.Fatalf("the tap outlived its descriptor in a process that was not handed it: %v", err)
	}
	_ = again.Close()
}
