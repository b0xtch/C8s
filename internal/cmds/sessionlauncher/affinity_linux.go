//go:build linux

package sessionlauncher

import (
	"fmt"
	"os/exec"
	"runtime"

	"golang.org/x/sys/unix"
)

// sysfsRoot is where the kernel describes the machine.
var sysfsRoot = "/sys"

// writeBackCPUs lists the CPUs a TDX host writes its caches back on.
func writeBackCPUs() ([]int, error) { return packageFirstCPUs(sysfsRoot) }

// startAway starts cmd so that it never runs on the CPUs in avoid, and
// reports which of them it kept the process off. A process takes the allowed
// CPUs of the thread that starts it, and every thread it makes takes them
// from it: a VMM's vCPU threads, and the kernel's vhost workers for it. A
// caller that may run on no other CPU starts cmd as it is.
func startAway(cmd *exec.Cmd, avoid []int) ([]int, error) {
	// The thread, with its allowed CPUs, is this goroutine's until the start.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var was unix.CPUSet
	if err := unix.SchedGetaffinity(0, &was); err != nil {
		return nil, fmt.Errorf("read the allowed CPUs: %w", err)
	}
	now := was
	var off []int
	for _, cpu := range avoid {
		if now.IsSet(cpu) {
			now.Clear(cpu)
			off = append(off, cpu)
		}
	}
	if now.Count() == 0 {
		return nil, cmd.Start()
	}
	if err := unix.SchedSetaffinity(0, &now); err != nil {
		return nil, fmt.Errorf("leave CPUs %v: %w", off, err)
	}
	err := cmd.Start()
	// The thread goes back to the launcher's others as it was.
	if back := unix.SchedSetaffinity(0, &was); back != nil && err == nil {
		err = fmt.Errorf("take CPUs %v back: %w", off, back)
	}
	return off, err
}
