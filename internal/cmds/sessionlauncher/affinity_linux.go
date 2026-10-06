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

// startOn starts cmd on the CPUs in keep, or where keep is empty on the ones
// this launcher has, and never on those in avoid; it reports which of avoid
// it kept the process off. A process takes the allowed CPUs of the thread
// that starts it, and every thread it makes takes them from it: a VMM's vCPU
// threads, and the kernel's vhost workers for it. The launcher itself stays
// where it was, so a host can keep its guests' VMMs to CPUs that none of its
// own programs run on. A process that would be left no CPU is started on
// those it was to keep to, or as it is.
func startOn(cmd *exec.Cmd, keep, avoid []int) ([]int, error) {
	// The thread, with its allowed CPUs, is this goroutine's until the start.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var was unix.CPUSet
	if err := unix.SchedGetaffinity(0, &was); err != nil {
		return nil, fmt.Errorf("read the allowed CPUs: %w", err)
	}
	on := was
	if len(keep) > 0 {
		on = unix.CPUSet{}
		for _, cpu := range keep {
			on.Set(cpu)
		}
		if on.Count() != len(keep) {
			return nil, fmt.Errorf("CPUs %v are more than this launcher can name", keep)
		}
	}
	now := on
	var off []int
	for _, cpu := range avoid {
		if now.IsSet(cpu) {
			now.Clear(cpu)
			off = append(off, cpu)
		}
	}
	if now.Count() == 0 {
		now, off = on, nil
	}
	if now == was {
		return off, cmd.Start()
	}
	if err := unix.SchedSetaffinity(0, &now); err != nil {
		return nil, fmt.Errorf("move to the VMM's CPUs: %w", err)
	}
	err := cmd.Start()
	// The thread goes back to the launcher's others as it was.
	if back := unix.SchedSetaffinity(0, &was); back != nil && err == nil {
		err = fmt.Errorf("move back from the VMM's CPUs: %w", back)
	}
	return off, err
}
