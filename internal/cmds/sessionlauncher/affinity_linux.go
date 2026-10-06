//go:build linux

package sessionlauncher

import (
	"fmt"
	"os/exec"

	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/coresched"
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
//
// The process is started apart from every other on the host's cores, with a
// core-scheduling cookie of its own (coresched): a core's two hardware
// threads then never run this guest and another at the same time. apart is
// false on a host whose cores have one hardware thread each.
func startOn(cmd *exec.Cmd, keep, avoid []int) (off []int, apart bool, err error) {
	// The thread that starts cmd is placed first, and ends with the start.
	apart, err = coresched.Start(cmd, func() error {
		var was unix.CPUSet
		if err := unix.SchedGetaffinity(0, &was); err != nil {
			return fmt.Errorf("read the allowed CPUs: %w", err)
		}
		on := was
		if len(keep) > 0 {
			on = unix.CPUSet{}
			for _, cpu := range keep {
				on.Set(cpu)
			}
			if on.Count() != len(keep) {
				return fmt.Errorf("CPUs %v are more than this launcher can name", keep)
			}
		}
		now := on
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
			return nil
		}
		if err := unix.SchedSetaffinity(0, &now); err != nil {
			return fmt.Errorf("move to the VMM's CPUs: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return off, apart, nil
}
