//go:build linux

package sandboxinit

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// everyProcessor gives the calling thread every processor of the guest, and
// keeps the caller on that thread: the process this one becomes at its exec
// has what the thread that called exec has. An agent may keep its own work
// to fewer processors, and whatever it starts inherits that.
func everyProcessor() {
	runtime.LockOSThread()
	var all unix.CPUSet
	for cpu := range len(all) * 64 {
		all.Set(cpu)
	}
	// The kernel takes of the set what the guest has.
	_ = unix.SchedSetaffinity(0, &all)
}
