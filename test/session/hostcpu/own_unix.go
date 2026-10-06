//go:build unix

package hostcpu

import "syscall"

// own is the CPU time of this process, in user mode and in the kernel.
func own() int64 {
	var used syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &used); err != nil {
		return 0
	}
	return (used.Utime.Nano() + used.Stime.Nano()) / 1000
}
