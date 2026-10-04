//go:build linux

package sessionagent

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// idleThread ties the calling goroutine to its thread and gives that thread
// the idle scheduling class: it runs only when nothing else in the guest
// wants its CPU. The goroutine must end without unlocking, which ends the
// thread with it.
func idleThread() error {
	runtime.LockOSThread()
	return unix.SchedSetAttr(0, &unix.SchedAttr{Policy: unix.SCHED_IDLE}, 0)
}
