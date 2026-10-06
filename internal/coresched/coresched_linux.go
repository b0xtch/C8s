//go:build linux

package coresched

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// smtActive says whether any core of the host runs two hardware threads.
var smtActive = "/sys/devices/system/cpu/smt/active"

func start(cmd *exec.Cmd, place func() error) (bool, error) {
	type started struct {
		apart bool
		err   error
	}
	done := make(chan started, 1)
	// Started before the thread below has a cookie to hand on.
	none := plainThread()
	go func() {
		// The thread is this goroutine's, and ends with it: the goroutine
		// never unlocks it. No other work of this program then runs with
		// the cookie or on the CPUs the thread is given here.
		runtime.LockOSThread()
		if place != nil {
			if err := place(); err != nil {
				done <- started{err: err}
				return
			}
		}
		apart, err := cookie()
		if err != nil {
			done <- started{err: err}
			return
		}
		// What the thread starts takes its cookie, and every thread that
		// makes takes it in turn.
		err = cmd.Start()
		if apart {
			// The cookie is the started program's now.
			giveUp(none)
		}
		done <- started{apart, err}
	}()
	out := <-done
	return out.apart, out.err
}

// cookie gives the calling thread a core-scheduling cookie of its own.
func cookie() (bool, error) {
	err := unix.Prctl(unix.PR_SCHED_CORE, unix.PR_SCHED_CORE_CREATE, 0, unix.PR_SCHED_CORE_SCOPE_THREAD, 0)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.ENODEV):
		// The kernel's word for cores of one hardware thread each.
		return false, nil
	}
	if data, readErr := os.ReadFile(smtActive); readErr != nil || strings.TrimSpace(string(data)) != "1" {
		return false, nil
	}
	return false, fmt.Errorf("this host's cores run two hardware threads each, and its kernel gives a program no core-scheduling cookie to keep them to one guest at a time: %w", err)
}

// plain is a thread of this program that is kept for one thing: it never
// makes a cookie, so a thread that takes over its none holds none.
var plain struct {
	once sync.Once
	tid  int
}

// plainThread starts that thread, once, and names it.
func plainThread() int {
	plain.once.Do(func() {
		named := make(chan int)
		go func() {
			// Locked for good: no start runs on it.
			runtime.LockOSThread()
			named <- unix.Gettid()
			select {}
		}()
		plain.tid = <-named
	})
	return plain.tid
}

// giveUp takes the calling thread's cookie from it, so that it holds none
// for whatever time the runtime takes to end it, or for good where the
// runtime keeps the thread and never runs it again, as it does its first.
// The kernel has no call that drops a cookie: a thread takes over that of
// another, and this one takes over the none of the thread that is kept to
// have none.
func giveUp(from int) {
	_ = unix.Prctl(unix.PR_SCHED_CORE, unix.PR_SCHED_CORE_SHARE_FROM, uintptr(from), unix.PR_SCHED_CORE_SCOPE_THREAD, 0)
}

// Cookie is the core-scheduling cookie of the thread or process pid, as the
// kernel names it: zero for none, and equal for two that may share a core.
func Cookie(pid int) (uint64, error) {
	var value uint64
	if err := unix.Prctl(unix.PR_SCHED_CORE, unix.PR_SCHED_CORE_GET, uintptr(pid), unix.PR_SCHED_CORE_SCOPE_THREAD, uintptr(unsafe.Pointer(&value))); err != nil {
		return 0, err
	}
	return value, nil
}
