//go:build linux

package sessionagent

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"
)

// keepTo keeps every thread of this process to the guest's first n
// processors. Threads it starts later and processes it starts inherit that:
// the runtime it starts containers with, and the sandbox's init until the
// init becomes code of the session's, which has every processor again.
func keepTo(n int) error {
	var set unix.CPUSet
	for cpu := range n {
		set.Set(cpu)
	}
	// A thread started while the others were being kept may have come from
	// one that was not yet: look until a pass finds none it had not kept.
	kept := map[int]bool{}
	for {
		tasks, err := os.ReadDir("/proc/self/task")
		if err != nil {
			return fmt.Errorf("list the agent's threads: %w", err)
		}
		found := false
		for _, task := range tasks {
			tid, err := strconv.Atoi(task.Name())
			if err != nil || kept[tid] {
				continue
			}
			// A thread that ended since the listing has nothing to keep.
			if err := unix.SchedSetaffinity(tid, &set); err != nil && !errors.Is(err, unix.ESRCH) {
				return fmt.Errorf("keep the agent to %d processors: %w", n, err)
			}
			kept[tid], found = true, true
		}
		if !found {
			return nil
		}
	}
}

// startWide starts cmd with every processor the agent was started with. A
// process has what the thread that started it has, and an agent kept to
// fewer has no such thread, so the calling one takes them for the start.
func startWide(cmd *exec.Cmd) error {
	// A locked thread is none the runtime starts another from.
	runtime.LockOSThread()
	var was unix.CPUSet
	if err := unix.SchedGetaffinity(0, &was); err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("read the agent's processors: %w", err)
	}
	if was.Count() >= runtime.NumCPU() {
		runtime.UnlockOSThread()
		return cmd.Start()
	}
	var all unix.CPUSet
	for cpu := range len(all) * 64 {
		all.Set(cpu)
	}
	// The kernel takes of the set what the guest has.
	if err := unix.SchedSetaffinity(0, &all); err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("take the guest's processors for a command: %w", err)
	}
	err := cmd.Start()
	// A thread that cannot go back stays locked, and so ends with its caller.
	if unix.SchedSetaffinity(0, &was) == nil {
		runtime.UnlockOSThread()
	}
	return err
}
