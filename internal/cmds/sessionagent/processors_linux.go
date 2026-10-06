//go:build linux

package sessionagent

import (
	"errors"
	"fmt"
	"os"
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
