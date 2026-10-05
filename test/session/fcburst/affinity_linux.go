package main

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// affinity returns what a goroutine calls before it starts a VMM: it keeps
// the goroutine's thread, and so the process the thread starts next, to the
// CPUs of list, and returns what puts the thread back. With no list it
// changes nothing.
func affinity(list string) (func() (func(), error), error) {
	if list == "" {
		return func() (func(), error) { return func() {}, nil }, nil
	}
	var want unix.CPUSet
	for _, part := range strings.Split(list, ",") {
		low, high, ranged := strings.Cut(part, "-")
		if !ranged {
			high = low
		}
		from, err := strconv.Atoi(low)
		to, err2 := strconv.Atoi(high)
		if err != nil || err2 != nil || from < 0 || to < from {
			return nil, fmt.Errorf("%q is no CPU or range of CPUs", part)
		}
		for cpu := from; cpu <= to; cpu++ {
			want.Set(cpu)
		}
	}
	if want.Count() == 0 {
		return nil, errors.New("the list names no CPU")
	}
	return func() (func(), error) {
		runtime.LockOSThread()
		var was unix.CPUSet
		if err := unix.SchedGetaffinity(0, &was); err != nil {
			runtime.UnlockOSThread()
			return nil, err
		}
		if err := unix.SchedSetaffinity(0, &want); err != nil {
			runtime.UnlockOSThread()
			return nil, fmt.Errorf("keep a VMM to CPUs %s: %w", list, err)
		}
		return func() {
			_ = unix.SchedSetaffinity(0, &was)
			runtime.UnlockOSThread()
		}, nil
	}, nil
}
