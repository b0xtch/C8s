// Package hostcpu reads how much CPU a host has given so far, for the tools
// that time bursts of starts. The difference over a burst is all the CPU the
// host gave while it ran, whoever took it: guests, their VMMs, the kernel's
// own threads, the quoting service, the daemon. With it goes what the
// reading program took itself, since the program that starts a burst is no
// part of the host's cost of one. With both goes how long the reading
// program's threads have waited for a processor: a program that starts a
// burst stands for front ends that scale out, so a burst it held back for
// want of a processor was bounded by it, and its record can say so.
package hostcpu

import (
	"os"
	"strconv"
	"strings"
)

// rootStat is the kernel's count for every task of the host, at the root of
// its control groups.
const rootStat = "/sys/fs/cgroup/cpu.stat"

// Reading is CPU time so far, in microseconds: Host is all the host has
// given, by its kernel's count, and Own what this process has taken of it.
// Waited is how long this process's threads have stood ready to run with no
// processor to run on, by the scheduler's count, where the kernel keeps it.
type Reading struct{ Host, Own, Waited int64 }

// Now reads both. It reports false where the kernel does not say what the
// host has given: on another system than Linux, or without a unified
// control group hierarchy.
func Now() (Reading, bool) {
	stat, err := os.ReadFile(rootStat)
	if err != nil {
		return Reading{}, false
	}
	host, ok := usageIn(stat)
	if !ok {
		return Reading{}, false
	}
	return Reading{Host: host, Own: own(), Waited: waited(tasksDir)}, true
}

// Since is what was given between an earlier reading and this one.
func (r Reading) Since(before Reading) Reading {
	return Reading{Host: r.Host - before.Host, Own: r.Own - before.Own, Waited: r.Waited - before.Waited}
}

// tasksDir lists this process's threads, each with the scheduler's counts
// for it.
const tasksDir = "/proc/self/task"

// waited sums, over the threads listed in dir, the second count of each
// one's schedstat: nanoseconds spent ready to run and not running. A thread
// that ended since the listing, or a kernel that keeps no such counts, adds
// nothing.
func waited(dir string) int64 {
	tasks, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	var total int64
	for _, task := range tasks {
		stat, err := os.ReadFile(dir + "/" + task.Name() + "/schedstat")
		if err != nil {
			continue
		}
		if fields := strings.Fields(string(stat)); len(fields) >= 2 {
			if ns, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				total += ns
			}
		}
	}
	return total / 1000
}

// usageIn finds the line of a control group's statistics that holds all of
// its tasks' time.
func usageIn(stat []byte) (int64, bool) {
	for line := range strings.Lines(string(stat)) {
		name, value, _ := strings.Cut(strings.TrimSpace(line), " ")
		if name != "usage_usec" {
			continue
		}
		usage, err := strconv.ParseInt(value, 10, 64)
		return usage, err == nil
	}
	return 0, false
}
