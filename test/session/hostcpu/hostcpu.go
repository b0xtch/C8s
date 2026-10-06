// Package hostcpu reads how much CPU a host has given so far, for the tools
// that time bursts of starts. The difference over a burst is all the CPU the
// host gave while it ran, whoever took it: guests, their VMMs, the kernel's
// own threads, the quoting service, the daemon. With it goes what the
// reading program took itself, since the program that starts a burst is no
// part of the host's cost of one.
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
type Reading struct{ Host, Own int64 }

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
	return Reading{Host: host, Own: own()}, true
}

// Since is what was given between an earlier reading and this one.
func (r Reading) Since(before Reading) Reading {
	return Reading{Host: r.Host - before.Host, Own: r.Own - before.Own}
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
