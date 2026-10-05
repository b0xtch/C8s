//go:build unix

package sessionagent

import (
	"bytes"
	"os"
	"runtime/metrics"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// spentNow reads the processor time given so far. A part the system does
// not say stays at nothing.
func spentNow() spent {
	var now spent
	var usage unix.Rusage
	if unix.Getrusage(unix.RUSAGE_SELF, &usage) == nil {
		now.agent = processorTime(&usage)
	}
	if unix.Getrusage(unix.RUSAGE_CHILDREN, &usage) == nil {
		now.children = processorTime(&usage)
	}
	sample := []metrics.Sample{{Name: "/cpu/classes/gc/total:cpu-seconds"}, {Name: "/gc/cycles/total:gc-cycles"}, {Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(sample)
	if sample[0].Value.Kind() == metrics.KindFloat64 {
		now.collector = time.Duration(sample[0].Value.Float64() * float64(time.Second))
	}
	if sample[1].Value.Kind() == metrics.KindUint64 {
		now.collections = sample[1].Value.Uint64()
	}
	if sample[2].Value.Kind() == metrics.KindUint64 {
		now.heap = sample[2].Value.Uint64()
	}
	now.guest = ranOnEveryProcessor()
	if data, err := os.ReadFile("/proc/stat"); err == nil {
		now.user, now.system, now.interrupts, now.idle = splitOf(data)
	}
	return now
}

// tick is the unit the kernel states processor time in to programs.
const tick = time.Second / 100

// splitOf reads the kernel's own split of all its processors' time from the
// first line of its statistics: in programs, in the kernel for them, in
// interrupts of both kinds, and idle.
func splitOf(stat []byte) (user, system, interrupts, idle time.Duration) {
	line, _, _ := bytes.Cut(stat, []byte("\n"))
	fields := bytes.Fields(line)
	if len(fields) < 8 || string(fields[0]) != "cpu" {
		return 0, 0, 0, 0
	}
	// cpu, then user, nice, system, idle, iowait, irq and softirq, in ticks.
	at := func(i int) time.Duration {
		n, _ := strconv.ParseInt(string(fields[i]), 10, 64)
		return time.Duration(n) * tick
	}
	return at(1) + at(2), at(3), at(6) + at(7), at(4) + at(5)
}

func processorTime(usage *unix.Rusage) time.Duration {
	return time.Duration(usage.Utime.Nano() + usage.Stime.Nano())
}

// ranOnEveryProcessor is how long tasks have run on all of the guest's
// processors together, from the scheduler's own count, or nothing where the
// kernel keeps none.
func ranOnEveryProcessor() time.Duration {
	data, err := os.ReadFile("/proc/schedstat")
	if err != nil {
		return 0
	}
	return ranIn(data)
}

// ranIn adds up the time run on each processor that the scheduler's
// statistics list.
func ranIn(data []byte) time.Duration {
	var ran time.Duration
	for _, line := range bytes.Split(data, []byte("\n")) {
		// cpu<n>, then nine counts: the seventh is the time run, in ns.
		fields := bytes.Fields(line)
		if len(fields) < 8 || !bytes.HasPrefix(fields[0], []byte("cpu")) {
			continue
		}
		if ns, err := strconv.ParseInt(string(fields[7]), 10, 64); err == nil {
			ran += time.Duration(ns)
		}
	}
	return ran
}
