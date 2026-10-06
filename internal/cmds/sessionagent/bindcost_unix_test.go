//go:build unix

package sessionagent

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// The time a guest's processors ran is the seventh count of each processor's
// line of the scheduler's statistics, whatever else the file holds.
func TestRanInAddsEachProcessorsRunTime(t *testing.T) {
	const stats = `version 17
timestamp 4294892412
cpu0 0 0 0 0 0 0 1500000000 20000000 4321
domain0 SMT 3 0 0 0 0 0 0 0 0
cpu1 0 0 0 0 0 0 500000000 10000000 1234
cpu2 0 0 0
not a line of it
`
	if got := ranIn([]byte(stats)); got != 2*time.Second {
		t.Fatalf("the processors ran %s, want 2s", got)
	}
	if got := ranIn(nil); got != 0 {
		t.Fatalf("no statistics: %s", got)
	}
}

// What a bind cost is the difference from when it was read, and never less
// than nothing for the agent's own time.
func TestBindTraceCostsWhatWasSpentSinceTheBind(t *testing.T) {
	_, trace := withBindTrace(t.Context())
	deadline := time.Now().Add(20 * time.Millisecond)
	for n := 0; time.Now().Before(deadline); n++ {
		_ = n * n
	}
	cost := trace.cost()
	if len(cost) != 20 || cost[0] != "agent_cpu_us" || cost[2] != "children_cpu_us" || cost[4] != "collector_cpu_us" || cost[10] != "guest_cpu_us" {
		t.Fatalf("the members of a bind's cost: %v", cost)
	}
	if ran, ok := cost[1].(int64); !ok || ran < 5000 {
		t.Fatalf("the agent spun for 20 ms and its bind cost it %v us", cost[1])
	}
}

// A bind's own line says when its parts were done and reads no cost. The
// cost is read once, when the bind's call has ended, so that no answer on
// the call waits on the reading.
func TestBindTraceReadsItsCostAtTheCallsEnd(t *testing.T) {
	var logged bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logged, nil))
	ctx, trace := withBindTrace(t.Context())
	traced(ctx, "answered")
	trace.log(log)
	if line := logged.String(); !strings.Contains(line, `"answered_us"`) || strings.Contains(line, "_cpu_us") {
		t.Fatalf("a bind's own line: %s", line)
	}
	logged.Reset()
	trace.ended(log)
	if line := logged.String(); !strings.Contains(line, `"took_us"`) || !strings.Contains(line, `"agent_cpu_us"`) || !strings.Contains(line, `"guest_idle_ms"`) {
		t.Fatalf("the end of a bind's call: %s", line)
	}
}

// The kernel's split of its processors' time is the first line of its
// statistics, in hundredths of a second.
func TestSplitOfReadsTheKernelsFirstLine(t *testing.T) {
	const stat = "cpu  200 10 300 4000 50 6 14 0 0 0\ncpu0 100 5 150 2000 25 3 7 0 0 0\nintr 1 2 3\n"
	user, system, interrupts, idle := splitOf([]byte(stat))
	if user != 2100*time.Millisecond || system != 3*time.Second || interrupts != 200*time.Millisecond || idle != 40500*time.Millisecond {
		t.Fatalf("user %s, system %s, interrupts %s, idle %s", user, system, interrupts, idle)
	}
	if user, system, interrupts, idle = splitOf([]byte("something else\n")); user+system+interrupts+idle != 0 {
		t.Fatal("a file that is not the kernel's statistics was read as them")
	}
}
