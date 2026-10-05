package sessionagent

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// bindTrace is when the parts of taking a bind were done, each as
// microseconds since the bind's request was read, and what the bind cost the
// guest's processors, for the agent's own log. None of it leaves the guest:
// what a caller is told of an admission's steps is the disclosure schema's
// list.
type bindTrace struct {
	began time.Time
	spent spent
	mu    sync.Mutex
	marks []any
}

type bindTraceKey struct{}

func withBindTrace(ctx context.Context) (context.Context, *bindTrace) {
	t := &bindTrace{began: time.Now(), spent: spentNow()}
	return context.WithValue(ctx, bindTraceKey{}, t), t
}

// spent is processor time: the agent's own and that of its children that
// have ended, as the kernel accounts both, the part of the agent's that its
// collector took, as the runtime estimates it, and what every processor of
// the guest ran in all, where the kernel says: tasks' time by the
// scheduler's count, and the kernel's own split of all time by its tick.
// With it go the collections the runtime has run and the heap they mark.
type spent struct {
	agent, children, collector, guest time.Duration
	user, system, interrupts, idle    time.Duration
	collections, heap                 uint64
}

// cost is what the guest's processors gave since the bind was read, as the
// members of a log line.
func (t *bindTrace) cost() []any { return costSince(t.spent) }

// costSince is what the guest's processors gave since before was read, as
// the members of a log line.
func costSince(before spent) []any {
	now := spentNow()
	return []any{
		"agent_cpu_us", (now.agent - before.agent).Microseconds(),
		"children_cpu_us", (now.children - before.children).Microseconds(),
		"collector_cpu_us", (now.collector - before.collector).Microseconds(),
		"collections", now.collections - before.collections,
		"heap_kb", now.heap >> 10,
		"guest_cpu_us", (now.guest - before.guest).Microseconds(),
		"guest_user_ms", (now.user - before.user).Milliseconds(),
		"guest_system_ms", (now.system - before.system).Milliseconds(),
		"guest_interrupts_ms", (now.interrupts - before.interrupts).Milliseconds(),
		"guest_idle_ms", (now.idle - before.idle).Milliseconds(),
	}
}

// traced records that the part named is done now.
func traced(ctx context.Context, part string) {
	if t, ok := ctx.Value(bindTraceKey{}).(*bindTrace); ok {
		t.add(part, time.Since(t.began))
	}
}

// tracedFor records how long the part named took, where that is not the time
// since the part before it.
func tracedFor(ctx context.Context, part string, took time.Duration) {
	if t, ok := ctx.Value(bindTraceKey{}).(*bindTrace); ok {
		t.add(part, took)
	}
}

func (t *bindTrace) add(part string, d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.marks = append(t.marks, part+"_us", d.Microseconds())
}

func (t *bindTrace) log(log *slog.Logger) {
	t.mu.Lock()
	defer t.mu.Unlock()
	log.Info("a bind was served", append(t.marks, t.cost()...)...)
}

// ended logs what the bind's whole call cost: the bind, and what followed
// its answer on the same call, such as the first command and the quote.
func (t *bindTrace) ended(log *slog.Logger) {
	log.Info("a bind's call ended", append([]any{"took_us", time.Since(t.began).Microseconds()}, t.cost()...)...)
}
