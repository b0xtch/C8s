package sessionagent

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// bindTrace is when the parts of taking a bind were done, each as
// microseconds since the bind's request was read, for the agent's own log.
// None of it leaves the guest: what a caller is told of an admission's steps
// is the disclosure schema's list.
type bindTrace struct {
	began time.Time
	mu    sync.Mutex
	marks []any
}

type bindTraceKey struct{}

func withBindTrace(ctx context.Context) (context.Context, *bindTrace) {
	t := &bindTrace{began: time.Now()}
	return context.WithValue(ctx, bindTraceKey{}, t), t
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
	log.Info("a bind was served", t.marks...)
}
