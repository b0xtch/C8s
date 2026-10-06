package sessiond

import (
	"context"
	"errors"
	"sync"
)

// errLineFull is a bind that found as many of its caller's binds waiting as
// the caller may have in line.
var errLineFull = errors.New("as many of this caller's binds wait their turn as this host runs TDs")

// turns bounds how many binds are in their guests' hands at once. A bind
// that finds as many in flight waits for one of them to end. Turns go round
// the callers that have binds waiting, each caller's oldest bind first, so
// one caller's many binds do not keep another's from its turn. A caller may
// have so many binds in line and no more, so that what waits is bounded, and
// by each caller's own binds alone.
type turns struct {
	mu sync.Mutex
	// line is the most binds one caller may have waiting.
	line int
	// free is how many more binds may go through now. It is above zero
	// only while nobody waits.
	free int
	// waiting is each caller's binds that wait, in the order they came, and
	// round the callers that have any, in the order of their next turns.
	waiting map[string][]*waiter
	round   []string
}

// waiter is one bind that waits for a turn.
type waiter struct {
	// granted is closed when the turn is the bind's.
	granted chan struct{}
}

// newTurns returns the bound for n binds at once, with at most line of one
// caller's binds waiting, or none for n of 0.
func newTurns(n, line int) *turns {
	if n <= 0 {
		return nil
	}
	return &turns{free: n, line: max(line, 1), waiting: map[string][]*waiter{}}
}

// take waits for a turn for a bind of caller's and returns what gives the
// turn back, which may be called more than once and from anywhere. waited
// says whether the bind had to wait. The turn is given back when ctx ends,
// if nobody gave it back sooner: a call that is over holds none. A caller
// that leaves before its bind's turn comes gets none, and the error says so,
// as it does for a bind that finds its caller's line full.
func (t *turns) take(ctx context.Context, caller string) (done func(), waited bool, err error) {
	if t == nil {
		return func() {}, false, nil
	}
	t.mu.Lock()
	if t.free > 0 {
		t.free--
		t.mu.Unlock()
		return t.held(ctx), false, nil
	}
	if len(t.waiting[caller]) >= t.line {
		t.mu.Unlock()
		return nil, false, errLineFull
	}
	w := &waiter{granted: make(chan struct{})}
	if len(t.waiting[caller]) == 0 {
		t.round = append(t.round, caller)
	}
	t.waiting[caller] = append(t.waiting[caller], w)
	t.mu.Unlock()
	select {
	case <-w.granted:
		return t.held(ctx), true, nil
	case <-ctx.Done():
	}
	t.mu.Lock()
	select {
	case <-w.granted:
		// The turn came as the caller left: it goes to the next.
		t.mu.Unlock()
		t.give()
	default:
		t.leave(caller, w)
		t.mu.Unlock()
	}
	return nil, true, ctx.Err()
}

// held is what gives a taken turn back, once, by whoever calls it first or
// by the end of ctx.
func (t *turns) held(ctx context.Context) func() {
	done := sync.OnceFunc(t.give)
	context.AfterFunc(ctx, done)
	return done
}

// give passes a turn to the bind whose turn is next, or keeps it free.
func (t *turns) give() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.round) == 0 {
		t.free++
		return
	}
	caller := t.round[0]
	t.round = t.round[1:]
	queue := t.waiting[caller]
	next := queue[0]
	if len(queue) == 1 {
		delete(t.waiting, caller)
	} else {
		// The caller's next bind takes its place at the back of the round.
		t.waiting[caller] = queue[1:]
		t.round = append(t.round, caller)
	}
	close(next.granted)
}

// leave takes a bind that waits out of its caller's line. The caller of
// leave holds the lock.
func (t *turns) leave(caller string, w *waiter) {
	queue := t.waiting[caller]
	for i, other := range queue {
		if other != w {
			continue
		}
		queue = append(queue[:i:i], queue[i+1:]...)
		break
	}
	if len(queue) > 0 {
		t.waiting[caller] = queue
		return
	}
	delete(t.waiting, caller)
	for i, other := range t.round {
		if other == caller {
			t.round = append(t.round[:i:i], t.round[i+1:]...)
			break
		}
	}
}

// lines is how many binds wait for a turn.
func (t *turns) lines() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, queue := range t.waiting {
		n += len(queue)
	}
	return n
}
