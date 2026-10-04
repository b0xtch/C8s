package sessionagent

import (
	"math"
	"sync"
	"time"
)

// The host's quoting service signs for every guest on the host. A guest that
// asked without limit, at the pace of whoever holds one of its keys, would
// take that service from the others. Each guest therefore rations its fresh
// quotes: a burst for a client that opens several sessions at once, a steady
// pace after it, and at most a second's worth booked ahead.
const (
	quoteBurst     = 20
	quotePerSecond = 5
	quoteDebt      = quotePerSecond
)

// quoteBudget is a token bucket over the guest's own clock, whose callers
// book the next token and wait for it.
type quoteBudget struct {
	mu     sync.Mutex
	now    func() time.Time
	tokens float64
	last   time.Time
}

func newQuoteBudget(now func() time.Time) *quoteBudget {
	return &quoteBudget{now: now, tokens: quoteBurst, last: now()}
}

// reserve books one quote, due after wait: at once while the burst lasts,
// then in turn. With a second's worth already booked it books nothing, and
// wait is how long until it would.
func (b *quoteBudget) reserve() (wait time.Duration, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens = math.Min(quoteBurst, b.tokens+elapsed.Seconds()*quotePerSecond)
		b.last = now
	}
	due := func(tokens float64) time.Duration {
		return time.Duration(math.Round(tokens / quotePerSecond * float64(time.Second)))
	}
	if b.tokens-1 < -quoteDebt {
		return due(1 - quoteDebt - b.tokens), false
	}
	b.tokens--
	if b.tokens >= 0 {
		return 0, true
	}
	return due(-b.tokens), true
}

// take books one quote if one is due now, and nothing otherwise: for a quote
// nobody is waiting for by itself.
func (b *quoteBudget) take() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens = math.Min(quoteBurst, b.tokens+elapsed.Seconds()*quotePerSecond)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
