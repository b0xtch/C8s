package sessionagent

import (
	"testing"
	"time"
)

func TestQuoteBudget(t *testing.T) {
	const step = time.Second / quotePerSecond
	now := time.Now()
	b := newQuoteBudget(func() time.Time { return now })
	book := func(what string, want time.Duration, wantOK bool) {
		t.Helper()
		if wait, ok := b.reserve(); ok != wantOK || wait != want {
			t.Fatalf("%s: booked %v, due in %s; want %v, %s", what, ok, wait, wantOK, want)
		}
	}
	for range quoteBurst {
		book("the burst", 0, true)
	}
	// Past the burst each caller is due one step after the one before, up to
	// a second ahead.
	for i := range quoteDebt {
		book("booked ahead", time.Duration(i+1)*step, true)
	}
	// Then nothing is booked, and the caller is told when something would be.
	book("a second already booked", step, false)
	book("a refusal books nothing", step, false)
	now = now.Add(step / 2)
	book("halfway to the next booking", step/2, false)
	now = now.Add(step / 2)
	book("one step later", quoteDebt*step, true)

	// Time pays the booked quotes off first, then refills, never past the burst.
	now = now.Add(time.Second)
	book("after the second that was booked, the next is one step away", step, true)
	now = now.Add(time.Hour)
	for range quoteBurst {
		book("the burst after an idle hour", 0, true)
	}
	book("an idle hour saved up no more than the burst", step, true)
	// A clock that steps back gives nothing.
	now = now.Add(-time.Minute)
	book("after the clock stepped back", 2*step, true)
}

// A quote nobody waits for is taken only when one is due now: it books
// nothing ahead and owes nothing.
func TestQuoteBudgetTakesOnlyWhatIsDue(t *testing.T) {
	const step = time.Second / quotePerSecond
	now := time.Now()
	b := newQuoteBudget(func() time.Time { return now })
	for i := range quoteBurst {
		if !b.take() {
			t.Fatalf("quote %d of the burst was not due", i+1)
		}
	}
	if b.take() {
		t.Fatal("a quote was taken past the burst")
	}
	// The refusal booked nothing: the next quote is due one step on, to a
	// taker and to a caller that waits alike.
	now = now.Add(step / 2)
	if b.take() {
		t.Fatal("a quote was taken half a step on")
	}
	now = now.Add(step / 2)
	if !b.take() || b.take() {
		t.Fatal("one step on, one quote is due and no more")
	}
	if wait, ok := b.reserve(); !ok || wait != step {
		t.Fatalf("a caller that waits books the next: %v, due in %s", ok, wait)
	}
	// What is booked ahead is not there to take.
	now = now.Add(step)
	if b.take() {
		t.Fatal("a booked quote was taken a second time")
	}
	// An idle hour refills the burst and no more.
	now = now.Add(time.Hour)
	for i := range quoteBurst {
		if !b.take() {
			t.Fatalf("quote %d after an idle hour was not due", i+1)
		}
	}
	if b.take() {
		t.Fatal("an idle hour saved up more than the burst")
	}
}
