package sessiond

import (
	"context"
	"errors"
	"testing"
	"time"
)

// waits blocks until n binds wait for a turn.
func (t *turns) waits(tb testing.TB, n int) {
	tb.Helper()
	for deadline := time.Now().Add(5 * time.Second); t.lines() != n; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			tb.Fatalf("%d binds wait, and %d were to", t.lines(), n)
		}
	}
}

// through is a bind that went through: who sent it, which of its caller's
// it was, and what gives its turn back.
type through struct {
	caller string
	n      int
	done   func()
}

// send has caller send its nth bind, and reports it on went once it is
// through.
func (t *turns) send(tb testing.TB, ctx context.Context, caller string, n int, went chan<- through) {
	go func() {
		done, waited, err := t.take(ctx, caller)
		if err != nil {
			return
		}
		if !waited {
			tb.Errorf("%s's bind %d went through with the bound full, and says it did not wait", caller, n)
		}
		went <- through{caller, n, done}
	}()
}

// No bound lets every bind through at once, and what gives a turn back does
// nothing.
func TestNoBoundOnBindsAtOnce(t *testing.T) {
	none := newTurns(0, 8)
	if none != nil {
		t.Fatal("a bound of 0 is a bound")
	}
	for range 100 {
		done, waited, err := none.take(context.Background(), "a")
		if err != nil || waited {
			t.Fatalf("a bind with no bound: waited %v, %v", waited, err)
		}
		done()
		done()
	}
}

// Past the bound a bind waits, and one caller's binds are let through in
// the order they came, each as a turn is given back. Giving one back twice
// gives back one.
func TestBindsPastTheBoundWaitTheirTurnInOrder(t *testing.T) {
	bound := newTurns(2, 8)
	ctx := context.Background()
	first, waited, err := bound.take(ctx, "a")
	if err != nil || waited {
		t.Fatalf("the first bind: waited %v, %v", waited, err)
	}
	second, waited, err := bound.take(ctx, "a")
	if err != nil || waited {
		t.Fatalf("the second bind: waited %v, %v", waited, err)
	}
	went := make(chan through, 8)
	for i := range 4 {
		bound.send(t, ctx, "a", i, went)
		bound.waits(t, i+1)
	}
	none := func(why string) {
		t.Helper()
		select {
		case w := <-went:
			t.Fatalf("%s: the bind %d went through", why, w.n)
		case <-time.After(50 * time.Millisecond):
		}
	}
	none("with the bound full")
	first()
	first()
	w := <-went
	if w.n != 0 {
		t.Fatalf("the bind %d went through where the first to wait was due", w.n)
	}
	none("one turn given back twice")
	second()
	for want := 1; want < 4; want++ {
		next := <-went
		if next.n != want {
			t.Fatalf("the bind %d went through where bind %d was due", next.n, want)
		}
		w.done()
		w = next
	}
	// With nobody waiting, a turn given back is free for whoever comes.
	w.done()
	if done, waited, err := bound.take(ctx, "b"); err != nil || waited {
		t.Fatalf("a bind with a turn free: waited %v, %v", waited, err)
	} else {
		done()
	}
}

// Turns go round the callers that have binds waiting, each caller's oldest
// first: a caller with many waiting does not keep another's one from its
// turn.
func TestTurnsGoRoundTheCallers(t *testing.T) {
	bound := newTurns(1, 8)
	ctx := context.Background()
	held, _, err := bound.take(ctx, "many")
	if err != nil {
		t.Fatal(err)
	}
	went := make(chan through, 16)
	for i := range 5 {
		bound.send(t, ctx, "many", i, went)
		bound.waits(t, i+1)
	}
	bound.send(t, ctx, "one", 0, went)
	bound.waits(t, 6)
	bound.send(t, ctx, "two", 0, went)
	bound.waits(t, 7)
	bound.send(t, ctx, "two", 1, went)
	bound.waits(t, 8)
	var order []through
	held()
	for range 8 {
		select {
		case w := <-went:
			order = append(order, w)
			w.done()
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of 8 binds went through", len(order))
		}
	}
	want := []through{{"many", 0, nil}, {"one", 0, nil}, {"two", 0, nil}, {"many", 1, nil}, {"two", 1, nil}, {"many", 2, nil}, {"many", 3, nil}, {"many", 4, nil}}
	for i, w := range order {
		if w.caller != want[i].caller || w.n != want[i].n {
			t.Fatalf("turn %d went to %s's bind %d, and %s's bind %d was due", i, w.caller, w.n, want[i].caller, want[i].n)
		}
	}
}

// A caller that leaves before its bind's turn comes gets none and holds
// none, whichever of its binds it was, and a turn whose call is over is
// given back without anyone giving it back.
func TestTurnOfACallThatIsOverIsGivenBack(t *testing.T) {
	bound := newTurns(1, 8)
	call, end := context.WithCancel(context.Background())
	if _, _, err := bound.take(call, "a"); err != nil {
		t.Fatal(err)
	}
	went := make(chan through, 4)
	bound.send(t, context.Background(), "b", 0, went)
	bound.waits(t, 1)
	gone, leave := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer leave()
	if done, waited, err := bound.take(gone, "b"); !errors.Is(err, context.DeadlineExceeded) || done != nil || !waited {
		t.Fatalf("a caller that left before its turn: waited %v, %v", waited, err)
	}
	other, leaveToo := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer leaveToo()
	if _, _, err := bound.take(other, "c"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("another caller that left before its turn: %v", err)
	}
	bound.waits(t, 1)
	select {
	case <-went:
		t.Fatal("a bind went through with the bound full")
	case <-time.After(50 * time.Millisecond):
	}
	end()
	select {
	case w := <-went:
		w.done()
	case <-time.After(5 * time.Second):
		t.Fatal("the turn of a call that is over was not given back")
	}
	// And the turn is free again: nobody that left holds it.
	if done, waited, err := bound.take(context.Background(), "d"); err != nil || waited {
		t.Fatalf("a bind after all of that: waited %v, %v", waited, err)
	} else {
		done()
	}
}

// A caller may have so many binds in line and no more: the next is refused
// at once, having waited for nothing, while another caller's bind still
// takes its place in line, and the full line's caller may wait again once
// one of its binds has had its turn.
func TestCallersLineIsBounded(t *testing.T) {
	bound := newTurns(1, 2)
	ctx := context.Background()
	held, _, err := bound.take(ctx, "many")
	if err != nil {
		t.Fatal(err)
	}
	went := make(chan through, 8)
	for i := range 2 {
		bound.send(t, ctx, "many", i, went)
		bound.waits(t, i+1)
	}
	if done, waited, err := bound.take(ctx, "many"); !errors.Is(err, errLineFull) || done != nil || waited {
		t.Fatalf("a bind past its caller's line: waited %v, %v", waited, err)
	}
	bound.send(t, ctx, "other", 0, went)
	bound.waits(t, 3)
	held()
	first := <-went
	if first.caller != "many" || first.n != 0 {
		t.Fatalf("the first turn went to %s's bind %d", first.caller, first.n)
	}
	// One of the caller's binds has left the line: there is room for one.
	bound.send(t, ctx, "many", 2, went)
	bound.waits(t, 3)
	first.done()
	for range 3 {
		select {
		case w := <-went:
			w.done()
		case <-time.After(5 * time.Second):
			t.Fatal("the binds in line did not all go through")
		}
	}
	// No line is none to fill.
	if done, _, err := newTurns(0, 0).take(ctx, "many"); err != nil || done == nil {
		t.Fatalf("a bind with no bound: %v", err)
	}
}
