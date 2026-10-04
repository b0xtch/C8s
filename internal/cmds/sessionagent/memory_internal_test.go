package sessionagent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// tdMeminfo is what a 2 GiB TD with 512 MiB below 4 GiB reported when idle.
const tdMeminfo = `MemTotal:        1892236 kB
MemFree:         1658540 kB
MemAvailable:    1780092 kB
Buffers:            4404 kB
Cached:           137384 kB
Unaccepted:      1286144 kB
DirectMap4k:       78268 kB
`

func TestParseMeminfo(t *testing.T) {
	free, unaccepted, err := parseMeminfo([]byte(tdMeminfo))
	if err != nil || free != 1658540 || unaccepted != 1286144 {
		t.Fatalf("free %d, unaccepted %d, %v", free, unaccepted, err)
	}
	// A kernel with nothing left to accept, or that never had any, says so by
	// leaving the line out.
	free, unaccepted, err = parseMeminfo([]byte("MemFree:  2048 kB\nCached: 1 kB\n"))
	if err != nil || free != 2048 || unaccepted != 0 {
		t.Fatalf("free %d, unaccepted %d, %v", free, unaccepted, err)
	}
	for name, text := range map[string]string{
		"no MemFree":                 "Cached: 1 kB\nUnaccepted: 0 kB\n",
		"more unaccepted than free":  "MemFree: 10 kB\nUnaccepted: 11 kB\n",
		"another unit":               "MemFree: 10 MB\n",
		"no unit":                    "MemFree: 10\n",
		"not a number":               "MemFree: ten kB\n",
		"negative":                   "MemFree: -1 kB\n",
		"unaccepted not a number":    "MemFree: 10 kB\nUnaccepted: x kB\n",
		"negative unaccepted":        "MemFree: 10 kB\nUnaccepted: -4 kB\n",
		"unaccepted in another unit": "MemFree: 10 kB\nUnaccepted: 4 MB\n",
		"empty":                      "",
	} {
		if _, _, err := parseMeminfo([]byte(text)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// fakeGuest is a guest's memory as the knob and meminfo show it. The kernel
// accepts whole 4 MiB blocks and no more than it has.
type fakeGuest struct {
	mu               sync.Mutex
	aheadMB, unaccMB int
	writes           []int
	// refuse fails every write; deaf takes it and accepts nothing.
	refuse  error
	deaf    bool
	readErr error
	// unreadableAfter that many writes, meminfo cannot be read.
	unreadableAfter int
	pauses          []time.Duration
	// stopAfter that many pauses, the next one reports the context ended.
	stopAfter int
	ended     bool
	idleErr   error
	idled     int
	// cancel is called once cancelAfter writes are in.
	cancelAfter int
	cancel      context.CancelFunc
}

func (g *fakeGuest) read() ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.readErr != nil || (g.unreadableAfter > 0 && len(g.writes) >= g.unreadableAfter) {
		return nil, errors.Join(g.readErr, errors.New("meminfo is gone"))
	}
	return []byte(fmt.Sprintf("MemTotal: 1 kB\nMemFree: %d kB\nUnaccepted: %d kB\n", (g.aheadMB+g.unaccMB)<<10, g.unaccMB<<10)), nil
}

func (g *fakeGuest) accept(megabytes int) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.writes = append(g.writes, megabytes)
	if g.cancel != nil && len(g.writes) == g.cancelAfter {
		g.cancel()
	}
	if g.refuse != nil {
		return g.refuse
	}
	if g.deaf {
		return nil
	}
	taken := min((megabytes+3)/4*4, g.unaccMB)
	g.unaccMB -= taken
	g.aheadMB += taken
	return nil
}

func (g *fakeGuest) memory(reserveMB int, rest bool) *Memory {
	return &Memory{
		ReserveMB: reserveMB, Rest: rest, Logger: slog.New(slog.DiscardHandler),
		read: g.read, accept: g.accept,
		after: func(ctx context.Context, d time.Duration) bool {
			g.mu.Lock()
			defer g.mu.Unlock()
			g.pauses = append(g.pauses, d)
			if g.stopAfter > 0 && len(g.pauses) > g.stopAfter {
				g.ended = true
				return false
			}
			return ctx.Err() == nil
		},
		idle: func() error {
			g.mu.Lock()
			defer g.mu.Unlock()
			g.idled++
			return g.idleErr
		},
	}
}

func TestReserveAcceptsWhatIsMissing(t *testing.T) {
	for _, c := range []struct {
		name                    string
		ahead, unaccepted, want int
		writes                  []int
	}{
		{"an idle guest", 13, 1256, 128, []int{115}},
		{"a guest that holds its reserve", 128, 1256, 128, nil},
		{"a guest that holds more", 363, 1256, 128, nil},
		{"less left than the reserve wants", 0, 50, 128, []int{50}},
		{"nothing left to accept", 20, 0, 128, nil},
		{"no reserve asked for", 0, 1256, 0, nil},
	} {
		g := &fakeGuest{aheadMB: c.ahead, unaccMB: c.unaccepted}
		g.memory(c.want, false).Reserve()
		if !slices.Equal(g.writes, c.writes) {
			t.Errorf("%s: wrote %v, want %v", c.name, g.writes, c.writes)
		}
	}
	// A guest whose meminfo cannot be read, or whose kernel refuses, goes on.
	g := &fakeGuest{unaccMB: 100, readErr: errors.New("no")}
	g.memory(64, false).Reserve()
	if len(g.writes) != 0 {
		t.Fatalf("wrote %v without knowing the guest's memory", g.writes)
	}
	g = &fakeGuest{unaccMB: 100, refuse: errors.New("no")}
	g.memory(64, false).Reserve()
	if !slices.Equal(g.writes, []int{64}) {
		t.Fatalf("wrote %v", g.writes)
	}
	// And the reserve does not go on to the rest.
	g = &fakeGuest{unaccMB: 500}
	g.memory(64, true).Reserve()
	if !slices.Equal(g.writes, []int{64}) {
		t.Fatalf("the reserve wrote %v", g.writes)
	}
}

func TestAcceptRestTakesStepsUntilNothingIsLeft(t *testing.T) {
	g := &fakeGuest{aheadMB: 10, unaccMB: 100}
	g.memory(0, true).AcceptRest(context.Background())
	if !slices.Equal(g.writes, []int{32, 32, 32, 4}) || g.unaccMB != 0 {
		t.Fatalf("wrote %v, %d MB left", g.writes, g.unaccMB)
	}
	// It waits before it begins, and then takes one step after another: a
	// sandbox that grows meanwhile pays for what it touches.
	if !slices.Equal(g.pauses, []time.Duration{acceptRestAfter}) {
		t.Fatalf("pauses: %v", g.pauses)
	}
	if g.idled != 1 {
		t.Fatalf("asked for idle priority %d times", g.idled)
	}
	// Idle priority refused: it still accepts, in its steps, and rests after
	// each, since its CPU is now one the sandbox may want.
	g = &fakeGuest{unaccMB: 40, idleErr: errors.New("not permitted")}
	g.memory(0, true).AcceptRest(context.Background())
	if !slices.Equal(g.writes, []int{32, 8}) || len(g.pauses) != 3 || g.pauses[0] != acceptRestAfter {
		t.Fatalf("wrote %v, paused %v", g.writes, g.pauses)
	}
}

func TestAcceptRestIsOffUnlessAskedFor(t *testing.T) {
	g := &fakeGuest{unaccMB: 100}
	g.memory(64, false).AcceptRest(context.Background())
	if len(g.writes) != 0 || len(g.pauses) != 0 {
		t.Fatalf("wrote %v, paused %v", g.writes, g.pauses)
	}
	var none *Memory
	none.AcceptRest(context.Background())
	none.Reserve()
}

func TestAcceptRestEndsWhenItIsToldTo(t *testing.T) {
	// Before it began.
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	g := &fakeGuest{unaccMB: 100}
	g.memory(0, true).AcceptRest(ended)
	if len(g.writes) != 0 || g.idled != 0 {
		t.Fatalf("wrote %v, idled %d", g.writes, g.idled)
	}
	// Between two steps.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g = &fakeGuest{unaccMB: 100, cancelAfter: 2, cancel: cancel}
	g.memory(0, true).AcceptRest(ctx)
	if !slices.Equal(g.writes, []int{32, 32}) {
		t.Fatalf("wrote %v", g.writes)
	}
	// And in a rest, on a thread that takes them.
	g = &fakeGuest{unaccMB: 100, stopAfter: 2, idleErr: errors.New("not permitted")}
	g.memory(0, true).AcceptRest(context.Background())
	if !slices.Equal(g.writes, []int{32, 32}) || !g.ended {
		t.Fatalf("wrote %v", g.writes)
	}
}

func TestAcceptRestStopsWhereItCannotGoOn(t *testing.T) {
	// The kernel refuses: that is the end, with no rest and no second look.
	g := &fakeGuest{unaccMB: 100, refuse: errors.New("no")}
	g.memory(0, true).AcceptRest(context.Background())
	if !slices.Equal(g.writes, []int{32}) || len(g.pauses) != 1 {
		t.Fatalf("wrote %v, paused %v", g.writes, g.pauses)
	}
	// The kernel takes the write and accepts nothing: asked once, not for ever.
	g = &fakeGuest{unaccMB: 100, deaf: true}
	g.memory(0, true).AcceptRest(context.Background())
	if !slices.Equal(g.writes, []int{32}) {
		t.Fatalf("wrote %v", g.writes)
	}
	// Meminfo cannot be read any more.
	g = &fakeGuest{unaccMB: 100, unreadableAfter: 2}
	g.memory(0, true).AcceptRest(context.Background())
	if !slices.Equal(g.writes, []int{32, 32}) {
		t.Fatalf("wrote %v", g.writes)
	}
}

func TestNewMemoryIsNilWithoutSomethingToDo(t *testing.T) {
	var logged strings.Builder
	logger := slog.New(slog.NewTextHandler(&logged, nil))
	// Nothing asked: nothing made, and the kernel is not even looked at.
	if NewMemory(0, false, logger) != nil || logged.Len() != 0 {
		t.Fatalf("a memory acceptor with nothing asked of it, or a word about it: %q", logged.String())
	}
	// No test machine has the knob. A guest without it accepts as it always did.
	if m := NewMemory(128, true, logger); m != nil {
		t.Skip("this machine has vm.accept_memory_mb")
	}
	if !strings.Contains(logged.String(), acceptKnob) {
		t.Fatalf("nothing said about the missing knob: %q", logged.String())
	}
}
