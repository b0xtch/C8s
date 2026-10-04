package sessionagent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// A confidential guest accepts its memory before it uses it, and its host
// backs what it accepted for as long as the guest lives. A kernel that accepts
// none ahead of use keeps a waiting guest small, and then every megabyte a
// sandbox first touches costs it time. Memory pays that ahead of the sandbox,
// through the kernel's vm.accept_memory_mb, where the guest's kernel has it.
type Memory struct {
	// ReserveMB is the accepted free memory a guest holds while it waits for
	// a sandbox. A tenant's start should touch less than this.
	ReserveMB int
	// Rest has the agent accept everything else once a sandbox runs, in the
	// background. Without it a sandbox accepts what it grows into.
	Rest   bool
	Logger *slog.Logger

	// read returns /proc/meminfo and accept writes megabytes to the knob.
	read   func() ([]byte, error)
	accept func(megabytes int) error
	// after waits: before the rest is begun, so that it stays out of the way
	// of a sandbox's start, and between steps on a thread that could not be
	// put at idle priority, which is what idle does.
	after func(context.Context, time.Duration) bool
	idle  func() error
}

const (
	acceptKnob = "/proc/sys/vm/accept_memory_mb"
	meminfo    = "/proc/meminfo"
	// acceptStepMB is one write to the knob: a short run of accepts, after
	// which the thread can be told to stop.
	acceptStepMB = 32
	// acceptRestAfter is how long a sandbox has run before the rest is
	// begun. Accepting a block keeps interrupts off on its CPU, and whatever
	// the guest does meanwhile is slower for it. A session's first second,
	// its sandbox's start and its first commands, is left alone.
	acceptRestAfter = time.Second
)

// NewMemory is the acceptor of a guest whose kernel has the knob. A guest
// without it (another kernel, or a platform that accepts nothing) gets nil,
// which does nothing.
func NewMemory(reserveMB int, rest bool, logger *slog.Logger) *Memory {
	if reserveMB <= 0 && !rest {
		return nil
	}
	if _, err := os.Stat(acceptKnob); err != nil {
		logger.Info("this kernel accepts no memory on request", "knob", acceptKnob, "error", err)
		return nil
	}
	return &Memory{
		ReserveMB: reserveMB, Rest: rest, Logger: logger,
		read: func() ([]byte, error) { return os.ReadFile(meminfo) },
		accept: func(megabytes int) error {
			f, err := os.OpenFile(acceptKnob, os.O_WRONLY, 0)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = f.WriteString(strconv.Itoa(megabytes))
			return err
		},
		after: wait,
		idle:  idleThread,
	}
}

func wait(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// state reads how much accepted memory is free and how much is still
// unaccepted, in megabytes. The kernel counts unaccepted memory as free.
func (m *Memory) state() (aheadMB, unacceptedMB int, err error) {
	data, err := m.read()
	if err != nil {
		return 0, 0, err
	}
	free, unaccepted, err := parseMeminfo(data)
	if err != nil {
		return 0, 0, err
	}
	return int((free - unaccepted) >> 10), int(unaccepted >> 10), nil
}

// parseMeminfo returns MemFree and Unaccepted in kilobytes. A kernel that
// never has unaccepted memory prints no such line, which reads as none.
func parseMeminfo(data []byte) (free, unaccepted int64, err error) {
	found := false
	lines := bufio.NewScanner(bytes.NewReader(data))
	for lines.Scan() {
		name, rest, ok := strings.Cut(lines.Text(), ":")
		if !ok || (name != "MemFree" && name != "Unaccepted") {
			continue
		}
		value, unit, _ := strings.Cut(strings.TrimSpace(rest), " ")
		kb, err := strconv.ParseInt(value, 10, 64)
		if err != nil || unit != "kB" || kb < 0 {
			return 0, 0, fmt.Errorf("meminfo: %q", lines.Text())
		}
		if name == "MemFree" {
			free, found = kb, true
		} else {
			unaccepted = kb
		}
	}
	if !found {
		return 0, 0, errors.New("meminfo: no MemFree")
	}
	if unaccepted > free {
		return 0, 0, fmt.Errorf("meminfo: %d kB unaccepted of %d kB free", unaccepted, free)
	}
	return free, unaccepted, nil
}

// Reserve accepts memory until ReserveMB of it is accepted and free, or none
// is left to accept. It returns when that is done. A failure is logged: the
// guest then accepts as it goes.
func (m *Memory) Reserve() {
	if m == nil {
		return
	}
	ahead, unaccepted, err := m.state()
	if err != nil {
		m.Logger.Warn("memory reserve", "error", err)
		return
	}
	want := min(m.ReserveMB-ahead, unaccepted)
	if want <= 0 {
		return
	}
	began := time.Now()
	if err := m.accept(want); err != nil {
		m.Logger.Warn("memory reserve", "error", err)
		return
	}
	m.Logger.Info("memory accepted ahead of a sandbox", "megabytes", want, "ahead_before", ahead, "took", time.Since(began).String())
}

// AcceptRest accepts what is left, a step at a time and one step after
// another, on a thread at idle priority: one CPU at most, and none that
// anything else in the guest wants. A sandbox that grows before this is done
// accepts what it touches itself, at the same price, so the sooner this is
// done the less a sandbox pays. It returns when nothing is left, when ctx
// ends, or when the kernel refuses.
func (m *Memory) AcceptRest(ctx context.Context) {
	if m == nil || !m.Rest {
		return
	}
	if !m.after(ctx, acceptRestAfter) {
		return
	}
	// A thread at normal priority would take its CPU from the sandbox. It
	// rests after each step for as long as the step took: half a CPU.
	paced := false
	if err := m.idle(); err != nil {
		m.Logger.Warn("memory acceptance runs at normal priority, half of the time", "error", err)
		paced = true
	}
	began, total, last := time.Now(), 0, -1
	for {
		if ctx.Err() != nil {
			return
		}
		_, unaccepted, err := m.state()
		// A step that left as much unaccepted as it found would be repeated
		// for ever.
		if err == nil && last >= 0 && unaccepted >= last {
			err = fmt.Errorf("%d MB unaccepted after a step, %d MB before it", unaccepted, last)
		}
		if err != nil {
			m.Logger.Warn("memory acceptance stopped", "error", err, "megabytes", total)
			return
		}
		if unaccepted == 0 {
			if total > 0 {
				m.Logger.Info("all memory accepted", "megabytes", total, "took", time.Since(began).String())
			}
			return
		}
		step := min(acceptStepMB, unaccepted)
		start := time.Now()
		if err := m.accept(step); err != nil {
			m.Logger.Warn("memory acceptance stopped", "error", err, "megabytes", total)
			return
		}
		total, last = total+step, unaccepted
		if paced && !m.after(ctx, time.Since(start)) {
			return
		}
	}
}
