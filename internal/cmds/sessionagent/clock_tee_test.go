//go:build !c8s_simtee

package sessionagent_test

import (
	"context"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
)

// A confidential guest is told its TSC's rate and settles on it at once. One
// that still measures it has no clock of its own yet, and stages no document
// that sets a deadline.
func TestBindDeadlineTakesNoClockThatIsStillMeasured(t *testing.T) {
	p, _ := newTimedPool(t)
	p.cfg.ClockSource = func() string { return "tsc-early" }
	if _, err := sessionagent.Stage(context.Background(), p.cfg); err == nil || !strings.Contains(err.Error(), "not tsc") {
		t.Fatalf("staged a bind deadline on the TSC before its rate is settled: %v", err)
	}
}
