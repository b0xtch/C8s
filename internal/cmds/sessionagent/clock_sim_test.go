//go:build c8s_simtee

package sessionagent_test

import (
	"context"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
)

// A guest with no TEE measures its TSC's rate against a timer its host
// emulates and may never settle it. A simulation build takes the counter
// under either of its names, and no clock that is another device.
func TestSimulatedGuestCountsOnItsTSCUnderEitherName(t *testing.T) {
	for _, source := range []string{"tsc", "tsc-early"} {
		p, _ := newTimedPool(t)
		p.cfg.ClockSource = func() string { return source }
		if _, err := sessionagent.Stage(context.Background(), p.cfg); err != nil {
			t.Errorf("a bind deadline on clocksource %q: %v", source, err)
		}
	}
	for _, source := range []string{"kvm-clock", "hpet", "acpi_pm", "jiffies", "tsc-early ", ""} {
		p, _ := newTimedPool(t)
		p.cfg.ClockSource = func() string { return source }
		if _, err := sessionagent.Stage(context.Background(), p.cfg); err == nil || !strings.Contains(err.Error(), "not tsc") {
			t.Errorf("staged a bind deadline on clocksource %q: %v", source, err)
		}
	}
}
