//go:build linux

package sessionagent

import (
	"io"
	"strings"
	"testing"
)

// An agent with no container runtime and no --bare could take no document:
// it would refuse a tenant's for want of a runtime and every other for want
// of a sandbox image. It says so when it starts.
func TestRunRefusesAnImageThatCouldRunNothing(t *testing.T) {
	run := func(args ...string) error {
		cmd := NewCmd()
		cmd.SetArgs(append([]string{"run", "--platform", "tdx"}, args...))
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		return cmd.Execute()
	}
	const refusal = "can run a tenant's code nowhere"
	if err := run(); err == nil || !strings.Contains(err.Error(), refusal) {
		t.Fatalf("an agent with neither --crun nor --bare: %v", err)
	}
	// With either, it goes on, to fail here for want of a TEE or a launch key.
	for _, flag := range []string{"--bare", "--crun=/usr/bin/crun"} {
		if err := run(flag); err == nil || strings.Contains(err.Error(), refusal) {
			t.Fatalf("an agent with %s: %v", flag, err)
		}
	}
}
