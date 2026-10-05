//go:build linux && c8s_simtee

package sessiond

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// A host that simulates a TEE starts each guest's launcher with the
// authority's directory, among what it tells every launcher.
func TestRunnerTellsItsLaunchersOfTheSimulation(t *testing.T) {
	self, argsFile := fakeLauncher(t)
	runner, spec := userRunner(t, self)
	runner.cfg.VMM.SimulatedTEE = "/authority"
	inst, err := runner.Start(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inst.Stop)
	var args string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if data, err := os.ReadFile(argsFile); err == nil && len(data) > 0 {
			args = strings.TrimSpace(string(data))
			break
		}
	}
	if !strings.Contains(args, " --image-store /store/images.store --simulated-tee /authority --network user ") {
		t.Fatalf("the launcher was started with\n %s", args)
	}
}
