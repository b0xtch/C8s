//go:build !c8s_simtee

package sessiond

import (
	"reflect"
	"strings"
	"testing"
)

// A host that was not built for it has no word for a simulation: its
// configuration refuses one, and nothing its launchers are told names one.
func TestThisBuildsHostSimulatesNoTEE(t *testing.T) {
	if n := reflect.TypeOf(Simulation{}).NumField(); n != 0 {
		t.Fatalf("the simulation of a build that has none holds %d fields", n)
	}
	launch := bundle(t)
	body := strings.Replace(strings.ReplaceAll(validConfig, "LAUNCH", launch), `confine: "64055"`, `confine: "64055", simulatedTEE: authority`, 1)
	if _, err := LoadConfig(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "simulatedTEE") {
		t.Fatalf("a configuration that asks for a simulated TEE: %v", err)
	}
	cfg, err := LoadConfig(writeConfig(t, strings.ReplaceAll(validConfig, "LAUNCH", launch)))
	if err != nil {
		t.Fatal(err)
	}
	if args := cfg.VMM.launcherArgs(); args != nil {
		t.Fatalf("this build's launchers are told %q", args)
	}
	if paths := cfg.VMM.paths(); paths != nil {
		t.Fatalf("this build's simulation has %d paths", len(paths))
	}
}
