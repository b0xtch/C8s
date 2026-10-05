//go:build c8s_simtee

package sessiond

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// A host of a build made for it simulates a TEE for its guests on its
// configuration's word, and on no other: each launcher is then told the
// authority's directory, taken from the configuration's own.
func TestConfigNamesTheSimulatedAuthority(t *testing.T) {
	launch := bundle(t)
	plain, err := LoadConfig(writeConfig(t, strings.ReplaceAll(validConfig, "LAUNCH", launch)))
	if err != nil {
		t.Fatal(err)
	}
	if args := plain.VMM.launcherArgs(); args != nil {
		t.Fatalf("a host that was asked for no simulation tells its launchers %q", args)
	}
	body := strings.Replace(strings.ReplaceAll(validConfig, "LAUNCH", launch), `confine: "64055"`, `confine: "64055", simulatedTEE: authority`, 1)
	path := writeConfig(t, body)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(filepath.Dir(path), "authority")
	if cfg.VMM.SimulatedTEE != want || cfg.VMM.Confine != "64055" {
		t.Fatalf("the VMM: %+v", cfg.VMM)
	}
	if args := cfg.VMM.launcherArgs(); !reflect.DeepEqual(args, []string{"--simulated-tee", want}) {
		t.Fatalf("the host's launchers are told %q", args)
	}
}
