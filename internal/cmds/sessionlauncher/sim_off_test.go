//go:build !c8s_simtee

package sessionlauncher

import (
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// A launcher that was not built for it simulates no TEE and has nothing that
// would: no option, and no state an option could set. A guest it launches
// runs in the TEE its platform names, and asks the vendor.
func TestThisBuildSimulatesNoTEE(t *testing.T) {
	if n := reflect.TypeOf(simulation{}).NumField(); n != 0 {
		t.Fatalf("the simulation of a build that has none holds %d fields", n)
	}
	cmd := newRunCmd()
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if strings.Contains(f.Name, "simulat") || strings.Contains(strings.ToLower(f.Usage), "simulat") {
			t.Errorf("--%s: a launcher of this build speaks of a simulation", f.Name)
		}
	})
	var s simulation
	set := pflag.NewFlagSet("launcher", pflag.ContinueOnError)
	s.flags(set)
	if set.HasFlags() {
		t.Fatal("the simulation of this build takes an option")
	}
	if s.on() || s.vendor("a.example:443") != "a.example:443" || s.stockDir("/stock") != "/stock" {
		t.Fatal("this build's launcher leads somewhere else than the vendor")
	}
	if reflect.ValueOf(s.fetcher()).Pointer() != reflect.ValueOf(session.FetchCollateral).Pointer() {
		t.Fatal("this build's launcher fetches the vendor's documents from somebody else")
	}
	if err := s.open(&Config{}); err != nil {
		t.Fatal(err)
	}
	if files, err := s.declare(&Config{}, nil, nil); err != nil || files != nil {
		t.Fatalf("this build's launcher declared %v (%v)", files, err)
	}
	// Every guest is asked for with the object that guards it.
	for _, platform := range []string{"tdx", "snp"} {
		cfg := baseConfig()
		cfg.Platform = platform
		args, err := cfg.QEMUArgs([]byte("key"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(args, " "), "-machine q35,confidential-guest-support=tee0,") {
			t.Errorf("%s: a guest is asked for with nothing that guards it: %q", platform, args)
		}
	}
}
