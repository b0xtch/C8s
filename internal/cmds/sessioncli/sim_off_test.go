//go:build !c8s_simtee

package sessioncli

import (
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// A command line that was not built for it knows no simulated TEE: no
// command and no option of its tree names one, and nothing could set one.
// Every command judges under the vendor's root.
func TestThisBuildsCommandsKnowNoSimulatedTEE(t *testing.T) {
	if n := reflect.TypeOf(simulatedTrust{}).NumField(); n != 0 {
		t.Fatalf("the simulated trust of a build that has none holds %d fields", n)
	}
	if cmds := simulationCmds(); cmds != nil {
		t.Fatalf("this build has %d commands for a simulation", len(cmds))
	}
	var s simulatedTrust
	set := pflag.NewFlagSet("command", pflag.ContinueOnError)
	s.flags(set)
	if set.HasFlags() || s.engine(session.EngineOptions{}) != nil {
		t.Fatal("the simulated trust of this build takes an option, or has an engine")
	}
	commands := 0
	var walk func(cmd *cobra.Command)
	walk = func(cmd *cobra.Command) {
		commands++
		for _, text := range []string{cmd.Name(), cmd.Short} {
			if strings.Contains(strings.ToLower(text), "simulat") || strings.Contains(text, "simtee") {
				t.Errorf("%s speaks of a simulation: %q", cmd.CommandPath(), text)
			}
		}
		cmd.Flags().VisitAll(func(f *pflag.Flag) {
			if strings.Contains(f.Name, "simulat") || strings.Contains(f.Usage, "simulated authority") {
				t.Errorf("%s --%s speaks of a simulation", cmd.CommandPath(), f.Name)
			}
		})
		for _, child := range cmd.Commands() {
			walk(child)
		}
	}
	walk(NewCmd())
	if commands < 15 {
		t.Fatalf("the walk found %d commands: too few", commands)
	}
}
