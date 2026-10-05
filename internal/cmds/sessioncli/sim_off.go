//go:build !c8s_simtee

package sessioncli

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// simulatedTrust judges evidence under a simulated authority in place of the
// vendor. This build has none and no option for one: every command judges
// under the vendor's root.
type simulatedTrust struct{}

func (*simulatedTrust) flags(*pflag.FlagSet) {}

// engine is the engine of a command that was asked to judge under a
// simulated authority, or nil for one that was not.
func (*simulatedTrust) engine(session.EngineOptions) session.Engine { return nil }

// simulationCmds are the commands that make and serve a simulated authority.
func simulationCmds() []*cobra.Command { return nil }
