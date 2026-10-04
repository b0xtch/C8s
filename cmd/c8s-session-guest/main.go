//go:build linux

// Command c8s-session-guest is the one program of c8s that a session guest's
// image carries: the agent, the key service, and the command that states the
// schemas both keep to. The operator's c8s holds the same code and a great
// deal more, none of which a guest runs.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionkeyservice"
	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionschema"
	"github.com/confidential-dot-ai/c8s/internal/version"
)

func main() {
	root := &cobra.Command{
		Use:           "c8s-session-guest",
		Short:         "The agent and the key service of a confidential session's guest",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(sessionagent.NewCmd(), sessionkeyservice.NewCmd(), sessionschema.NewCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
