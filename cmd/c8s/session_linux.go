package main

import (
	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionlauncher"
)

// Both run only on Linux: the agent inside the guest, the launcher on the
// host that boots it.
func init() {
	rootCmd.AddCommand(sessionagent.NewCmd(), sessionlauncher.NewCmd())
}
