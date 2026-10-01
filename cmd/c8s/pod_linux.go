package main

import (
	"github.com/confidential-dot-ai/c8s/internal/cmds/podagent"
	"github.com/confidential-dot-ai/c8s/internal/cmds/podlauncher"
)

// Both run only on Linux: the agent inside the guest, the launcher on the
// host that boots it.
func init() {
	rootCmd.AddCommand(podagent.NewCmd(), podlauncher.NewCmd())
}
