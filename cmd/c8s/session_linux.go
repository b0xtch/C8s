package main

import (
	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
	"github.com/confidential-dot-ai/c8s/internal/cmds/sessiondaemon"
	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionlauncher"
)

// These run only on Linux: the agent inside the guest, and on the host the
// launcher that boots it and the daemon that keeps the pools.
func init() {
	rootCmd.AddCommand(sessionagent.NewCmd(), sessionlauncher.NewCmd(), sessiondaemon.NewCmd())
}
