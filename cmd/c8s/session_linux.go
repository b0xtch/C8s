package main

import (
	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
	"github.com/confidential-dot-ai/c8s/internal/cmds/sessiondaemon"
	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionkeyservice"
	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionlauncher"
)

// These run only on Linux: the agent inside a session guest and the key
// service inside its own, and on the host the launcher that boots a guest
// and the daemon that keeps the pools.
func init() {
	rootCmd.AddCommand(sessionagent.NewCmd(), sessionkeyservice.NewCmd(), sessionlauncher.NewCmd(), sessiondaemon.NewCmd())
}
