package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/sessioncli"

func init() {
	rootCmd.AddCommand(sessioncli.NewCmd())
}
