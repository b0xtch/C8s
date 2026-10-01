package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/pod"

func init() {
	rootCmd.AddCommand(pod.NewCmd())
}
