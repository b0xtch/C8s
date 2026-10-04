//go:build linux

// Command c8s-session-init is process 1 of a session guest. It is the one
// program in the guest's initramfs: it opens the verity root the kernel
// command line names, makes the encrypted state volume, binds the launch key
// into the guest's evidence, and runs the agent the root carries. See
// internal/cmds/sessioninit.
package main

import (
	"os"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sessioninit"
)

func main() { os.Exit(sessioninit.Main()) }
