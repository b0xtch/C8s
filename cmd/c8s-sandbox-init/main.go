//go:build linux

// Command c8s-sandbox-init is the first process of a session's sandbox until
// its session is bound, and then becomes the image's process. See
// internal/cmds/sandboxinit.
package main

import (
	"os"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sandboxinit"
)

func main() { os.Exit(sandboxinit.Main()) }
