//go:build !linux

package sessionagent

import "os/exec"

// startWide starts cmd: only a Linux agent keeps itself to fewer processors
// than its guest has.
func startWide(cmd *exec.Cmd) error { return cmd.Start() }
