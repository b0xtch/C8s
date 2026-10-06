//go:build !linux

package sessionlauncher

import "os/exec"

// startOn starts cmd. Where a thread's CPUs cannot be chosen, it is kept to
// none and off none.
func startOn(cmd *exec.Cmd, _, _ []int) ([]int, error) { return nil, cmd.Start() }

// writeBackCPUs lists none: only a Linux host launches a guest.
func writeBackCPUs() ([]int, error) { return nil, nil }
