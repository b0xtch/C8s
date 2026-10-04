//go:build !linux

package sessionlauncher

import "os/exec"

// startAway starts cmd. Where a thread's CPUs cannot be chosen, it is kept
// off none.
func startAway(cmd *exec.Cmd, _ []int) ([]int, error) { return nil, cmd.Start() }

// writeBackCPUs lists none: only a Linux host launches a guest.
func writeBackCPUs() ([]int, error) { return nil, nil }
