//go:build !linux

package coresched

import "os/exec"

// start starts cmd. Only a Linux host runs guests.
func start(cmd *exec.Cmd, place func() error) (bool, error) {
	if place != nil {
		if err := place(); err != nil {
			return false, err
		}
	}
	return false, cmd.Start()
}
