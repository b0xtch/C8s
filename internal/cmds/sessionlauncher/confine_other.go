//go:build !linux

package sessionlauncher

import (
	"errors"
	"syscall"
)

// directIO is nothing where the launcher only runs its tests.
const directIO = 0

func (c *Confinement) sysProcAttr(string) (*syscall.SysProcAttr, error) {
	return nil, errors.New("confining the VMM needs Linux")
}
