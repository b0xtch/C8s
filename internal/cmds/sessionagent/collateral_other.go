//go:build !linux

package sessionagent

import "errors"

var errNoHostListener = errors.New("a hand-in from the host needs Linux and a vsock device")

// ListenHost listens for the guest's host on a vsock port.
func ListenHost(uint32) (hostListener, error) { return nil, errNoHostListener }
