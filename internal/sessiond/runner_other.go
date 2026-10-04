//go:build !linux

package sessiond

import (
	"errors"
	"log/slog"
)

// NewQEMURunner needs Linux: KVM, taps and the host's packet filter.
func NewQEMURunner(*Config, *slog.Logger) (Runner, error) {
	return nil, errors.New("the session daemon boots TDs on Linux only")
}
