//go:build !linux

package podlauncher

import (
	"errors"
	"os"

	"github.com/confidential-dot-ai/c8s/pkg/podcvm"
)

func setupTap(*Config) (*podcvm.HostNetwork, []*os.File, error) {
	return nil, nil, errors.New("tap networking needs Linux")
}
