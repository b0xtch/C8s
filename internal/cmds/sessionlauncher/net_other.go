//go:build !linux

package sessionlauncher

import (
	"errors"
	"io"
	"os"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

var errNeedsLinux = errors.New("guest networking and vsock need Linux")

func setupTap(*Config) (*session.HostNetwork, string, *os.File, *os.File, error) {
	return nil, "", nil, nil, errNeedsLinux
}

func reserveVsock() (*os.File, uint32, error) { return nil, 0, errNeedsLinux }

func dialGuest(uint32, uint32) (io.ReadWriteCloser, error) { return nil, errNeedsLinux }
