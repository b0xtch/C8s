//go:build linux

package sessionlauncher

import (
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// handInTimeout bounds each read and each write to a guest.
const handInTimeout = 10 * time.Second

// dialGuest connects to a vsock port of the guest with this context id.
func dialGuest(cid, port uint32) (io.ReadWriteCloser, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock socket: %w", err)
	}
	timeout := unix.NsecToTimeval(int64(handInTimeout))
	for _, opt := range []int{unix.SO_RCVTIMEO, unix.SO_SNDTIMEO} {
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, opt, &timeout); err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("vsock timeout: %w", err)
		}
	}
	if err := unix.Connect(fd, &unix.SockaddrVM{CID: cid, Port: port}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("vsock connect to guest %d port %d: %w", cid, port, err)
	}
	return os.NewFile(uintptr(fd), "guest-vsock"), nil
}
