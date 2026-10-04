//go:build linux

package sessionagent

import (
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// handInTimeout bounds each read and each write of one hand-in.
const handInTimeout = 10 * time.Second

// vsockListener is a listening vsock socket that hands out connections from
// the host alone.
type vsockListener struct{ fd int }

// ListenHost listens for the guest's host on a vsock port.
func ListenHost(port uint32) (hostListener, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("bind vsock port %d: %w", port, err)
	}
	if err := unix.Listen(fd, 4); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("listen on vsock port %d: %w", port, err)
	}
	return &vsockListener{fd: fd}, nil
}

func (l *vsockListener) Accept() (io.ReadWriteCloser, error) {
	for {
		fd, peer, err := unix.Accept4(l.fd, unix.SOCK_CLOEXEC)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !fromHost(peer) {
			_ = unix.Close(fd)
			continue
		}
		timeout := unix.NsecToTimeval(int64(handInTimeout))
		for _, opt := range []int{unix.SO_RCVTIMEO, unix.SO_SNDTIMEO} {
			if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, opt, &timeout); err != nil {
				_ = unix.Close(fd)
				return nil, fmt.Errorf("vsock timeout: %w", err)
			}
		}
		return os.NewFile(uintptr(fd), "host-vsock"), nil
	}
}

func (l *vsockListener) Close() error { return unix.Close(l.fd) }

// fromHost reports whether a vsock connection came from the guest's host. The
// guest's own processes reach the port too, over the kernel's loopback
// transport, under the guest's context id or the local one. The kernel fills
// in the peer's id, and the host's is its alone.
func fromHost(peer unix.Sockaddr) bool {
	vm, ok := peer.(*unix.SockaddrVM)
	return ok && vm.CID == unix.VMADDR_CID_HOST
}
