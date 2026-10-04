//go:build linux

package sessionagent

import (
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Only the host's context id is the host. A process in the guest reaches the
// same port over the loopback transport, and comes as the guest or as local.
func TestOnlyTheHostsContextIDIsTheHost(t *testing.T) {
	for name, tc := range map[string]struct {
		peer unix.Sockaddr
		host bool
	}{
		"the host":         {&unix.SockaddrVM{CID: unix.VMADDR_CID_HOST, Port: 1023}, true},
		"local":            {&unix.SockaddrVM{CID: unix.VMADDR_CID_LOCAL, Port: 1023}, false},
		"the hypervisor":   {&unix.SockaddrVM{CID: unix.VMADDR_CID_HYPERVISOR, Port: 1023}, false},
		"a guest":          {&unix.SockaddrVM{CID: 3, Port: 1023}, false},
		"another guest":    {&unix.SockaddrVM{CID: 70000, Port: 1023}, false},
		"any":              {&unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: 1023}, false},
		"no vsock address": {&unix.SockaddrInet4{Port: 2}, false},
		"a unix socket":    {&unix.SockaddrUnix{Name: "2"}, false},
		"no address":       {nil, false},
	} {
		if got := fromHost(tc.peer); got != tc.host {
			t.Errorf("%s: taken for the host: %v", name, got)
		}
	}
}

// A connection from inside the guest is not handed out, and the listener
// goes on listening. It needs the kernel's vsock loopback transport, which a
// guest image has built in.
func TestGuestsOwnProcessHandsNothingIn(t *testing.T) {
	const port = 18444
	ln, err := ListenHost(port)
	if err != nil {
		t.Skipf("no vsock here: %v", err)
	}
	defer ln.Close()
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Skipf("no vsock here: %v", err)
	}
	if err := unix.Connect(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_LOCAL, Port: port}); err != nil {
		_ = unix.Close(fd)
		t.Skipf("no vsock loopback transport here: %v", err)
	}
	local := os.NewFile(uintptr(fd), "local")
	defer local.Close()

	accepted := make(chan io.ReadWriteCloser, 1)
	go func() {
		if conn, err := ln.Accept(); err == nil {
			accepted <- conn
		}
	}()
	// The listener hangs up on it.
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 5})
	if n, err := local.Read(make([]byte, 1)); n != 0 || (err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, unix.ECONNRESET)) {
		t.Fatalf("a connection from inside the guest read %d bytes, %v", n, err)
	}
	select {
	case conn := <-accepted:
		_ = conn.Close()
		t.Fatal("a connection from inside the guest was taken for the host's")
	case <-time.After(200 * time.Millisecond):
	}
}
