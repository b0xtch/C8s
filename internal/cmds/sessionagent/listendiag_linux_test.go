//go:build linux

package sessionagent

import (
	"errors"
	"net"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

// The kernel names this process's listening sockets, by family, and names
// no connected one: a connection's own port is not a listener's.
func TestKernelAnswersWithListeningSocketsAlone(t *testing.T) {
	if _, err := tcpListeners(unix.AF_INET); errors.Is(err, unix.ENOENT) {
		t.Skip("this kernel answers no sock_diag for TCP")
	}
	four, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer four.Close()
	port4 := four.Addr().(*net.TCPAddr).Port
	// A connection to it, whose local port at the dialing end is no listener.
	conn, err := net.Dial("tcp4", four.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	accepted, err := four.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	dialed := conn.LocalAddr().(*net.TCPAddr).Port

	ports, err := tcpListeners(unix.AF_INET)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(ports, port4) {
		t.Fatalf("the kernel lists %v, without this process's listener on %d", ports, port4)
	}
	if slices.Contains(ports, dialed) {
		t.Fatalf("the kernel lists the connection's port %d as a listener", dialed)
	}
	if six, err := net.Listen("tcp6", "[::1]:0"); err == nil {
		defer six.Close()
		port6 := six.Addr().(*net.TCPAddr).Port
		ports, err := tcpListeners(unix.AF_INET6)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(ports, port6) {
			t.Fatalf("the kernel lists %v for IPv6, without this process's listener on %d", ports, port6)
		}
		if again, _ := tcpListeners(unix.AF_INET); slices.Contains(again, port6) && port6 != port4 {
			t.Fatalf("an IPv6 listener is listed for IPv4: %v", again)
		}
	}
	_ = four.Close()
	if ports, err = tcpListeners(unix.AF_INET); err != nil || slices.Contains(ports, port4) {
		t.Fatalf("a closed listener is still listed: %v, %v", ports, err)
	}
}
