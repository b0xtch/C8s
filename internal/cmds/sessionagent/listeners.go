package sessionagent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// guestPorts are the ports the guest's own services may listen on, or take
// datagrams on. The image's packet filter closes exactly these to the sandbox
// on every local address, so the two must agree, and a test holds them
// together.
var guestPorts = [][2]int{{1, 1023}, {8400, 8499}}

func isGuestPort(port int) bool { return portIn(guestPorts, port) }

func portIn(ranges [][2]int, port int) bool {
	for _, r := range ranges {
		if port >= r[0] && port <= r[1] {
			return true
		}
	}
	return false
}

// ListenerGuard checks that the guest's own listeners are where the packet
// filter assumes them. A command with no sandbox image runs in the guest's
// network namespace, and the filter keeps it off the guest's ports. That
// covers every guest service only as long as none listens anywhere else, and
// nothing can cover a socket on an abstract unix name, which no filter sees.
// Both are checked before any tenant code runs, when every listener is still
// the guest's own.
type ListenerGuard struct {
	// Proc is where the proc filesystem is mounted.
	Proc string
}

// Check fails if a TCP socket listens outside the guest's ports, a UDP socket
// takes datagrams from anyone outside them, or any socket accepts connections
// on an abstract unix name.
func (g ListenerGuard) Check(context.Context) error {
	for _, table := range []struct {
		name, protocol string
		open           func(path string) ([]int, error)
		ports          [][2]int
	}{
		{"net/tcp", "TCP", listeningPorts, guestPorts},
		{"net/tcp6", "TCP", listeningPorts, guestPorts},
		{"net/udp", "UDP", unconnectedPorts, guestPorts},
		{"net/udp6", "UDP", unconnectedPorts, guestPorts},
	} {
		ports, err := table.open(filepath.Join(g.Proc, table.name))
		// A kernel without IPv6 has no tcp6 or udp6 table.
		if errors.Is(err, fs.ErrNotExist) && strings.HasSuffix(table.name, "6") {
			continue
		}
		if err != nil {
			return fmt.Errorf("list the guest's listeners: %w", err)
		}
		for _, port := range ports {
			if !portIn(table.ports, port) {
				return fmt.Errorf("something in the guest listens on %s port %d, which the packet filter leaves open to the sandbox", table.protocol, port)
			}
		}
	}
	names, err := abstractListeners(filepath.Join(g.Proc, "net/unix"))
	if err != nil {
		return fmt.Errorf("list the guest's unix sockets: %w", err)
	}
	if len(names) > 0 {
		return fmt.Errorf("something in the guest accepts connections on abstract unix sockets, which no filter keeps from the sandbox: %s", strings.Join(names, ", "))
	}
	return nil
}

// tcpListen is the state column of a listening socket in /proc/net/tcp.
const tcpListen = "0A"

// listeningPorts reads the local ports of the listening sockets in one of the
// kernel's TCP socket tables.
func listeningPorts(path string) ([]int, error) {
	return localPorts(path, func(fields []string) (bool, error) { return fields[3] == tcpListen, nil })
}

// unconnectedPorts reads the local ports of the sockets in one of the
// kernel's UDP socket tables that take a datagram from any sender. A
// connected socket takes them from its peer alone, and no process without a
// raw socket can send as that peer.
func unconnectedPorts(path string) ([]int, error) {
	return localPorts(path, func(fields []string) (bool, error) {
		address, port, ok := strings.Cut(fields[2], ":")
		if !ok {
			return false, fmt.Errorf("unexpected remote address %q", fields[2])
		}
		return strings.Trim(address, "0") == "" && strings.Trim(port, "0") == "", nil
	})
}

// localPorts reads the local port of each socket that counts in one of the
// kernel's TCP or UDP socket tables.
func localPorts(path string, counts func(fields []string) (bool, error)) ([]int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var ports []int
	lines := bufio.NewScanner(f)
	lines.Scan() // the column names
	for lines.Scan() {
		// sl local_address rem_address st ...
		fields := strings.Fields(lines.Text())
		if len(fields) < 4 {
			return nil, fmt.Errorf("%s: unexpected line %q", path, lines.Text())
		}
		ok, err := counts(fields)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if !ok {
			continue
		}
		_, hexPort, ok := strings.Cut(fields[1], ":")
		port, err := strconv.ParseUint(hexPort, 16, 16)
		if !ok || err != nil {
			return nil, fmt.Errorf("%s: unexpected local address %q", path, fields[1])
		}
		ports = append(ports, int(port))
	}
	return ports, lines.Err()
}

// unixAcceptsConnections is __SO_ACCEPTCON in the flags column of
// /proc/net/unix: the socket has been put in the listening state.
const unixAcceptsConnections = 1 << 16

// abstractListeners returns the abstract names that listening unix sockets
// are bound to. The kernel prints the leading NUL of such a name as "@".
func abstractListeners(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var names []string
	lines := bufio.NewScanner(f)
	lines.Scan() // the column names
	for lines.Scan() {
		// Num RefCount Protocol Flags Type St Inode [Path]
		fields := strings.Fields(lines.Text())
		if len(fields) < 7 {
			return nil, fmt.Errorf("%s: unexpected line %q", path, lines.Text())
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil {
			return nil, fmt.Errorf("%s: unexpected flags %q", path, fields[3])
		}
		if len(fields) > 7 && flags&unixAcceptsConnections != 0 && strings.HasPrefix(fields[7], "@") {
			names = append(names, fields[7])
		}
	}
	return names, lines.Err()
}
