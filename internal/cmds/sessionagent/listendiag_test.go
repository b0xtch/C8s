package sessionagent

import (
	"context"
	"encoding/binary"
	"errors"
	"io/fs"
	"strings"
	"testing"
)

// The question the agent puts to the kernel is for listening TCP sockets of
// one family and for nothing else: any other state bit would have the kernel
// walk its table of connected sockets too.
func TestListenersRequestAsksForListeningSocketsAlone(t *testing.T) {
	for _, family := range []uint8{familyIPv4, familyIPv6} {
		req := listenersRequest{family: family}
		got := req.Serialize()
		if len(got) != req.Len() || len(got) != 56 {
			t.Fatalf("a request of %d bytes, said to be %d", len(got), req.Len())
		}
		if got[0] != family || got[1] != 6 || got[2] != 0 || got[3] != 0 {
			t.Errorf("family %d: the request begins %v", family, got[:4])
		}
		if states := binary.NativeEndian.Uint32(got[4:8]); states != 1<<10 {
			t.Errorf("family %d: the request asks for states %#x, want listening alone", family, states)
		}
		// No address, port, interface or cookie: every such socket.
		for i, b := range got[8:] {
			if b != 0 {
				t.Fatalf("family %d: byte %d of the socket id is %d", family, i, b)
			}
		}
	}
}

func diagMessage(family, state uint8, port uint16) []byte {
	msg := make([]byte, 72)
	msg[0], msg[1] = family, state
	binary.BigEndian.PutUint16(msg[4:6], port)
	return msg
}

// An answer is a listening socket of the family asked for, and its port is
// read where the kernel puts it. Anything else is no answer to the question.
func TestListenerPort(t *testing.T) {
	if port, err := listenerPort(diagMessage(familyIPv4, 10, 8443), familyIPv4); err != nil || port != 8443 {
		t.Fatalf("a listening socket on 8443 read as %d, %v", port, err)
	}
	if port, err := listenerPort(append(diagMessage(familyIPv6, 10, 65535), 1, 2, 3), familyIPv6); err != nil || port != 65535 {
		t.Fatalf("an answer with attributes after it read as %d, %v", port, err)
	}
	for name, msg := range map[string][]byte{
		"a connected socket":    diagMessage(familyIPv4, 1, 8443),
		"another family's":      diagMessage(familyIPv6, 10, 8443),
		"a short answer":        diagMessage(familyIPv4, 10, 8443)[:71],
		"no answer at all":      nil,
		"a socket being closed": diagMessage(familyIPv4, 7, 8443),
	} {
		if port, err := listenerPort(msg, familyIPv4); err == nil {
			t.Errorf("%s read as a listener on %d", name, port)
		}
	}
}

// With the kernel asked for its listening sockets, the guard holds them to
// the guest's ports as it holds the tables', and reads no TCP table.
func TestListenerGuardAsksForTCPListeners(t *testing.T) {
	asked := map[int]int{}
	listening := map[int][]int{familyIPv4: {22, 8443}, familyIPv6: {8443}}
	var failing error
	// A proc with no TCP table at all: only the kernel's answer is read.
	guard := fakeProc(t, "", "", procUnix)
	guard.TCP = func(family int) ([]int, error) {
		asked[family]++
		if failing != nil && family == familyIPv6 {
			return nil, failing
		}
		return listening[family], nil
	}
	if err := guard.Check(context.Background()); err != nil {
		t.Fatalf("the guest's own listeners: %v", err)
	}
	if asked[familyIPv4] != 1 || asked[familyIPv6] != 1 {
		t.Fatalf("the kernel was asked %v", asked)
	}
	for name, change := range map[string]func(){
		"IPv4": func() { listening[familyIPv4] = []int{8443, 9000} },
		"IPv6": func() { listening[familyIPv6] = []int{31337} },
	} {
		saved4, saved6 := listening[familyIPv4], listening[familyIPv6]
		change()
		err := guard.Check(context.Background())
		if err == nil || !strings.Contains(err.Error(), "which the packet filter leaves open to the sandbox") {
			t.Errorf("a listener outside the guest's ports on %s: %v", name, err)
		}
		listening[familyIPv4], listening[familyIPv6] = saved4, saved6
	}
	// A kernel without IPv6 has no such sockets, and that is no failure. Any
	// other failure to ask is one: the guest does not start a sandbox on a
	// check it could not make.
	failing = fs.ErrNotExist
	if err := guard.Check(context.Background()); err != nil {
		t.Fatalf("a kernel without IPv6: %v", err)
	}
	failing = errors.New("netlink: no such file or directory")
	if err := guard.Check(context.Background()); err == nil {
		t.Fatal("a check the kernel did not answer passed")
	}
	guard.TCP = func(int) ([]int, error) { return nil, fs.ErrNotExist }
	if err := guard.Check(context.Background()); err == nil {
		t.Fatal("a kernel that answers for no IPv4 socket passed")
	}
}
