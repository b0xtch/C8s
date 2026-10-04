package sessionagent

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// What a guest lists before any session's code runs, taken from one on TDX:
// the agent's listener and one connection to it. Nothing else in the guest
// has a socket.
const (
	procTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
`
	procTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:20FB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 747 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF00000F02000A:20FB 0000000000000000FFFF00000202000A:DD7E 01 00000000:00000000 02:000005D7 00000000     0        0 2072 3 0000000000000000 20 4 28 14 -1
`
	procUDP = `   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
`
	procUDP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
`
	procUnix = `Num       RefCount Protocol Flags    Type St Inode Path
`
)

// fakeProc is a proc filesystem with the given socket tables, and a guest's
// own UDP tables.
func fakeProc(t *testing.T, tcp, tcp6, unix string) ListenerGuard {
	t.Helper()
	return fakeProcUDP(t, tcp, tcp6, procUDP, procUDP6, unix)
}

func fakeProcUDP(t *testing.T, tcp, tcp6, udp, udp6, unix string) ListenerGuard {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"tcp": tcp, "tcp6": tcp6, "udp": udp, "udp6": udp6, "unix": unix} {
		if content == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, "net", name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return ListenerGuard{Proc: dir}
}

func TestListenerGuard(t *testing.T) {
	if err := fakeProc(t, procTCP, procTCP6, procUnix).Check(context.Background()); err != nil {
		t.Fatalf("a session guest's own listeners: %v", err)
	}
	// A kernel built without IPv6.
	if err := fakeProc(t, procTCP, "", procUnix).Check(context.Background()); err != nil {
		t.Fatalf("with no tcp6 table: %v", err)
	}

	listener := func(port string) string {
		return "   9: 00000000:" + port + " 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9999 1 0000000000000000 100 0 0 10 0\n"
	}
	for name, tc := range map[string]struct {
		guard ListenerGuard
		want  string
	}{
		"a listener on an unprivileged port": {fakeProc(t, procTCP+listener("2328"), procTCP6, procUnix), "TCP port 9000"},
		"one over IPv6 only":                 {fakeProc(t, procTCP, procTCP6+strings.Replace(listener("1F90"), "00000000:1F90 00000000:0000", "00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000", 1), procUnix), "TCP port 8080"},
		"just past the agent's block":        {fakeProc(t, procTCP+listener("2134"), procTCP6, procUnix), "TCP port 8500"},
		"a listener on an abstract name": {
			fakeProc(t, procTCP, procTCP6, procUnix+"0000000000000000: 00000002 00000000 00010000 0001 01  4000 @/tmp/.X11-unix/X0\n"),
			"@/tmp/.X11-unix/X0",
		},
		"no socket table":      {fakeProc(t, "", procTCP6, procUnix), "list the guest's listeners"},
		"no unix socket table": {fakeProc(t, procTCP, procTCP6, ""), "list the guest's unix sockets"},
		"a table it cannot read": {
			fakeProc(t, procTCP+"   9: nonsense\n", procTCP6, procUnix),
			"unexpected line",
		},
	} {
		err := tc.guard.Check(context.Background())
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error naming %q", name, err, tc.want)
		}
	}

	// A unix socket is the sandbox's to reach only by an abstract name it
	// listens on: one bound to a path is behind the file system's modes, and
	// one that is connected or takes datagrams accepts no connection.
	for name, line := range map[string]string{
		"a listener on a path":                   "0000000000000000: 00000002 00000000 00010000 0001 01  1176 /run/c8s-session/control\n",
		"a connected socket on an abstract name": "0000000000000000: 00000003 00000000 00000000 0001 03  2396 @c50b0068cb5d5f80/bus\n",
		"a datagram socket on an abstract name":  "0000000000000000: 00000002 00000000 00000000 0002 01  1423 @10909561722113124532\n",
		"a socket with no name":                  "0000000000000000: 00000002 00000000 00000000 0002 03   854\n",
	} {
		if err := fakeProc(t, procTCP, procTCP6, procUnix+line).Check(context.Background()); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	// Ports of the guest's own are fine wherever they are in its ranges, and a
	// socket that is not listening is nobody's listener.
	for _, port := range []string{"0016", "03FF", "20D0", "2133"} {
		if err := fakeProc(t, procTCP+listener(port), procTCP6, procUnix).Check(context.Background()); err != nil {
			t.Errorf("a guest service on port 0x%s: %v", port, err)
		}
	}
	connected := strings.Replace(listener("2328"), " 0A ", " 01 ", 1)
	if err := fakeProc(t, procTCP+connected, procTCP6, procUnix).Check(context.Background()); err != nil {
		t.Errorf("a connected socket on port 9000: %v", err)
	}
}

// A UDP socket has no listening state: one that is bound and not connected
// takes a datagram from anyone, the sandbox included. The guest's own are
// its resolver's stubs, on ports the filter closes.
func TestListenerGuardUDP(t *testing.T) {
	socket := func(port, remote string) string {
		return " 9000: 00000000:" + port + " " + remote + " 07 00000000:00000000 00:00000000 00000000   100        0 9999 2 0000000000000000 0\n"
	}
	const anyone, peer = "00000000:0000", "0111FEA9:007B"
	socket6 := " 9000: 00000000000000000000000000000000:D431 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   100        0 9999 2 0000000000000000 0\n"

	for name, tc := range map[string]struct {
		guard ListenerGuard
		want  string
	}{
		"a service on an unprivileged port":     {fakeProcUDP(t, procTCP, procTCP6, procUDP+socket("2328", anyone), procUDP6, procUnix), "UDP port 9000"},
		"a client that sends from a bound port": {fakeProcUDP(t, procTCP, procTCP6, procUDP+socket("D431", anyone), procUDP6, procUnix), "UDP port 54321"},
		// A resolver's ports, which a guest that ran one once had open.
		"multicast DNS":          {fakeProcUDP(t, procTCP, procTCP6, procUDP+socket("14E9", anyone), procUDP6, procUnix), "UDP port 5353"},
		"LLMNR":                  {fakeProcUDP(t, procTCP, procTCP6, procUDP+socket("14EB", anyone), procUDP6, procUnix), "UDP port 5355"},
		"one over IPv6 only":     {fakeProcUDP(t, procTCP, procTCP6, procUDP, procUDP6+socket6, procUnix), "UDP port 54321"},
		"no socket table":        {fakeProcUDP(t, procTCP, procTCP6, "", procUDP6, procUnix), "list the guest's listeners"},
		"a table it cannot read": {fakeProcUDP(t, procTCP, procTCP6, procUDP+" 9000: 00000000:2328 nonsense 07\n", procUDP6, procUnix), "unexpected remote address"},
	} {
		err := tc.guard.Check(context.Background())
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error naming %q", name, err, tc.want)
		}
	}

	// A kernel built without IPv6.
	if err := fakeProcUDP(t, procTCP, "", procUDP, "", procUnix).Check(context.Background()); err != nil {
		t.Fatalf("with no IPv6 tables: %v", err)
	}
	// The guest's own ports, wherever they are in its ranges.
	for _, port := range []string{"0044", "03FF", "20D0", "2133"} {
		if err := fakeProcUDP(t, procTCP, procTCP6, procUDP+socket(port, anyone), procUDP6, procUnix).Check(context.Background()); err != nil {
			t.Errorf("a guest service on UDP port 0x%s: %v", port, err)
		}
	}
	// Connected, a socket hears its peer alone.
	if err := fakeProcUDP(t, procTCP, procTCP6, procUDP+socket("2328", peer), procUDP6, procUnix).Check(context.Background()); err != nil {
		t.Errorf("a connected socket on UDP port 9000: %v", err)
	}
}

// The ports the guard allows the guest are the ports the image's packet
// filter closes to the sandbox, and the agent's own port is one of them. If
// the two drifted apart, a guest service could listen where the sandbox
// reaches it with both checks passing.
func TestGuestPortsAreTheOnesThePacketFilterCloses(t *testing.T) {
	data, err := os.ReadFile(expectedRuleset)
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("needs the guest image profile: run from a checkout")
	}
	if err != nil {
		t.Fatal(err)
	}
	var listing struct {
		Nftables []struct {
			Rule *struct {
				Chain string `json:"chain"`
				Expr  []struct {
					Match *struct {
						Left struct {
							Payload struct {
								Protocol string `json:"protocol"`
								Field    string `json:"field"`
							} `json:"payload"`
						} `json:"left"`
						Right json.RawMessage `json:"right"`
					} `json:"match"`
					Reject json.RawMessage `json:"reject"`
				} `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(data, &listing); err != nil {
		t.Fatal(err)
	}
	// closed reads the ports the output chain rejects for one protocol: a set
	// whose elements are ranges or single ports.
	closed := func(protocol string) [][2]int {
		var out [][2]int
		for _, item := range listing.Nftables {
			if item.Rule == nil || item.Rule.Chain != "output" {
				continue
			}
			rejects := false
			var ports json.RawMessage
			for _, expr := range item.Rule.Expr {
				rejects = rejects || expr.Reject != nil
				if expr.Match != nil && expr.Match.Left.Payload.Protocol == protocol && expr.Match.Left.Payload.Field == "dport" {
					ports = expr.Match.Right
				}
			}
			if !rejects || ports == nil {
				continue
			}
			var set struct {
				Set []json.RawMessage `json:"set"`
			}
			if err := json.Unmarshal(ports, &set); err != nil {
				t.Fatalf("the rule that closes %s ports to the sandbox lists them as %s: %v", protocol, ports, err)
			}
			for _, element := range set.Set {
				var span struct {
					Range [2]int `json:"range"`
				}
				var port int
				switch {
				case json.Unmarshal(element, &port) == nil:
					out = append(out, [2]int{port, port})
				case json.Unmarshal(element, &span) == nil:
					out = append(out, span.Range)
				default:
					t.Fatalf("the rule that closes %s ports to the sandbox has the element %s", protocol, element)
				}
			}
		}
		return out
	}
	for _, protocol := range []string{"tcp", "udp"} {
		if got := closed(protocol); !slices.Equal(got, guestPorts) {
			t.Fatalf("the packet filter closes %s ports %v to the sandbox, the guard allows the guest %v", protocol, got, guestPorts)
		}
	}
	if !isGuestPort(session.AgentPort) {
		t.Fatalf("the agent's port %d is not one of the guest's ports %v", session.AgentPort, guestPorts)
	}
}
