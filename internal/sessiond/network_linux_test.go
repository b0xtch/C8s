//go:build linux

package sessiond

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestMain lets the test binary stand in for a program in another network
// namespace: a listener that says who reached it, or one connection attempt.
func TestMain(m *testing.M) {
	switch role := os.Getenv("C8S_FILTER_HELPER"); {
	case strings.HasPrefix(role, "listen "):
		os.Exit(helperListen(strings.TrimPrefix(role, "listen ")))
	case strings.HasPrefix(role, "dial "):
		os.Exit(helperDial(strings.Fields(strings.TrimPrefix(role, "dial "))))
	}
	os.Exit(m.Run())
}

// helperListen answers every connection with the address it came from.
func helperListen(addr string) int {
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println("listening")
	for {
		conn, err := ln.Accept()
		if err != nil {
			return 1
		}
		host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		fmt.Fprintln(conn, host)
		conn.Close()
	}
}

// helperDial connects from source to target and prints what it is told.
func helperDial(args []string) int {
	dialer := &net.Dialer{Timeout: 1500 * time.Millisecond}
	if args[0] != "-" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(args[0])}
	}
	conn, err := dialer.Dial("tcp4", args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Print(line)
	return 0
}

// world is a host with two guests on taps of their own and a network
// upstream of it, each a network namespace:
//
//	guest1 -- c8st0 \
//	                 host -- up0 -- upstream
//	guest2 -- c8st1 /
//
// The interfaces on the host's side carry the names the daemon gives a TD's
// tap, so the daemon's ruleset treats them as it treats one.
type world struct {
	t      *testing.T
	prefix string
}

const (
	hostEnd1, guest1 = "10.99.0.1", "10.99.0.2"
	hostEnd2, guest2 = "10.99.0.5", "10.99.0.6"
	hostUp, upstream = "198.51.100.1", "198.51.100.2"
)

func newWorld(t *testing.T) *world {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to make network namespaces")
	}
	for _, tool := range []string{"ip", "nft"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("needs %s", tool)
		}
	}
	w := &world{t: t, prefix: fmt.Sprintf("c8sf%d", os.Getpid()%10000)}
	for _, ns := range []string{"host", "g1", "g2", "up"} {
		w.ip("netns", "add", w.ns(ns))
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", w.ns(ns)).Run() })
		w.in(ns, "ip", "link", "set", "lo", "up")
	}
	link := func(hostIf, hostAddr, peerNS, peerAddr string) {
		w.in("host", "ip", "link", "add", hostIf, "type", "veth", "peer", "name", "eth0", "netns", w.ns(peerNS))
		w.in("host", "ip", "addr", "add", hostAddr+"/30", "dev", hostIf)
		w.in("host", "ip", "link", "set", hostIf, "up")
		w.in(peerNS, "ip", "addr", "add", peerAddr+"/30", "dev", "eth0")
		w.in(peerNS, "ip", "link", "set", "eth0", "up")
		w.in(peerNS, "ip", "route", "add", "default", "via", hostAddr)
	}
	link((&Network{}).tapName(0), hostEnd1, "g1", guest1)
	link((&Network{}).tapName(1), hostEnd2, "g2", guest2)
	link("up0", hostUp, "up", upstream)
	w.in("host", "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
	// The reverse path filter is the kernel's own guard against a spoofed
	// source. Off, so that the ruleset's guard is the one under test.
	w.in("host", "sysctl", "-q", "-w", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0")
	for _, iface := range []string{(&Network{}).tapName(0), (&Network{}).tapName(1), "up0"} {
		w.in("host", "sysctl", "-q", "-w", "net.ipv4.conf."+iface+".rp_filter=0")
	}
	w.listen("host", "0.0.0.0:2222")
	w.listen("g1", "0.0.0.0:8443")
	w.listen("g2", "0.0.0.0:8443")
	w.listen("up", "0.0.0.0:8080")
	return w
}

func (w *world) ns(name string) string { return w.prefix + name }

func (w *world) ip(args ...string) {
	w.t.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		w.t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

func (w *world) in(ns string, args ...string) {
	w.t.Helper()
	w.ip(append([]string{"netns", "exec", w.ns(ns)}, args...)...)
}

// load puts the daemon's ruleset into the host's packet filter.
func (w *world) load(egress string, reach ...netip.AddrPort) {
	w.t.Helper()
	cmd := exec.Command("ip", "netns", "exec", w.ns("host"), "nft", "-f", "-")
	rules := (&Network{}).filterRuleset(egress, reach)
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		w.t.Fatalf("load the ruleset: %v: %s\n%s", err, out, rules)
	}
}

func (w *world) listen(ns, addr string) {
	w.t.Helper()
	cmd := exec.Command("ip", "netns", "exec", w.ns(ns), os.Args[0])
	cmd.Env = append(os.Environ(), "C8S_FILTER_HELPER=listen "+addr)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		w.t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || strings.TrimSpace(line) != "listening" {
		w.t.Fatalf("the listener in %s: %q, %v", ns, line, err)
	}
	go func() { _, _ = io.Copy(io.Discard, stdout) }()
}

// dial connects from ns to target, from source when it is not "-". It
// returns the address the listener saw, or "" when nothing connected.
func (w *world) dial(ns, source, target string) string {
	w.t.Helper()
	cmd := exec.Command("ip", "netns", "exec", w.ns(ns), os.Args[0])
	cmd.Env = append(os.Environ(), "C8S_FILTER_HELPER=dial "+source+" "+target)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (w *world) reaches(ns, target, what string) {
	w.t.Helper()
	if w.dial(ns, "-", target) == "" {
		w.t.Errorf("%s: no connection from %s to %s", what, ns, target)
	}
}

func (w *world) blocked(ns, target, what string) {
	w.t.Helper()
	if seen := w.dial(ns, "-", target); seen != "" {
		w.t.Errorf("%s: %s reached %s", what, ns, target)
	}
}

// The ruleset the daemon loads keeps a guest to itself: it reaches nothing
// of its host, no other guest and nothing beyond, and only its host reaches
// it.
func TestFilterIsolatesGuests(t *testing.T) {
	w := newWorld(t)
	// The topology itself lets everything through.
	w.reaches("g1", hostEnd1+":2222", "before the ruleset, a guest and its host")
	w.reaches("g1", guest2+":8443", "before the ruleset, two guests")
	w.reaches("g1", upstream+":8080", "before the ruleset, a guest and upstream")
	w.reaches("up", guest1+":8443", "before the ruleset, upstream and a guest")

	w.load("")
	w.reaches("host", guest1+":8443", "the daemon's road to a guest")
	w.reaches("host", guest2+":8443", "the daemon's road to a guest")
	w.blocked("g1", hostEnd1+":2222", "a guest and its host's end of the tap")
	w.blocked("g1", hostEnd2+":2222", "a guest and its host's end of another tap")
	w.blocked("g1", hostUp+":2222", "a guest and its host's other address")
	w.blocked("g1", guest2+":8443", "a guest and another guest")
	w.blocked("g2", guest1+":8443", "a guest and another guest")
	w.blocked("g1", upstream+":8080", "a guest and upstream, with no egress configured")
	w.blocked("up", guest1+":8443", "upstream and a guest")
	// Loading it again replaces the table: a daemon restarts.
	w.load("")
	w.reaches("host", guest1+":8443", "the daemon's road after a reload")
	w.blocked("g1", guest2+":8443", "two guests after a reload")
}

// What the configuration opens to every guest is reached, and nothing beside
// it: another port of the same address stays closed, on the host and beyond.
func TestFilterReach(t *testing.T) {
	w := newWorld(t)
	w.listen("host", "0.0.0.0:2223")
	w.listen("up", "0.0.0.0:8081")
	w.load("", netip.MustParseAddrPort(hostUp+":2222"), netip.MustParseAddrPort(upstream+":8080"))
	w.reaches("g1", hostUp+":2222", "a guest and the host address and port opened to it")
	w.reaches("g2", hostUp+":2222", "another guest and the same")
	w.reaches("g1", upstream+":8080", "a guest and the destination beyond the host opened to it")
	w.blocked("g1", hostUp+":2223", "a guest and another port of the opened host address")
	w.blocked("g1", hostEnd1+":2222", "a guest and the same port on another host address")
	w.blocked("g1", upstream+":8081", "a guest and another port of the opened destination")
	w.blocked("g1", guest2+":8443", "a guest and another guest")
	w.blocked("up", guest1+":8443", "the opened destination and a guest")
}

// With an egress interface a guest's traffic leaves there, under the host's
// address, and nowhere else. Nothing comes in.
func TestFilterEgress(t *testing.T) {
	w := newWorld(t)
	w.load("up0")
	if seen := w.dial("g1", "-", upstream+":8080"); seen != hostUp {
		t.Errorf("a guest's connection upstream was seen from %q, want the host's address %s", seen, hostUp)
	}
	w.blocked("up", guest1+":8443", "upstream and a guest")
	w.blocked("g1", hostEnd1+":2222", "a guest and its host")
	w.blocked("g1", guest2+":8443", "a guest and another guest")
	// A guest that sends from an address its tap was not given.
	w.in("g1", "ip", "addr", "add", guest2+"/32", "dev", "lo")
	if seen := w.dial("g1", guest2, upstream+":8080"); seen != "" {
		t.Errorf("a guest reached upstream from another guest's address (seen from %s)", seen)
	}
	if seen := w.dial("g1", "-", upstream+":8080"); seen != hostUp {
		t.Errorf("the guest's own address stopped working: seen from %q", seen)
	}
}

// Two daemons on one host each load a table of their own. A daemon that
// loads its ruleset again replaces its own table and leaves the other's.
func TestSecondDaemonsTableLeavesTheFirstsAlone(t *testing.T) {
	w := newWorld(t)
	first, second := &Network{}, &Network{TapPrefix: "c8su"}
	load := func(n *Network, reach ...netip.AddrPort) {
		t.Helper()
		cmd := exec.Command("ip", "netns", "exec", w.ns("host"), "nft", "-f", "-")
		cmd.Stdin = strings.NewReader(n.filterRuleset("", reach))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("load %s: %v: %s", n.table(), err, out)
		}
	}
	listed := func(table string) string {
		t.Helper()
		out, err := exec.Command("ip", "netns", "exec", w.ns("host"), "nft", "list", "table", "inet", table).CombinedOutput()
		if err != nil {
			t.Fatalf("list %s: %v: %s", table, err, out)
		}
		return string(out)
	}
	opened := netip.MustParseAddrPort("192.0.2.7:8443")
	load(first, opened)
	load(second)
	if rules := listed(first.table()); !strings.Contains(rules, "192.0.2.7") || strings.Contains(rules, "c8su") {
		t.Fatalf("the first daemon's table after the second loaded its own:\n%s", rules)
	}
	if rules := listed(second.table()); strings.Contains(rules, "192.0.2.7") || strings.Contains(rules, `"c8st*"`) || !strings.Contains(rules, `"c8su*"`) {
		t.Fatalf("the second daemon's table:\n%s", rules)
	}
	// The second loads again, as a daemon that restarts does.
	load(second, netip.MustParseAddrPort("192.0.2.9:8443"))
	if rules := listed(first.table()); !strings.Contains(rules, "192.0.2.7") || strings.Contains(rules, "192.0.2.9") {
		t.Fatalf("the first daemon's table after the second loaded again:\n%s", rules)
	}
	if rules := listed(second.table()); !strings.Contains(rules, "192.0.2.9") {
		t.Fatalf("the second daemon's table after it loaded again:\n%s", rules)
	}
	// With both loaded, the first's guests are held as before, and reached
	// as before: the second's rules match none of the first's taps.
	w.blocked("g1", hostEnd1+":2222", "a guest and its host, with a second daemon's table loaded")
	w.blocked("g1", guest2+":8443", "two guests, with a second daemon's table loaded")
	w.reaches("host", guest1+":8443", "the daemon's road to a guest, with a second daemon's table loaded")
}
