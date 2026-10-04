package sessionagent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// egressFixture is a proxy whose destinations are stand-ins on this machine:
// its dialer maps the names the tests use to them, and refuses everything
// else the way the real one refuses the guest.
type egressFixture struct {
	proxy *httptest.Server
	mu    sync.Mutex
	// dialed is every address the proxy was asked to connect to.
	dialed []string
	// named is, for each dial, the address the policy named for it, or the
	// zero value.
	named []netip.AddrPort
}

func newEgressFixture(t *testing.T, policy *session.Egress, upstreams map[string]string) *egressFixture {
	t.Helper()
	f := &egressFixture{}
	handler := &EgressProxy{
		Policy: policy,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			named, _ := ctx.Value(namedAddress{}).(netip.AddrPort)
			f.mu.Lock()
			f.dialed = append(f.dialed, address)
			f.named = append(f.named, named)
			f.mu.Unlock()
			target, ok := upstreams[address]
			if !ok {
				return nil, &net.OpError{Op: "dial", Net: network, Err: fmt.Errorf("%w: %s", errInsideGuest, address)}
			}
			return (&net.Dialer{}).DialContext(ctx, network, target)
		},
	}
	f.proxy = httptest.NewServer(handler)
	t.Cleanup(f.proxy.Close)
	return f
}

func (f *egressFixture) dials() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dialed...)
}

// connect sends CONNECT for authority and returns the proxy's answer and the
// connection, which is the tunnel when the answer is 200.
func (f *egressFixture) connect(t *testing.T, authority string) (*http.Response, net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", f.proxy.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	return resp, conn, reader
}

// echoServer answers each connection with what it is sent.
func echoServer(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lis.Close() })
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return lis.Addr().String()
}

func TestEgressProxyTunnels(t *testing.T) {
	f := newEgressFixture(t, nil, map[string]string{"service.example:443": echoServer(t)})
	resp, conn, reader := f.connect(t, "service.example:443")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT answered %s", resp.Status)
	}
	for _, message := range []string{"first\n", "second\n"} {
		if _, err := io.WriteString(conn, message); err != nil {
			t.Fatal(err)
		}
		got, err := reader.ReadString('\n')
		if err != nil || got != message {
			t.Fatalf("the tunnel returned %q, %v, want %q", got, err, message)
		}
	}
	if got := f.dials(); len(got) != 1 || got[0] != "service.example:443" {
		t.Errorf("the proxy dialed %v", got)
	}
}

// A client may send its first bytes right behind the CONNECT, before the
// answer. They are the tunnel's, and must reach the destination.
func TestEgressProxyCarriesBytesSentBehindTheConnect(t *testing.T) {
	f := newEgressFixture(t, nil, map[string]string{"service.example:443": echoServer(t)})
	conn, err := net.Dial("tcp", f.proxy.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "CONNECT service.example:443 HTTP/1.1\r\nHost: service.example:443\r\n\r\nearly\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT answered %v, %v", resp, err)
	}
	if got, err := reader.ReadString('\n'); err != nil || got != "early\n" {
		t.Fatalf("the tunnel returned %q, %v", got, err)
	}
}

func TestEgressProxyRefuses(t *testing.T) {
	policy := &session.Egress{Allow: []string{"service.example:443", "*.pkg.example:443", "inside.example:443"}}
	f := newEgressFixture(t, policy, map[string]string{
		"service.example:443": echoServer(t),
		"other.example:443":   echoServer(t),
	})
	for name, tc := range map[string]struct {
		authority string
		status    int
		says      string
	}{
		"a destination the policy does not name": {"other.example:443", http.StatusForbidden, "does not allow"},
		"the right name on another port":         {"service.example:8443", http.StatusForbidden, "does not allow"},
		"no port":                                {"service.example", http.StatusForbidden, "does not allow"},
		// Allowed by name, and the dialer finds it is the guest itself.
		"a name that leads into the guest": {"inside.example:443", http.StatusForbidden, "inside the guest"},
	} {
		resp, _, _ := f.connect(t, tc.authority)
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != tc.status || !strings.Contains(string(body), tc.says) {
			t.Errorf("%s: %s %q, want %d naming %q", name, resp.Status, body, tc.status, tc.says)
		}
	}
	// Only the last was worth a dial: the policy refused the others first.
	if got := f.dials(); len(got) != 1 || got[0] != "inside.example:443" {
		t.Errorf("the proxy dialed %v for requests its policy refuses", got)
	}
	if resp, _, _ := f.connect(t, "service.example:443"); resp.StatusCode != http.StatusOK {
		t.Errorf("an allowed destination answered %s", resp.Status)
	}
}

// A name for the machine itself is refused as the name it is. What a resolver
// would answer for it is not asked: the fixture's would lead outside.
func TestEgressProxyRefusesLocalhostByName(t *testing.T) {
	outside := echoServer(t)
	f := newEgressFixture(t, nil, map[string]string{
		"localhost:8443":       outside,
		"LocalHost.:8443":      outside,
		"agent.localhost:8443": outside,
		"_gateway:53":          outside,
		"_outbound:443":        outside,
		"_localdnsstub:53":     outside,
		"localhost:80":         outside,
		"localhost.example:80": outside,
	})
	for _, authority := range []string{"localhost:8443", "LocalHost.:8443", "agent.localhost:8443", "_gateway:53", "_outbound:443", "_localdnsstub:53"} {
		resp, _, _ := f.connect(t, authority)
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "inside the guest") {
			t.Errorf("CONNECT %s: %s %q, want 403 naming the guest", authority, resp.Status, body)
		}
	}
	proxyURL, err := url.Parse(f.proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get("http://localhost/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("GET http://localhost/: %s, want 403", resp.Status)
	}
	if got := f.dials(); len(got) != 0 {
		t.Errorf("the proxy dialed %v for names of the guest itself", got)
	}
	// A name that only starts like one is any other name.
	if resp, _, _ := f.connect(t, "localhost.example:80"); resp.StatusCode != http.StatusOK {
		t.Errorf("CONNECT localhost.example:80 answered %s", resp.Status)
	}
}

func TestEgressProxyForwardsPlainHTTP(t *testing.T) {
	var sawHost, sawForwarded string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHost, sawForwarded = r.Host, r.Header.Get("X-Forwarded-For")
		_, _ = io.WriteString(w, "from the origin")
	}))
	defer origin.Close()
	policy := &session.Egress{Allow: []string{"origin.example:80"}}
	f := newEgressFixture(t, policy, map[string]string{
		"origin.example:80": origin.Listener.Addr().String(),
		"other.example:80":  origin.Listener.Addr().String(),
	})
	proxyURL, err := url.Parse(f.proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get("http://origin.example/path")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "from the origin" {
		t.Fatalf("an allowed request answered %s %q", resp.Status, body)
	}
	if sawHost != "origin.example" {
		t.Errorf("the origin saw Host %q", sawHost)
	}
	// Nothing about the sandbox's side of the proxy is added to its request.
	if sawForwarded != "" {
		t.Errorf("the origin was told X-Forwarded-For %q", sawForwarded)
	}

	resp, err = client.Get("http://other.example/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("a request the policy does not allow answered %s", resp.Status)
	}

	// A request that is not for a proxy at all.
	resp, err = http.Get(f.proxy.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a request in origin form answered %s", resp.Status)
	}
}

// What the proxy may connect to, by the address it is about to dial. The
// guest itself is never a destination: its loopback, where its services
// listen; its own interface addresses, which reach the same services; and the
// link-local range, where its host answers. A private network is one only by
// its address, named in the policy.
func TestCheckDestination(t *testing.T) {
	own := func() ([]net.Addr, error) {
		_, a, _ := net.ParseCIDR("10.0.2.15/24")
		a.IP = net.ParseIP("10.0.2.15")
		_, b, _ := net.ParseCIDR("2001:db8::15/64")
		b.IP = net.ParseIP("2001:db8::15")
		return []net.Addr{a, b}, nil
	}
	hops := func() ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.2.2"), netip.MustParseAddr("203.0.113.1")}, nil
	}
	at := func(addr string) netip.AddrPort { return netip.AddrPortFrom(netip.MustParseAddr(addr), 443) }

	for _, inside := range []string{
		"127.0.0.1", "127.0.0.53", "127.255.255.254", "::1", "::ffff:127.0.0.1",
		"0.0.0.0", "::", "0.1.2.3", "255.255.255.255",
		"169.254.17.1", "169.254.169.254", "fe80::1", "224.0.0.251", "ff02::1",
		"10.0.2.15", "::ffff:10.0.2.15", "2001:db8::15",
		// IPv6 forms that carry an IPv4 address: a translator's (RFC 6052),
		// 6to4, and IPv4-compatible. Each ends at the address it carries.
		"64:ff9b::7f00:1", "2002:7f00:1::1", "::7f00:1", // 127.0.0.1
		"64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::1", // 169.254.169.254
		"64:ff9b::a00:20f", "2002:a00:20f::1", // 10.0.2.15, the guest's own
		"64:ff9b::e000:fb", // 224.0.0.251
	} {
		if err := checkDestination(at(inside), netip.AddrPort{}, own, hops); !errors.Is(err, errInsideGuest) {
			t.Errorf("%s: %v, want it refused as inside the guest", inside, err)
		}
		// Naming it in the policy changes nothing.
		if err := checkDestination(at(inside), at(inside), own, hops); !errors.Is(err, errInsideGuest) {
			t.Errorf("%s, named by the policy: %v, want it refused as inside the guest", inside, err)
		}
	}
	for _, private := range []string{
		"10.0.2.2",                                                // the default gateway
		"10.0.2.99",                                               // a neighbor on the guest's link
		"10.9.9.9", "172.16.0.9", "172.31.255.254", "192.168.1.1", // RFC 1918
		"100.64.0.1", "100.127.255.254", // shared address space
		"fd00::1",     // unique local
		"2001:db8::1", // a neighbor on the guest's IPv6 link
		"203.0.113.1", // a gateway that is not on a link of the guest's
		"::ffff:10.9.9.9",
		"64:ff9b::a09:909", "2002:a09:909::1", "::a09:909", // 10.9.9.9 in an IPv6 form
		"64:ff9b::a00:202",                     // the default gateway, through a translator
		"64:ff9b::6440:1",                      // 100.64.0.1, through a translator
		"2002:cb00:7101::1",                    // 6to4 to 203.0.113.1, a gateway
		"fec0::1",                              // site-local
		"2001:0:4136:e378:8000:63bf:3fff:fdd2", // Teredo
		"64:ff9b:1::a09:909",                   // a translator prefix a network assigns itself
	} {
		if err := checkDestination(at(private), netip.AddrPort{}, own, hops); !errors.Is(err, errPrivate) {
			t.Errorf("%s: %v, want it refused as private", private, err)
		}
		if err := checkDestination(at(private), at(private), own, hops); err != nil {
			t.Errorf("%s, named by the policy: %v", private, err)
		}
		// Named on another port, or another address named: still refused.
		other := netip.AddrPortFrom(netip.MustParseAddr(private), 8443)
		if err := checkDestination(at(private), other, own, hops); !errors.Is(err, errPrivate) {
			t.Errorf("%s, named on another port: %v, want it refused", private, err)
		}
		if err := checkDestination(at(private), at("10.200.0.1"), own, hops); !errors.Is(err, errPrivate) {
			t.Errorf("%s, with another address named: %v, want it refused", private, err)
		}
	}
	for _, public := range []string{
		"192.0.2.10", "8.8.8.8", "100.128.0.1", "172.32.0.1", "2606:4700::1111", "203.0.113.2",
		"64:ff9b::808:808", "2002:808:808::1", // 8.8.8.8 in an IPv6 form
		"2001:4860:4860::8888", // near Teredo's prefix, and not in it
	} {
		if err := checkDestination(at(public), netip.AddrPort{}, own, hops); err != nil {
			t.Errorf("%s: %v", public, err)
		}
	}
	failing := func() ([]net.Addr, error) { return nil, io.ErrUnexpectedEOF }
	if err := checkDestination(at("192.0.2.10"), netip.AddrPort{}, failing, hops); err == nil {
		t.Error("a destination was allowed although the guest's own addresses could not be listed")
	}
	noHops := func() ([]netip.Addr, error) { return nil, io.ErrUnexpectedEOF }
	if err := checkDestination(at("192.0.2.10"), netip.AddrPort{}, own, noHops); err == nil {
		t.Error("a destination was allowed although the guest's gateways could not be listed")
	}
}

// Only an address rule names an address for the dial. A name the policy
// allows carries none, so whatever it resolves to is held to the rule for
// private networks.
func TestEgressProxyNamesOnlyLiteralAddresses(t *testing.T) {
	outside := echoServer(t)
	policy := &session.Egress{Allow: []string{"10.1.2.3:443", "internal.example:443", "[fd00::7]:443"}}
	f := newEgressFixture(t, policy, map[string]string{
		"10.1.2.3:443": outside, "internal.example:443": outside, "[fd00::7]:443": outside,
	})
	for _, authority := range []string{"10.1.2.3:443", "internal.example:443", "[fd00::7]:443"} {
		if resp, _, _ := f.connect(t, authority); resp.StatusCode != http.StatusOK {
			t.Fatalf("CONNECT %s answered %s", authority, resp.Status)
		}
	}
	f.mu.Lock()
	got := append([]netip.AddrPort(nil), f.named...)
	f.mu.Unlock()
	want := []netip.AddrPort{netip.MustParseAddrPort("10.1.2.3:443"), {}, netip.MustParseAddrPort("[fd00::7]:443")}
	if !slices.Equal(got, want) {
		t.Errorf("addresses named for the dials: %v, want %v", got, want)
	}

	// Without a policy nothing is named, whatever the sandbox asks for.
	open := newEgressFixture(t, nil, map[string]string{"10.1.2.3:443": outside})
	if resp, _, _ := open.connect(t, "10.1.2.3:443"); resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT answered %s", resp.Status)
	}
	open.mu.Lock()
	defer open.mu.Unlock()
	if len(open.named) != 1 || open.named[0].IsValid() {
		t.Errorf("with no policy the dial was given the address %v", open.named)
	}
}

func TestParseRoutes(t *testing.T) {
	// /proc/net/route of a guest on QEMU's user network, and a route with no
	// next hop.
	for line, want := range map[string]string{
		"enp0s4	00000000	0202000A	0003	0	0	1024	00000000	0	0	0":                    "10.0.2.2",
		"enp0s4	0002000A	00000000	0001	0	0	1024	00FFFFFF	0	0	0":                    "",
		"Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT": "",
	} {
		hop, ok := parseRoute4(strings.Fields(line))
		if got := map[bool]string{true: hop.String(), false: ""}[ok]; got != want {
			t.Errorf("%q: next hop %q, want %q", line, got, want)
		}
	}
	for line, want := range map[string]string{
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000002 00000400 00000001 00000000 00000003 enp0s4": "fe80::2",
		"fec00000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 enp0s4": "",
	} {
		hop, ok := parseRoute6(strings.Fields(line))
		if got := map[bool]string{true: hop.String(), false: ""}[ok]; got != want {
			t.Errorf("%q: next hop %q, want %q", line, got, want)
		}
	}
}

// The dialer the proxy uses when it is given none refuses the guest by the
// address it is about to connect to, so a listener on this machine's
// loopback is out of its reach by address and by any name for it.
func TestEgressProxyDefaultDialerRefusesLoopback(t *testing.T) {
	target := echoServer(t)
	_, port, _ := net.SplitHostPort(target)
	proxy := httptest.NewServer(&EgressProxy{})
	defer proxy.Close()
	for _, host := range []string{"127.0.0.1", "localhost", "[::1]"} {
		conn, err := net.Dial("tcp", proxy.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		authority := host + ":" + port
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
		resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
		conn.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("CONNECT %s answered %s, want 403", authority, resp.Status)
		}
	}
}
