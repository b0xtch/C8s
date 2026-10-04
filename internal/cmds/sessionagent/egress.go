package sessionagent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

const (
	// EgressProxyPort is where the sandbox finds its proxy, on the loopback
	// of its own network namespace.
	EgressProxyPort = session.SandboxProxyPort

	egressDialTimeout = 15 * time.Second
	// maxEgressConns bounds the connections the sandbox holds open through
	// the proxy. Each costs the agent two goroutines and two sockets.
	maxEgressConns = 1024
)

var (
	// errInsideGuest refuses a destination that is the guest itself, or its
	// host on the guest's own link. No policy opens one.
	errInsideGuest = errors.New("the destination is inside the guest")
	// errPrivate refuses a destination on a private network, which only an
	// address rule of the sandbox's egress policy opens.
	errPrivate = errors.New("the destination is on a private network, and the sandbox's egress policy does not name its address")
)

// EgressProxy is the sandbox's only way out. The sandbox runs in a network
// namespace with a loopback interface and nothing else, and this proxy
// listens on that loopback while it dials from the guest's own namespace.
//
// It speaks HTTP CONNECT for anything over TCP, and forwards plain HTTP
// requests sent in absolute form. Three rules hold for both.
//
// No destination is the guest: not its loopback, where its own services
// listen, not an address of its interfaces, and not the link-local range its
// host answers on. Without this rule the proxy would hand the sandbox
// everything its namespace was built to keep it from.
//
// A destination on a private network (the guest's own subnets, its gateways,
// the private and shared address ranges) is reached only if the sandbox's
// egress policy names that address. A name does not open one: what a name
// resolves to is the host's to say.
//
// And a destination must be one the policy allows, when there is a policy.
type EgressProxy struct {
	// Policy is the sandbox's allowlist. Nil allows any public destination.
	Policy *session.Egress
	// Dial opens the outbound connection. Nil dials from the agent's own
	// network namespace under the rules above.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	once      sync.Once
	slots     chan struct{}
	transport *http.Transport
	forward   *httputil.ReverseProxy
}

func (p *EgressProxy) init() {
	p.once.Do(func() {
		if p.Dial == nil {
			dialer := &net.Dialer{Timeout: egressDialTimeout, ControlContext: checkDial}
			p.Dial = dialer.DialContext
		}
		p.slots = make(chan struct{}, maxEgressConns)
		p.transport = &http.Transport{
			DialContext:           p.Dial,
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          64,
			IdleConnTimeout:       30 * time.Second,
			ResponseHeaderTimeout: 5 * time.Minute,
		}
		p.forward = &httputil.ReverseProxy{
			Rewrite:   func(*httputil.ProxyRequest) {},
			Transport: p.transport,
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
				refuse(w, err)
			},
		}
	})
}

// namedAddress is the context key for the one address the policy names for a
// request: an address rule matched the literal address the sandbox asked for.
type namedAddress struct{}

// checkDial is a net.Dialer control function. It sees the address a
// connection is about to be made to, after any name was resolved and for each
// address tried, so a name that resolves into the guest or onto a private
// network is refused like the address itself.
func checkDial(ctx context.Context, _, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: %q", errInsideGuest, address)
	}
	named, _ := ctx.Value(namedAddress{}).(netip.AddrPort)
	return checkDestination(ap, named, net.InterfaceAddrs, gateways)
}

// reserved is what no sandbox connection goes to besides loopback,
// link-local and multicast: "this network", and the limited broadcast address.
var reserved = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("255.255.255.255/32"),
}

// sharedAddressSpace is 100.64.0.0/10 (RFC 6598): carrier-grade NAT, and the
// range overlay networks hand out. It is no more public than 10.0.0.0/8.
var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// IPv6 prefixes whose addresses carry an IPv4 address that a translator or a
// relay on the way delivers the connection to.
var (
	// The translator's prefix of RFC 6052: the IPv4 address is the last 32 bits.
	nat64 = netip.MustParsePrefix("64:ff9b::/96")
	// 6to4 (RFC 3056): the IPv4 address of the site's relay follows the prefix.
	sixToFour = netip.MustParsePrefix("2002::/16")
	// IPv4-compatible addresses (RFC 4291, deprecated): the last 32 bits.
	v4Compatible = netip.MustParsePrefix("::/96")
)

// opaque are IPv6 ranges that are private, or lead to an IPv4 address this
// proxy cannot read out of them: site-local addresses (RFC 3879), Teredo
// (RFC 4380), and the translator prefixes a network assigns itself
// (RFC 8215), where the address sits at a position only that network knows.
var opaque = []netip.Prefix{
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
}

// carried returns the IPv4 address that addr, an IPv6 address, stands for.
func carried(addr netip.Addr) (netip.Addr, bool) {
	if !addr.Is6() {
		return netip.Addr{}, false
	}
	b := addr.As16()
	switch {
	case nat64.Contains(addr), v4Compatible.Contains(addr):
		return netip.AddrFrom4([4]byte(b[12:16])), true
	case sixToFour.Contains(addr):
		return netip.AddrFrom4([4]byte(b[2:6])), true
	}
	return netip.Addr{}, false
}

// checkDestination decides whether the proxy may connect to ap. named is the
// address the sandbox's egress policy names for this request, if it names
// one: only that opens a private destination.
//
// An IPv6 address that carries an IPv4 address is judged as both: the
// connection ends at the IPv4 one.
func checkDestination(ap, named netip.AddrPort, interfaces func() ([]net.Addr, error), gateways func() ([]netip.Addr, error)) error {
	addr := ap.Addr().Unmap().WithZone("")
	if !addr.IsValid() {
		return fmt.Errorf("%w: %s", errInsideGuest, addr)
	}
	ends := []netip.Addr{addr}
	if inner, ok := carried(addr); ok {
		ends = append(ends, inner)
	}
	private := false
	for _, prefix := range opaque {
		private = private || prefix.Contains(addr)
	}
	for _, end := range ends {
		if end.IsLoopback() || end.IsUnspecified() || end.IsMulticast() ||
			end.IsLinkLocalUnicast() || end.IsLinkLocalMulticast() || end.IsInterfaceLocalMulticast() {
			return fmt.Errorf("%w: %s", errInsideGuest, addr)
		}
		for _, prefix := range reserved {
			if prefix.Contains(end) {
				return fmt.Errorf("%w: %s", errInsideGuest, addr)
			}
		}
		private = private || end.IsPrivate() || sharedAddressSpace.Contains(end)
	}
	own, err := interfaces()
	if err != nil {
		return fmt.Errorf("list the guest's addresses: %w", err)
	}
	for _, a := range own {
		prefix, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		for _, end := range ends {
			if prefix.Addr().Unmap() == end {
				return fmt.Errorf("%w: %s is its own address", errInsideGuest, addr)
			}
			// A neighbor on one of the guest's own links.
			if netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()).Masked().Contains(end) {
				private = true
			}
		}
	}
	if !private {
		hops, err := gateways()
		if err != nil {
			return fmt.Errorf("list the guest's gateways: %w", err)
		}
		for _, hop := range hops {
			for _, end := range ends {
				if hop.Unmap() == end {
					private = true
				}
			}
		}
	}
	if private && netip.AddrPortFrom(named.Addr().Unmap(), named.Port()) != netip.AddrPortFrom(addr, ap.Port()) {
		return fmt.Errorf("%w: %s", errPrivate, addr)
	}
	return nil
}

// guestNames are the names the guest's resolver answers by itself, with the
// guest's own addresses or its gateway's.
var guestNames = map[string]bool{
	"localhost": true, "_gateway": true, "_outbound": true, "_localdnsstub": true, "_localdnsproxy": true,
}

// guestName reports whether host is a name for the guest or its gateway.
// Such a name is refused as the name it is, without asking a resolver, whose
// answer for it differs from one resolver to the next.
func guestName(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return guestNames[host] || strings.HasSuffix(host, ".localhost")
}

// admit applies the name rules and the policy to a request for host:port, and
// returns the context its connection is dialed under.
func (p *EgressProxy) admit(ctx context.Context, authority, host string, port int) (context.Context, error) {
	if !p.Policy.Allows(host, port) {
		return nil, errNotAllowed(authority)
	}
	if guestName(host) {
		return nil, fmt.Errorf("%w: %s", errInsideGuest, host)
	}
	// A literal address the policy allows was named by an address rule: a
	// name rule never matches an address.
	if addr, err := netip.ParseAddr(host); err == nil && p.Policy != nil {
		ctx = context.WithValue(ctx, namedAddress{}, netip.AddrPortFrom(addr, uint16(port)))
	}
	return ctx, nil
}

func (p *EgressProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.init()
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		http.Error(w, "too many connections through the egress proxy", http.StatusServiceUnavailable)
		return
	}
	switch {
	case r.Method == http.MethodConnect:
		p.connect(w, r)
	case r.URL.IsAbs() && r.URL.Scheme == "http":
		host, port, err := hostPort(r.URL.Host, 80)
		if err != nil {
			refuse(w, errNotAllowed(r.URL.Host))
			return
		}
		ctx, err := p.admit(r.Context(), r.URL.Host, host, port)
		if err != nil {
			refuse(w, err)
			return
		}
		p.forward.ServeHTTP(w, r.WithContext(ctx))
	default:
		http.Error(w, "this is a proxy: send CONNECT, or an http:// request in absolute form", http.StatusBadRequest)
	}
}

// connect answers CONNECT host:port with a tunnel to it.
func (p *EgressProxy) connect(w http.ResponseWriter, r *http.Request) {
	host, port, err := hostPort(r.Host, 0)
	if err != nil {
		refuse(w, errNotAllowed(r.Host))
		return
	}
	ctx, err := p.admit(r.Context(), r.Host, host, port)
	if err != nil {
		refuse(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(ctx, egressDialTimeout)
	upstream, err := p.Dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	cancel()
	if err != nil {
		refuse(w, err)
		return
	}
	defer upstream.Close()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT needs HTTP/1.1", http.StatusHTTPVersionNotSupported)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || buffered.Flush() != nil {
		return
	}
	done := make(chan struct{}, 2)
	// The buffered reader may hold bytes the client sent behind its CONNECT.
	go relay(upstream, buffered, done)
	go relay(client, upstream, done)
	<-done
	// One direction ended. Give the other a moment to finish what it carries,
	// then cut both: neither side learns how to wait on a half-open tunnel.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

func relay(dst io.Writer, src io.Reader, done chan<- struct{}) {
	_, _ = io.Copy(dst, src)
	if half, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = half.CloseWrite()
	}
	done <- struct{}{}
}

type errNotAllowed string

func (e errNotAllowed) Error() string {
	return "the sandbox's egress policy does not allow " + string(e)
}

// refuse answers a request the proxy will not carry. A refusal by rule is the
// sandbox's to read; anything else is a failure to reach the destination.
func refuse(w http.ResponseWriter, err error) {
	var notAllowed errNotAllowed
	switch {
	case errors.As(err, &notAllowed), errors.Is(err, errInsideGuest), errors.Is(err, errPrivate):
		http.Error(w, err.Error(), http.StatusForbidden)
	default:
		http.Error(w, "could not reach the destination: "+err.Error(), http.StatusBadGateway)
	}
}

// hostPort splits a request's authority. defaultPort stands in for a missing
// port, or with 0 a missing port is an error.
func hostPort(authority string, defaultPort int) (string, int, error) {
	host, portText, err := net.SplitHostPort(authority)
	if err != nil {
		if defaultPort == 0 {
			return "", 0, err
		}
		host, portText = authority, strconv.Itoa(defaultPort)
		// A bare IPv6 address comes in brackets.
		if len(host) > 1 && host[0] == '[' && host[len(host)-1] == ']' {
			host = host[1 : len(host)-1]
		}
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 || host == "" {
		return "", 0, fmt.Errorf("invalid destination %q", authority)
	}
	return host, port, nil
}
