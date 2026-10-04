package sessiond

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

const (
	// tapPrefix starts the name of every TD's tap. The host's packet filter
	// matches on it, so its rules hold for a tap made after they were loaded.
	tapPrefix = "c8st"
	// filterTable is the daemon's table in the host's packet filter.
	filterTable = "c8s_sessions"
)

// tapName is the tap of the TD in slot.
func tapName(slot int) string { return tapPrefix + strconv.Itoa(slot) }

// slotAddresses cuts the four addresses of a slot from the guests' block:
// the host's end of the tap, and the guest's.
func slotAddresses(block netip.Prefix, slot int) (host netip.Addr, guest netip.Prefix, err error) {
	base := block.Addr().As4()
	n := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	n += uint32(slot) * 4
	at := func(i uint32) netip.Addr {
		v := n + i
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	if slot < 0 || !block.Contains(at(3)) {
		return netip.Addr{}, netip.Prefix{}, fmt.Errorf("slot %d is outside %s", slot, block)
	}
	return at(1), netip.PrefixFrom(at(2), 30), nil
}

// slotMAC is the guest's Ethernet address: locally administered, unicast.
func slotMAC(slot int) string {
	return fmt.Sprintf("02:c8:53:%02x:%02x:%02x", byte(slot>>16), byte(slot>>8), byte(slot))
}

// filterRuleset is what the daemon loads into the host's packet filter, as
// one table of its own that replaces any it loaded before.
//
// A guest is a tenant's. From its tap it reaches nothing of the host and no
// other guest, and it sends only from the address its tap was given. Nothing
// from outside the host reaches a guest: connections to one start at the
// daemon. With an egress interface, a guest's traffic may leave on that
// interface alone, under the host's address. reach lists the destinations
// every guest may connect to whatever else is closed, on the host or beyond
// it: a pool's key service.
func filterRuleset(egress string, reach []netip.AddrPort) string {
	taps := `"` + tapPrefix + `*"`
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\ntable inet %s {\n", filterTable, filterTable, filterTable)
	// The counters say what a guest tried: nothing of a tenant's is in them.
	fmt.Fprintf(&b, `	chain prerouting {
		type filter hook prerouting priority raw; policy accept;
		iifname %[1]s fib saddr . iif oif missing counter drop
	}
	chain input {
		type filter hook input priority filter; policy accept;
		iifname %[1]s ct state established,related accept
%[2]s		iifname %[1]s counter drop
	}
	chain forward {
		type filter hook forward priority filter; policy accept;
		iifname %[1]s oifname %[1]s counter drop
		oifname %[1]s ct state established,related accept
		oifname %[1]s counter drop
%[2]s`, taps, opened(taps, reach))
	if egress != "" {
		fmt.Fprintf(&b, "\t\tiifname %s oifname %q accept\n", taps, egress)
	}
	fmt.Fprintf(&b, "\t\tiifname %s counter drop\n\t}\n", taps)
	if egress != "" {
		fmt.Fprintf(&b, `	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		iifname %s oifname %q masquerade
	}
`, taps, egress)
	}
	b.WriteString("}\n")
	return b.String()
}

// opened renders the rules that let a guest's connections to reach pass.
func opened(taps string, reach []netip.AddrPort) string {
	var b strings.Builder
	for _, dest := range reach {
		fmt.Fprintf(&b, "\t\tiifname %s ip daddr %s tcp dport %d accept\n", taps, dest.Addr(), dest.Port())
	}
	return b.String()
}
