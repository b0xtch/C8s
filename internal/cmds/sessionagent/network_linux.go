//go:build linux

package sessionagent

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// applyNetwork gives the guest's one interface the address, route and MTU
// its host asked for. The request is the whole configuration: the interface
// takes no address of its own making and listens to no router.
func applyNetwork(n *session.HostNetwork) error {
	link, err := guestLink(deviceTimeout)
	if err != nil {
		return err
	}
	name := link.Attrs().Name
	// No router advertisement and no link-local address may add to what the
	// host's request says. A kernel without IPv6 has none of these.
	for key, value := range map[string]string{"accept_ra": "0", "autoconf": "0", "addr_gen_mode": "1"} {
		err := os.WriteFile(filepath.Join("/proc/sys/net/ipv6/conf", name, key), []byte(value), 0)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s %s: %w", name, key, err)
		}
	}
	// The guest announces its address when it takes it. A guest that sends
	// nothing first, as one without DHCP does, is otherwise unknown to its
	// link until someone asks for it, and the first connection to it waits
	// for that.
	if err := os.WriteFile(filepath.Join("/proc/sys/net/ipv4/conf", name, "arp_notify"), []byte("1"), 0); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s arp_notify: %w", name, err)
	}
	if n.MTU != 0 {
		if err := netlink.LinkSetMTU(link, n.MTU); err != nil {
			return fmt.Errorf("%s: MTU %d: %w", name, n.MTU, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("%s: up: %w", name, err)
	}
	prefix, err := netip.ParsePrefix(n.Address)
	if err != nil {
		return err
	}
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: prefix.Addr().AsSlice(), Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())}}
	if prefix.Addr().Is4() {
		// The kernel gives an address from 169.254.0.0/16 link scope and
		// sources nothing beyond the link from it. This is the guest's one
		// address, whatever range its host took it from.
		addr.Scope = int(netlink.SCOPE_UNIVERSE)
	} else {
		// The host numbered this link: there is nobody to detect a duplicate
		// with, and the address is of no use for a second while it is tried.
		addr.Flags = unix.IFA_F_NODAD
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("%s: address %s: %w", name, n.Address, err)
	}
	if n.Gateway == "" {
		return nil
	}
	route := &netlink.Route{LinkIndex: link.Attrs().Index, Gw: net.ParseIP(n.Gateway)}
	if n.OnLink {
		route.Flags = int(netlink.FLAG_ONLINK)
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("%s: route by %s: %w", name, n.Gateway, err)
	}
	return nil
}

// guestLink is the guest's one network device. Its driver may still be
// probing when the launch files are loaded.
func guestLink(wait time.Duration) (netlink.Link, error) {
	for deadline := time.Now().Add(wait); ; time.Sleep(20 * time.Millisecond) {
		links, err := netlink.LinkList()
		if err != nil {
			return nil, err
		}
		var found []netlink.Link
		for _, link := range links {
			// A device with a driver of its own: no loopback, no dummy, no
			// tunnel, none of which a host attached.
			if link.Type() == "device" && link.Attrs().EncapType == "ether" {
				found = append(found, link)
			}
		}
		switch {
		case len(found) == 1:
			return found[0], nil
		case len(found) > 1:
			return nil, fmt.Errorf("this guest has %d network devices, and its host's request names one address", len(found))
		case time.Now().After(deadline):
			return nil, errors.New("the host asks for a network and this guest has no network device")
		}
	}
}
