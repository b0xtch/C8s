//go:build linux

package sessionlauncher

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

const tapName = "c8s-tap0"

// setupTap gives the guest an interface of the launcher's network namespace,
// such as a pod's own. It opens a tap, redirects every frame between that
// interface and the tap at L2, and returns the address and MAC the guest
// must take, which are the interface's, with the tap and
// vhost-net when the host has it.
//
// The tap is not persistent: it lives exactly as long as the descriptor QEMU
// inherits, so a dead guest leaves nothing behind.
func setupTap(cfg *Config) (_ *session.HostNetwork, mac string, tapFile, vhost *os.File, _ error) {
	link, err := netlink.LinkByName(cfg.Interface)
	if err != nil {
		return nil, "", nil, nil, fmt.Errorf("interface %s: %w", cfg.Interface, err)
	}
	network, err := interfaceNetwork(link)
	if err != nil {
		return nil, "", nil, nil, err
	}

	tapFile, err = openTap(tapName)
	if err != nil {
		return nil, "", nil, nil, err
	}
	fail := func(err error) (*session.HostNetwork, string, *os.File, *os.File, error) {
		tapFile.Close()
		return nil, "", nil, nil, err
	}
	tap, err := netlink.LinkByName(tapName)
	if err != nil {
		return fail(err)
	}
	if err := netlink.LinkSetMTU(tap, link.Attrs().MTU); err != nil {
		return fail(fmt.Errorf("set tap MTU: %w", err))
	}
	if err := netlink.LinkSetUp(tap); err != nil {
		return fail(fmt.Errorf("bring tap up: %w", err))
	}
	for _, pair := range [][2]netlink.Link{{link, tap}, {tap, link}} {
		if err := redirect(pair[0], pair[1]); err != nil {
			return fail(fmt.Errorf("redirect %s to %s: %w", pair[0].Attrs().Name, pair[1].Attrs().Name, err))
		}
	}
	// vhost-net moves the data path into the host kernel. Without it QEMU
	// still works, copying every packet in user space.
	if vhost, err = os.OpenFile("/dev/vhost-net", os.O_RDWR, 0); err != nil {
		vhost = nil
	}
	return network, link.Attrs().HardwareAddr.String(), tapFile, vhost, nil
}

// VHOST_VSOCK_SET_GUEST_CID, which x/sys does not carry.
const vhostVsockSetGuestCID = 0x4008af60

// reserveVsock opens a vhost-vsock device and gives it a context id that no
// other guest on the host holds. The kernel is the allocator: it refuses an
// id in use, so two launchers can never share one, with nothing between them
// to coordinate. QEMU inherits the device with its id already set.
func reserveVsock() (*os.File, uint32, error) {
	device, err := os.OpenFile("/dev/vhost-vsock", os.O_RDWR, 0)
	if err != nil {
		return nil, 0, err
	}
	cid, err := pickCID(func(cid uint64) error {
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, device.Fd(), vhostVsockSetGuestCID, uintptr(unsafe.Pointer(&cid)))
		if errno != 0 {
			return errno
		}
		return nil
	})
	if err != nil {
		device.Close()
		return nil, 0, err
	}
	return device, cid, nil
}

// openTap creates a single-queue tap with virtio headers, the layout QEMU's
// virtio-net expects of an inherited descriptor.
func openTap(name string) (*os.File, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	var req struct {
		name  [unix.IFNAMSIZ]byte
		flags uint16
		_     [22]byte
	}
	copy(req.name[:unix.IFNAMSIZ-1], name)
	req.flags = unix.IFF_TAP | unix.IFF_NO_PI | unix.IFF_VNET_HDR
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&req))); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("create tap %s: %w", name, errno)
	}
	return os.NewFile(uintptr(fd), name), nil
}

// redirect steals every frame arriving on from and transmits it on to.
func redirect(from, to netlink.Link) error {
	qdisc := &netlink.Ingress{QdiscAttrs: netlink.QdiscAttrs{
		LinkIndex: from.Attrs().Index, Parent: netlink.HANDLE_INGRESS, Handle: netlink.MakeHandle(0xffff, 0),
	}}
	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("ingress qdisc: %w", err)
	}
	filter := &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: from.Attrs().Index, Parent: netlink.MakeHandle(0xffff, 0),
			Priority: 1, Protocol: unix.ETH_P_ALL,
		},
		Actions: []netlink.Action{netlink.NewMirredAction(to.Attrs().Index)},
	}
	return netlink.FilterAdd(filter)
}

// interfaceNetwork reads what the interface was given: address, default gateway,
// MTU and resolver.
func interfaceNetwork(link netlink.Link) (*session.HostNetwork, error) {
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	var address *net.IPNet
	for _, a := range addrs {
		if a.IP.IsGlobalUnicast() {
			address = a.IPNet
			break
		}
	}
	if address == nil {
		return nil, fmt.Errorf("interface %s has no IPv4 address", link.Attrs().Name)
	}
	out := &session.HostNetwork{Address: address.String(), MTU: link.Attrs().MTU, DNS: resolvers("/etc/resolv.conf")}
	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	for _, r := range routes {
		if r.Gw == nil || (r.Dst != nil && !r.Dst.IP.IsUnspecified()) {
			continue
		}
		out.Gateway = r.Gw.String()
		prefix, err := netip.ParsePrefix(out.Address)
		gw, ok := netip.AddrFromSlice(r.Gw.To4())
		out.OnLink = err == nil && ok && !prefix.Masked().Contains(gw)
		// An overlay CNI leaves the link at 1500 and puts the tunnel's smaller
		// MTU on the route. The guest has one link and one route, so it takes
		// the smaller value as its link MTU.
		if r.MTU > 0 && r.MTU < out.MTU {
			out.MTU = r.MTU
		}
		break
	}
	if err := (&session.HostConfig{Network: out}).Validate(); err != nil {
		return nil, fmt.Errorf("the interface's network is not expressible to the guest: %w", err)
	}
	return out, nil
}

func resolvers(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	for scanner := bufio.NewScanner(f); scanner.Scan() && len(out) < 3; {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[0] == "nameserver" {
			if addr, err := netip.ParseAddr(fields[1]); err == nil && !addr.IsLoopback() {
				out = append(out, addr.String())
			}
		}
	}
	return out
}
