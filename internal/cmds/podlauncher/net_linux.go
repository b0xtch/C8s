//go:build linux

package podlauncher

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

	"github.com/confidential-dot-ai/c8s/pkg/podcvm"
)

const tapName = "c8s-tap0"

// setupTap gives the guest the pod's own interface. It opens a tap, redirects
// every frame between the pod interface and the tap at L2, and returns the
// address the guest must configure, which is the pod's.
//
// The tap is not persistent: it lives exactly as long as the descriptor QEMU
// inherits, so a dead guest leaves nothing behind.
func setupTap(cfg *Config) (*podcvm.HostNetwork, []*os.File, error) {
	link, err := netlink.LinkByName(cfg.Interface)
	if err != nil {
		return nil, nil, fmt.Errorf("pod interface %s: %w", cfg.Interface, err)
	}
	network, err := interfaceNetwork(link)
	if err != nil {
		return nil, nil, err
	}

	tapFD, err := openTap(tapName)
	if err != nil {
		return nil, nil, err
	}
	files := []*os.File{tapFD}
	closeAll := func() {
		for _, f := range files {
			f.Close()
		}
	}
	tap, err := netlink.LinkByName(tapName)
	if err != nil {
		closeAll()
		return nil, nil, err
	}
	if err := netlink.LinkSetMTU(tap, link.Attrs().MTU); err != nil {
		closeAll()
		return nil, nil, fmt.Errorf("set tap MTU: %w", err)
	}
	if err := netlink.LinkSetUp(tap); err != nil {
		closeAll()
		return nil, nil, fmt.Errorf("bring tap up: %w", err)
	}
	for _, pair := range [][2]netlink.Link{{link, tap}, {tap, link}} {
		if err := redirect(pair[0], pair[1]); err != nil {
			closeAll()
			return nil, nil, fmt.Errorf("redirect %s to %s: %w", pair[0].Attrs().Name, pair[1].Attrs().Name, err)
		}
	}
	// vhost-net moves the data path into the host kernel. Without it QEMU
	// still works, copying every packet in user space.
	if vhost, err := os.OpenFile("/dev/vhost-net", os.O_RDWR, 0); err == nil {
		files = append(files, vhost)
	}
	cfg.tap = &tapDevice{mac: link.Attrs().HardwareAddr.String(), vhost: len(files) == 2}
	return network, files, nil
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

// interfaceNetwork reads what the CNI gave the pod: address, default gateway,
// MTU and resolver.
func interfaceNetwork(link netlink.Link) (*podcvm.HostNetwork, error) {
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
		return nil, fmt.Errorf("pod interface %s has no IPv4 address", link.Attrs().Name)
	}
	out := &podcvm.HostNetwork{Address: address.String(), MTU: link.Attrs().MTU, DNS: resolvers("/etc/resolv.conf")}
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
		break
	}
	if err := (&podcvm.HostConfig{Network: out}).Validate(); err != nil {
		return nil, fmt.Errorf("pod network is not expressible to the guest: %w", err)
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
