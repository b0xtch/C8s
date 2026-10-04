package sessionagent

import (
	"bufio"
	"encoding/hex"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// rtfGateway is the kernel's flag for a route that goes through a next hop.
const rtfGateway = 0x2

// gateways lists the next hops of the guest's routes: where its host, or
// whatever stands between it and the network, answers.
func gateways() ([]netip.Addr, error) {
	v4, err := readGateways("/proc/net/route", parseRoute4)
	if err != nil {
		return nil, err
	}
	v6, err := readGateways("/proc/net/ipv6_route", parseRoute6)
	if err != nil {
		return nil, err
	}
	return append(v4, v6...), nil
}

// readGateways reads one of the kernel's route tables. A kernel without that
// address family has no such file, and no gateway of that family.
func readGateways(path string, parse func(fields []string) (netip.Addr, bool)) ([]netip.Addr, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []netip.Addr
	lines := bufio.NewScanner(f)
	for lines.Scan() {
		if hop, ok := parse(strings.Fields(lines.Text())); ok {
			out = append(out, hop)
		}
	}
	return out, lines.Err()
}

// parseRoute4 reads one line of /proc/net/route: interface, destination,
// gateway and flags, the addresses as hex in host byte order.
func parseRoute4(fields []string) (netip.Addr, bool) {
	if len(fields) < 4 {
		return netip.Addr{}, false
	}
	flags, err := strconv.ParseUint(fields[3], 16, 32)
	if err != nil || flags&rtfGateway == 0 {
		return netip.Addr{}, false
	}
	raw, err := hex.DecodeString(fields[2])
	if err != nil || len(raw) != 4 {
		return netip.Addr{}, false
	}
	// x86 is little-endian: the kernel prints the address's bytes reversed.
	return netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]}), true
}

// parseRoute6 reads one line of /proc/net/ipv6_route: destination and its
// prefix length, source and its prefix length, next hop, metric, two counters,
// flags and interface.
func parseRoute6(fields []string) (netip.Addr, bool) {
	if len(fields) < 9 {
		return netip.Addr{}, false
	}
	flags, err := strconv.ParseUint(fields[8], 16, 32)
	if err != nil || flags&rtfGateway == 0 {
		return netip.Addr{}, false
	}
	raw, err := hex.DecodeString(fields[4])
	if err != nil || len(raw) != 16 {
		return netip.Addr{}, false
	}
	hop := netip.AddrFrom16([16]byte(raw))
	return hop, !hop.IsUnspecified()
}
