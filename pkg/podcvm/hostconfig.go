package podcvm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
)

// HostConfigFile is the unsigned file the launcher places beside the signed
// launch document. It carries only what the host decides anyway: how the guest
// reaches the network. Nothing in it is trusted, and nothing in it can change
// what the guest measures or who may drive it.
const HostConfigFile = "host.json"

const maxHostConfigSize = 16 * 1024

// HostConfig is the host-chosen runtime configuration of one guest.
type HostConfig struct {
	Network *HostNetwork `json:"network,omitempty"`
}

// HostNetwork is a static address for the guest's one interface. Absent, the
// guest falls back to DHCP.
type HostNetwork struct {
	// Address is the interface address in CIDR form.
	Address string `json:"address"`
	Gateway string `json:"gateway,omitempty"`
	// OnLink routes to the gateway directly, for a gateway outside Address's
	// prefix (the point-to-point layouts several CNIs use).
	OnLink bool     `json:"on_link,omitempty"`
	DNS    []string `json:"dns,omitempty"`
	MTU    int      `json:"mtu,omitempty"`
}

// ReadHostConfig reads and parses the host.json at path. A missing file is no
// host request at all and yields nil.
func ReadHostConfig(path string) (*HostConfig, error) {
	data, err := ReadBounded(path, maxHostConfigSize)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return ParseHostConfig(data)
}

// ParseHostConfig strictly parses host.json. Every field is validated as the
// hostile input it is.
func ParseHostConfig(data []byte) (*HostConfig, error) {
	if len(data) == 0 || len(data) > maxHostConfigSize {
		return nil, fmt.Errorf("host configuration must contain 1..%d bytes", maxHostConfigSize)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg HostConfig
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode host configuration: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("host configuration contains trailing data")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks every address and bound, and rewrites each address in its
// canonical form. What a consumer later renders is then the value that was
// parsed, never the string the host wrote: netip accepts any bytes after an
// IPv6 zone's "%", a newline and a second directive included.
func (c *HostConfig) Validate() error {
	n := c.Network
	if n == nil {
		return nil
	}
	prefix, err := netip.ParsePrefix(n.Address)
	if err != nil || !prefix.Addr().IsValid() || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
		return fmt.Errorf("network.address %q is not a unicast address in CIDR form", n.Address)
	}
	n.Address = prefix.String()
	if n.Gateway != "" {
		gw, err := parseHostAddr(n.Gateway)
		if err != nil || gw.Is4() != prefix.Addr().Is4() {
			return fmt.Errorf("network.gateway %q is not a unicast address of the interface's family", n.Gateway)
		}
		if !n.OnLink && !prefix.Masked().Contains(gw) {
			return fmt.Errorf("network.gateway %s is outside %s and on_link is not set", gw, prefix.Masked())
		}
		n.Gateway = gw.String()
	} else if n.OnLink {
		return fmt.Errorf("network.on_link needs a gateway")
	}
	if len(n.DNS) > 3 {
		return fmt.Errorf("network.dns lists more than 3 servers")
	}
	for i, server := range n.DNS {
		addr, err := parseHostAddr(server)
		if err != nil {
			return fmt.Errorf("network.dns %q is not a unicast address", server)
		}
		n.DNS[i] = addr.String()
	}
	if n.MTU != 0 && (n.MTU < 576 || n.MTU > 65535) {
		return fmt.Errorf("network.mtu must be 576..65535")
	}
	return nil
}

// parseHostAddr accepts a plain unicast address: no zone, which is free text.
func parseHostAddr(s string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, err
	}
	if addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() {
		return netip.Addr{}, fmt.Errorf("%q is not a plain unicast address", s)
	}
	return addr, nil
}
