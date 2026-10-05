package session

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"net/netip"
	"regexp"
	"strconv"
)

// HostConfigFile is the unsigned file the launcher places beside the signed
// launch document. It carries only what the host decides anyway: how the guest
// reaches the network, its key service and Intel's documents. Nothing in it
// is trusted, and nothing in it can change what the guest measures or who may
// drive it.
const HostConfigFile = "host.json"

const maxHostConfigSize = 16 * 1024

// HostConfig is the host-chosen runtime configuration of one guest.
type HostConfig struct {
	Network *HostNetwork `json:"network,omitempty"`
	// KeyServicePort is the vsock port of the host on which the guest's
	// launcher carries a connection to the key service the launch document
	// pins. Zero is none: the guest dials the key service's address itself.
	KeyServicePort uint32 `json:"key_service_port,omitempty"`
	// CollateralPort is the vsock port of the host on which the guest's
	// launcher answers with Intel's documents for the guest's platform. The
	// guest opens a connection, says one line, its CollateralPlatform as
	// JSON, and reads until the host is done: a CollateralResponse, which it
	// keeps unread as its answer to PathCollateral. An answer of no bytes is
	// a host that has none now. Zero is no port: the guest serves none, and
	// its verifiers ask Intel.
	CollateralPort uint32 `json:"collateral_port,omitempty"`
	// VendorPorts are vsock ports of the host on which the guest's launcher
	// carries a connection to the vendor's service, by the service's
	// host:port (see VendorServices). They are for a guest that judges
	// others' evidence and has no network device: a key service replica. Its
	// TLS session on such a connection ends at the vendor, so the launcher
	// can keep a document from the guest and can give it none.
	VendorPorts map[string]uint32 `json:"vendor_ports,omitempty"`
	// EndPort is the vsock port of the host on which the guest's launcher
	// takes the guest's last word: how far it had come and why it ends, one
	// message of the disclosure schema, which the guest's init sends as the
	// guest ends itself. Zero is no port: the guest then ends without a word.
	EndPort uint32 `json:"end_port,omitempty"`
}

// maxVendorPorts bounds the services a host names roads to.
const maxVendorPorts = 8

// HostNetwork is a static address for the guest's one interface. Absent, the
// guest configures no interface: it has no DHCP client.
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
	// The kernel reads this one as any port.
	if c.KeyServicePort == math.MaxUint32 {
		return fmt.Errorf("key_service_port %d is no port", c.KeyServicePort)
	}
	if c.CollateralPort == math.MaxUint32 {
		return fmt.Errorf("collateral_port %d is no port", c.CollateralPort)
	}
	if c.EndPort == math.MaxUint32 {
		return fmt.Errorf("end_port %d is no port", c.EndPort)
	}
	if len(c.VendorPorts) > maxVendorPorts {
		return fmt.Errorf("vendor_ports names more than %d services", maxVendorPorts)
	}
	for service, port := range c.VendorPorts {
		host, number, err := net.SplitHostPort(service)
		if n, numErr := strconv.ParseUint(number, 10, 16); err != nil || numErr != nil || n == 0 || !hostNameRE.MatchString(host) {
			return fmt.Errorf("vendor_ports names %q, which is no host name and port", service)
		}
		if port == 0 || port == math.MaxUint32 {
			return fmt.Errorf("vendor_ports gives %s port %d, which is no port", service, port)
		}
	}
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

// hostNameRE is a DNS name in lowercase: labels of letters, digits and inner
// hyphens.
var hostNameRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

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
