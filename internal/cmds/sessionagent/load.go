package sessionagent

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// LoadConfig places what Load reads and writes. The defaults are the guest
// image's; tests rebase them.
type LoadConfig struct {
	// SourceDir is the mounted opkeydata volume.
	SourceDir string
	// LaunchDir receives launch.yaml and its signature for the agent.
	LaunchDir string
	// NetworkDir is systemd-networkd's runtime configuration directory.
	NetworkDir string
}

const networkUnitName = "10-c8s-session.network"

// load copies this boot's launch files off the opkeydata volume and renders
// the host's network request for systemd-networkd. It authenticates nothing:
// the files it copies are verified by Stage, and the network settings are the
// host's to choose because the host is the network.
func load(cfg LoadConfig) error {
	if err := os.MkdirAll(cfg.LaunchDir, 0o700); err != nil {
		return err
	}
	for name, limit := range map[string]int64{session.DocumentFile: session.MaxDocumentSize, session.SignatureFile: 4096} {
		data, err := session.ReadBounded(filepath.Join(cfg.SourceDir, name), limit)
		if err != nil {
			return fmt.Errorf("opkeydata: %w", err)
		}
		if err := fileutil.WriteAtomic(filepath.Join(cfg.LaunchDir, name), data, 0o600); err != nil {
			return err
		}
	}
	host, err := session.ReadHostConfig(filepath.Join(cfg.SourceDir, session.HostConfigFile))
	if err != nil {
		return err
	}
	// No host request: the image's DHCP default applies.
	if host == nil || host.Network == nil {
		return nil
	}
	if err := os.MkdirAll(cfg.NetworkDir, 0o755); err != nil {
		return err
	}
	return fileutil.WriteAtomic(filepath.Join(cfg.NetworkDir, networkUnitName), []byte(networkUnit(host.Network)), 0o644)
}

// networkUnit renders a validated host network request. Validation rewrote
// every value from its parsed form, an address or an integer, so none can
// carry a second directive.
func networkUnit(n *session.HostNetwork) string {
	var b strings.Builder
	b.WriteString("# Rendered by c8s session-agent load from the host's unsigned host.json.\n")
	b.WriteString("[Match]\nType=ether\nKind=!dummy\n\n[Network]\nDHCP=no\nLinkLocalAddressing=no\nIPv6AcceptRA=no\n")
	for _, server := range n.DNS {
		fmt.Fprintf(&b, "DNS=%s\n", server)
	}
	fmt.Fprintf(&b, "\n[Address]\nAddress=%s\n", n.Address)
	// networkd gives an address from 169.254.0.0/16 link scope, and the
	// kernel sources nothing beyond the link from such an address: the guest
	// would send to the world from 0.0.0.0. This is the guest's one address,
	// whatever range the host took it from.
	if prefix, err := netip.ParsePrefix(n.Address); err == nil && prefix.Addr().Is4() {
		b.WriteString("Scope=global\n")
	}
	if n.Gateway != "" {
		fmt.Fprintf(&b, "\n[Route]\nGateway=%s\n", n.Gateway)
		if n.OnLink {
			b.WriteString("GatewayOnLink=yes\n")
		}
	}
	if n.MTU != 0 {
		fmt.Fprintf(&b, "\n[Link]\nMTUBytes=%d\n", n.MTU)
	}
	return b.String()
}
