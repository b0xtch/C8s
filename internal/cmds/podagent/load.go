package podagent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/podcvm"
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

const networkUnitName = "10-c8s-pod.network"

// load copies this boot's launch files off the opkeydata volume and renders
// the host's network request for systemd-networkd. It authenticates nothing:
// the files it copies are verified by Stage, and the network settings are the
// host's to choose because the host is the network.
func load(cfg LoadConfig) error {
	if err := os.MkdirAll(cfg.LaunchDir, 0o700); err != nil {
		return err
	}
	for name, limit := range map[string]int64{podcvm.DocumentFile: podcvm.MaxDocumentSize, podcvm.SignatureFile: 4096} {
		data, err := podcvm.ReadBounded(filepath.Join(cfg.SourceDir, name), limit)
		if err != nil {
			return fmt.Errorf("opkeydata: %w", err)
		}
		if err := fileutil.WriteAtomic(filepath.Join(cfg.LaunchDir, name), data, 0o600); err != nil {
			return err
		}
	}
	host, err := podcvm.ReadHostConfig(filepath.Join(cfg.SourceDir, podcvm.HostConfigFile))
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
func networkUnit(n *podcvm.HostNetwork) string {
	var b strings.Builder
	b.WriteString("# Rendered by c8s pod-agent load from the host's unsigned host.json.\n")
	b.WriteString("[Match]\nType=ether\nKind=!dummy\n\n[Network]\nDHCP=no\nLinkLocalAddressing=no\nIPv6AcceptRA=no\n")
	fmt.Fprintf(&b, "Address=%s\n", n.Address)
	for _, server := range n.DNS {
		fmt.Fprintf(&b, "DNS=%s\n", server)
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
