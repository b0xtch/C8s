package sessionagent

import (
	"encoding/json"
	"fmt"
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
	// ResolvConf receives the resolvers the host names. The image's
	// /etc/resolv.conf is a link to it.
	ResolvConf string
	// Network applies the host's network request to the guest's interface.
	// Nil applies nothing.
	Network func(*session.HostNetwork) error
}

// load copies this boot's launch files off the opkeydata volume and applies
// the host's network request. It authenticates nothing: the files it copies
// are verified by Stage, and the network settings are the host's to choose
// because the host is the network.
//
// A guest handed no network request has no network: there is no DHCP client
// in a session guest, and nothing else in it would configure an interface.
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
	if host == nil {
		return nil
	}
	// The agent reads the host's request from here, as it was parsed.
	staged, err := json.Marshal(host)
	if err != nil {
		return err
	}
	if err := fileutil.WriteAtomic(filepath.Join(cfg.LaunchDir, session.HostConfigFile), staged, 0o600); err != nil {
		return err
	}
	if host.Network == nil {
		return nil
	}
	if cfg.ResolvConf != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.ResolvConf), 0o755); err != nil {
			return err
		}
		if err := fileutil.WriteAtomic(cfg.ResolvConf, []byte(resolvConf(host.Network)), 0o644); err != nil {
			return err
		}
	}
	if cfg.Network == nil {
		return nil
	}
	if err := cfg.Network(host.Network); err != nil {
		return fmt.Errorf("apply the host's network request: %w", err)
	}
	return nil
}

// resolvConf renders the resolvers of a validated host network request.
// Validation rewrote every value from its parsed form, an address, so none
// can carry a second line.
func resolvConf(n *session.HostNetwork) string {
	var b strings.Builder
	b.WriteString("# Written by c8s session-agent load from the host's unsigned host.json.\n")
	for _, server := range n.DNS {
		fmt.Fprintf(&b, "nameserver %s\n", server)
	}
	return b.String()
}
