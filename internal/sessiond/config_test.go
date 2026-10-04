package sessiond

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/sessionsim"
)

// bundle is a launch bundle of a pool named sim, of class sim.
func bundle(t *testing.T) string {
	t.Helper()
	return filepath.Dir(sessionsim.NewGuest(t, nil).LaunchKeyPath)
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "daemon.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const validConfig = `
listen: 127.0.0.1:7443
host: host-a
stateDir: state
capacity: 8
tls: {cert: pki/server.pem, key: pki/server.key, clientCA: pki/ca.pem}
network: {mode: tap, guestCIDR: 10.99.0.0/24, dns: [192.0.2.53]}
vmm: {quoteSocket: /run/qgs.socket, confine: "64055"}
classes:
  sim: {vcpus: 4, memory: 16G, lowMemory: 512M, scratch: 8G}
pools:
  - imageDir: image
    launchDir: LAUNCH
    depth: 2
    bindGrace: 45s
`

func TestLoadConfig(t *testing.T) {
	launch := bundle(t)
	path := writeConfig(t, strings.ReplaceAll(validConfig, "LAUNCH", launch))
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	pool := cfg.Pools[0]
	if cfg.StateDir != filepath.Join(dir, "state") || cfg.TLS.Cert != filepath.Join(dir, "pki/server.pem") || pool.ImageDir != filepath.Join(dir, "image") {
		t.Fatalf("relative paths are not taken from the file's directory: %+v", cfg)
	}
	if pool.Name() != "sim" || pool.class != "sim" || pool.platform != "tdx" || time.Duration(pool.BindGrace) != 45*time.Second {
		t.Fatalf("the pool: %+v", pool)
	}
	if cfg.Classes["sim"].VCPUs != 4 || cfg.VMM.Confine != "64055" {
		t.Fatalf("the configuration: %+v", cfg)
	}

	// A pool with no grace of its own gets the default.
	short := strings.ReplaceAll(strings.ReplaceAll(validConfig, "LAUNCH", launch), "    bindGrace: 45s\n", "")
	if cfg, err = LoadConfig(writeConfig(t, short)); err != nil || time.Duration(cfg.Pools[0].BindGrace) != DefaultBindGrace {
		t.Fatalf("the default grace: %v, %v", cfg, err)
	}
}

func TestLoadConfigRefuses(t *testing.T) {
	launch := bundle(t)
	// A bundle whose signature does not fit its document.
	forged := t.TempDir()
	for _, name := range []string{session.PubkeyFile, session.DocumentFile, session.SignatureFile} {
		data, err := os.ReadFile(filepath.Join(launch, name))
		if err != nil {
			t.Fatal(err)
		}
		if name == session.DocumentFile {
			data = append(data, '\n')
		}
		if err := os.WriteFile(filepath.Join(forged, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, change := range map[string][2]string{
		"an unknown field":                  {"capacity: 8", "capacity: 8\nsecret: yes"},
		"no capacity":                       {"capacity: 8", "capacity: 0"},
		"pools deeper than the capacity":    {"depth: 2", "depth: 9"},
		"a guest block too small":           {"10.99.0.0/24", "10.99.0.0/28"},
		"a guest block that is no network":  {"10.99.0.0/24", "10.99.0.7/24"},
		"an IPv6 guest block":               {"10.99.0.0/24", "fd00::/64"},
		"an unknown network mode":           {"mode: tap", "mode: bridge"},
		"a port in tap mode":                {"mode: tap", "firstPort: 30000, mode: tap"},
		"four resolvers":                    {"dns: [192.0.2.53]", "dns: [192.0.2.1, 192.0.2.2, 192.0.2.3, 192.0.2.4]"},
		"a class the host does not offer":   {"  sim: {vcpus: 4", "  other: {vcpus: 4"},
		"memory with no unit":               {"memory: 16G", "memory: \"16\""},
		"no vCPU":                           {"vcpus: 4", "vcpus: 0"},
		"a grace of a day":                  {"bindGrace: 45s", "bindGrace: 24h"},
		"a grace that is no duration":       {"bindGrace: 45s", "bindGrace: soon"},
		"no client authority":               {", clientCA: pki/ca.pem", ""},
		"a launch bundle that is not there": {"LAUNCH", "/nonexistent"},
		"a launch bundle with a forged doc": {"LAUNCH", forged},
		"the same pool twice":               {"pools:", "pools:\n  - {imageDir: image, launchDir: LAUNCH, depth: 1}"},
		"a negative depth":                  {"depth: 2", "depth: -1"},
		"no listen address":                 {"listen: 127.0.0.1:7443", "listen: \"\""},
		"no state directory":                {"stateDir: state", "stateDir: \"\""},
	} {
		body := strings.Replace(validConfig, change[0], change[1], 1)
		if body == validConfig {
			t.Fatalf("%s: the change did not apply", name)
		}
		if _, err := LoadConfig(writeConfig(t, strings.ReplaceAll(body, "LAUNCH", launch))); err == nil {
			t.Errorf("a configuration with %s was accepted", name)
		}
	}
	user := strings.Replace(validConfig, "network: {mode: tap, guestCIDR: 10.99.0.0/24, dns: [192.0.2.53]}", "network: {mode: user, firstPort: 65530}", 1)
	if _, err := LoadConfig(writeConfig(t, strings.ReplaceAll(user, "LAUNCH", launch))); err == nil {
		t.Error("loopback ports past 65535 were accepted")
	}
}

func TestSlotAddresses(t *testing.T) {
	block := netip.MustParsePrefix("10.99.0.0/24")
	for slot, want := range map[int][2]string{
		0:  {"10.99.0.1", "10.99.0.2/30"},
		1:  {"10.99.0.5", "10.99.0.6/30"},
		63: {"10.99.0.253", "10.99.0.254/30"},
	} {
		host, guest, err := slotAddresses(block, slot)
		if err != nil || host.String() != want[0] || guest.String() != want[1] {
			t.Errorf("slot %d: host %s, guest %s, %v", slot, host, guest, err)
		}
	}
	for _, slot := range []int{-1, 64, 1 << 20} {
		if _, _, err := slotAddresses(block, slot); err == nil {
			t.Errorf("slot %d fits in %s", slot, block)
		}
	}
	// A block that crosses an octet.
	host, guest, err := slotAddresses(netip.MustParsePrefix("10.99.0.0/16"), 64)
	if err != nil || host.String() != "10.99.1.1" || guest.String() != "10.99.1.2/30" {
		t.Errorf("slot 64 of a /16: host %s, guest %s, %v", host, guest, err)
	}
	if a, b := slotMAC(0), slotMAC(0x01ffff); a != "02:c8:53:00:00:00" || b != "02:c8:53:01:ff:ff" {
		t.Errorf("slot MACs %s and %s", a, b)
	}
	if name := tapName(16383); len(name) > 15 {
		t.Errorf("tap name %s is longer than an interface name may be", name)
	}
}

func TestFilterRuleset(t *testing.T) {
	closed := filterRuleset("")
	if strings.Contains(closed, "masquerade") || strings.Contains(closed, "accept\n\t\tiifname \"c8st*\" counter drop\n\t}\n}") {
		t.Errorf("with no egress interface a guest's traffic is let out:\n%s", closed)
	}
	open := filterRuleset("eth0")
	for _, rule := range []string{
		`iifname "c8st*" oifname "eth0" accept`,
		`iifname "c8st*" oifname "eth0" masquerade`,
		`iifname "c8st*" oifname "c8st*" counter drop`,
		`iifname "c8st*" fib saddr . iif oif missing counter drop`,
	} {
		if !strings.Contains(open, rule) {
			t.Errorf("the ruleset lacks %q:\n%s", rule, open)
		}
	}
	// The egress rule comes before the drop that ends the chain.
	if strings.Index(open, `oifname "eth0" accept`) > strings.LastIndex(open, `iifname "c8st*" counter drop`) {
		t.Errorf("the egress rule sits behind the drop:\n%s", open)
	}
}
