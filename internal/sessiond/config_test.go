package sessiond

import (
	"fmt"
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

// binder is a binder as a pool's configuration names one.
func binder(digit byte) string { return "sha256:" + strings.Repeat(string(digit), 64) }

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
vmm: {quoteSocket: /run/qgs.socket, confine: "64055", cpus: "2-19,26-43"}
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
	if cfg.Classes["sim"].VCPUs != 4 || cfg.VMM.Confine != "64055" || cfg.VMM.CPUs != "2-19,26-43" {
		t.Fatalf("the configuration: %+v", cfg)
	}

	// A pool watched by nobody names no binder. One that names some keeps
	// them as they are written.
	if len(pool.Binders) != 0 {
		t.Fatalf("a pool that names no binder has %v", pool.Binders)
	}
	watched := strings.Replace(strings.ReplaceAll(validConfig, "LAUNCH", launch), "depth: 2", "depth: 2\n    binders: [\""+binder('a')+"\", \""+binder('b')+"\"]", 1)
	if cfg, err = LoadConfig(writeConfig(t, watched)); err != nil || len(cfg.Pools[0].Binders) != 2 || cfg.Pools[0].Binders[1].Key != binder('b') {
		t.Fatalf("a pool with two binders: %v, %v", cfg, err)
	}
	// A binder named by its key alone watches, and binds nothing unclaimed.
	// One named with authorities may claim a TD with a bind under one of
	// them, and under no other.
	if first := &cfg.Pools[0]; first.binder(binder('a')) == nil || first.binder(binder('c')) != nil || first.binds(binder('a'), binder('d')) {
		t.Fatalf("a pool with two binders that only watch: %+v", first.Binders)
	}
	claiming := strings.Replace(strings.ReplaceAll(validConfig, "LAUNCH", launch), "depth: 2",
		"depth: 2\n    binders:\n      - "+binder('a')+"\n      - key: "+binder('b')+"\n        authorities: [\""+binder('d')+"\", \""+binder('e')+"\"]", 1)
	if cfg, err = LoadConfig(writeConfig(t, claiming)); err != nil {
		t.Fatalf("a pool whose second binder may claim: %v", err)
	}
	if p := &cfg.Pools[0]; len(p.Binders) != 2 || p.binds(binder('a'), binder('d')) || !p.binds(binder('b'), binder('d')) || !p.binds(binder('b'), binder('e')) ||
		p.binds(binder('b'), binder('f')) || p.binds(binder('c'), binder('d')) || p.binds(binder('d'), binder('d')) {
		t.Fatalf("a pool whose second binder may claim under two authorities: %+v", p.Binders)
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
		"a destination with no port":        {"dns: [192.0.2.53]", "reach: [192.0.2.7]"},
		"a destination by name":             {"dns: [192.0.2.53]", "reach: [\"keys.example:8443\"]"},
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
		"VMM CPUs out of order":             {"cpus: \"2-19,26-43\"", "cpus: \"26-43,2-19\""},
		"VMM CPUs that are no list":         {"cpus: \"2-19,26-43\"", "cpus: \"most\""},
		"no state directory":                {"stateDir: state", "stateDir: \"\""},
		"a binder by its name":              {"depth: 2", "depth: 2\n    binders: [orchestrator]"},
		"a binder by a digest too short":    {"depth: 2", "depth: 2\n    binders: [\"sha256:" + strings.Repeat("a", 63) + "\"]"},
		"a binder by a digest in capitals":  {"depth: 2", "depth: 2\n    binders: [\"sha256:" + strings.Repeat("A", 64) + "\"]"},
		"one binder twice":                  {"depth: 2", "depth: 2\n    binders: [\"" + binder('a') + "\", \"" + binder('a') + "\"]"},
		"more binders than a pool takes":    {"depth: 2", "depth: 2\n    binders: [" + strings.Repeat("\""+binder('a')+"\", ", maxBinders+1) + "]"},
		"a binder with no key":              {"depth: 2", "depth: 2\n    binders: [{authorities: [\"" + binder('d') + "\"]}]"},
		"a binder with a field of no kind":  {"depth: 2", "depth: 2\n    binders: [{key: \"" + binder('a') + "\", authority: \"" + binder('d') + "\"}]"},
		"a binder that is a list":           {"depth: 2", "depth: 2\n    binders: [[\"" + binder('a') + "\"]]"},
		"an authority by its name":          {"depth: 2", "depth: 2\n    binders: [{key: \"" + binder('a') + "\", authorities: [acme]}]"},
		"one authority twice":               {"depth: 2", "depth: 2\n    binders: [{key: \"" + binder('a') + "\", authorities: [\"" + binder('d') + "\", \"" + binder('d') + "\"]}]"},
		"one binder twice, as a mapping":    {"depth: 2", "depth: 2\n    binders: [\"" + binder('a') + "\", {key: \"" + binder('a') + "\"}]"},
		"more authorities than one takes":   {"depth: 2", "depth: 2\n    binders: [{key: \"" + binder('a') + "\", authorities: [" + manyAuthorities(maxAuthorities+1) + "]}]"},
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
	// The longest prefix with the last slot of the largest block is still an
	// interface's name.
	for _, network := range []*Network{{}, {TapPrefix: "c8s0123456"}} {
		if name := network.tapName(16383); len(name) > 15 {
			t.Errorf("tap name %s is longer than an interface name may be", name)
		}
	}
}

// A daemon's taps and its table in the packet filter are named for its
// prefix, so that a second daemon on a host has its own and replaces nothing
// of the first's. With none configured both have the names they always had.
func TestTapPrefixNamesADaemonsTapsAndItsTable(t *testing.T) {
	plain := &Network{}
	if plain.tapName(7) != "c8st7" || plain.table() != "c8s_sessions" {
		t.Fatalf("a daemon with no prefix of its own: tap %s, table %s", plain.tapName(7), plain.table())
	}
	same := &Network{TapPrefix: "c8st"}
	if same.tapName(7) != "c8st7" || same.table() != "c8s_sessions" {
		t.Fatalf("a daemon that names the usual prefix: tap %s, table %s", same.tapName(7), same.table())
	}
	second := &Network{TapPrefix: "c8su"}
	if second.tapName(7) != "c8su7" || second.table() != "c8s_sessions_c8su" {
		t.Fatalf("a second daemon: tap %s, table %s", second.tapName(7), second.table())
	}
	rules := second.filterRuleset("eth0", []netip.AddrPort{netip.MustParseAddrPort("192.0.2.7:8443")})
	if !strings.HasPrefix(rules, "table inet c8s_sessions_c8su\ndelete table inet c8s_sessions_c8su\ntable inet c8s_sessions_c8su {\n") {
		t.Fatalf("a second daemon's ruleset replaces another table than its own:\n%s", rules)
	}
	if strings.Contains(rules, "c8st") || strings.Count(rules, `"c8su*"`) < 8 {
		t.Fatalf("a second daemon's rules match other taps than its own:\n%s", rules)
	}
	launch := bundle(t)
	body := func(network string) string {
		return strings.Replace(strings.ReplaceAll(validConfig, "LAUNCH", launch), "network: {mode: tap, guestCIDR: 10.99.0.0/24, dns: [192.0.2.53]}", network, 1)
	}
	cfg, err := LoadConfig(writeConfig(t, body("network: {mode: tap, guestCIDR: 10.99.0.0/24, tapPrefix: c8su}")))
	if err != nil || cfg.Network.tapPrefix() != "c8su" {
		t.Fatalf("a configuration that names a prefix: %v", err)
	}
	for _, bad := range []string{"C8su", "8su", "c8s-u", "c8s_u", "c8s01234567", "c8s u"} {
		if _, err := LoadConfig(writeConfig(t, body("network: {mode: tap, guestCIDR: 10.99.0.0/24, tapPrefix: \""+bad+"\"}"))); err == nil || !strings.Contains(err.Error(), "tapPrefix") {
			t.Errorf("tapPrefix %q: %v", bad, err)
		}
	}
	if _, err := LoadConfig(writeConfig(t, body("network: {mode: user, firstPort: 39000, tapPrefix: c8su}"))); err == nil || !strings.Contains(err.Error(), "belong to mode tap") {
		t.Errorf("a prefix for taps in a mode that has none: %v", err)
	}
}

func TestFilterRuleset(t *testing.T) {
	closed := (&Network{}).filterRuleset("", nil)
	if strings.Contains(closed, "masquerade") || strings.Contains(closed, "accept\n\t\tiifname \"c8st*\" counter drop\n\t}\n}") {
		t.Errorf("with no egress interface a guest's traffic is let out:\n%s", closed)
	}
	open := (&Network{}).filterRuleset("eth0", []netip.AddrPort{netip.MustParseAddrPort("192.0.2.7:8443")})
	for _, rule := range []string{
		`iifname "c8st*" oifname "eth0" accept`,
		`iifname "c8st*" oifname "eth0" masquerade`,
		`iifname "c8st*" oifname "c8st*" counter drop`,
		`iifname "c8st*" fib saddr . iif oif missing counter drop`,
		`iifname "c8st*" ip daddr 192.0.2.7 tcp dport 8443 accept`,
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

// manyAuthorities is n authorities, each another.
func manyAuthorities(n int) string {
	var out []string
	for i := range n {
		out = append(out, fmt.Sprintf("\"sha256:%064x\"", i))
	}
	return strings.Join(out, ", ")
}
