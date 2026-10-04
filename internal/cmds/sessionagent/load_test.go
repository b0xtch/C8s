package sessionagent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// applied records the network requests a load applied.
type applied struct{ requests []session.HostNetwork }

func (a *applied) apply(n *session.HostNetwork) error {
	a.requests = append(a.requests, *n)
	return nil
}

func loadFixture(t *testing.T, host string) (LoadConfig, *applied) {
	t.Helper()
	src := t.TempDir()
	files := map[string]string{session.DocumentFile: "schemaVersion: x\n", session.SignatureFile: "c2ln\n"}
	if host != "" {
		files[session.HostConfigFile] = host
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(src, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	network := &applied{}
	return LoadConfig{
		SourceDir: src, LaunchDir: filepath.Join(t.TempDir(), "launch"),
		ResolvConf: filepath.Join(t.TempDir(), "run", "resolv.conf"), Network: network.apply,
	}, network
}

func TestLoadCopiesLaunchFilesAndAppliesNetwork(t *testing.T) {
	cfg, network := loadFixture(t, `{"network":{"address":"10.42.0.12/24","gateway":"10.42.0.1","dns":["10.43.0.10","10.43.0.11"],"mtu":1450}}`)
	if err := load(cfg); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{session.DocumentFile, session.SignatureFile} {
		info, err := os.Stat(filepath.Join(cfg.LaunchDir, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v, %v", name, info, err)
		}
	}
	if len(network.requests) != 1 {
		t.Fatalf("applied %d requests", len(network.requests))
	}
	got := network.requests[0]
	if got.Address != "10.42.0.12/24" || got.Gateway != "10.42.0.1" || got.MTU != 1450 || got.OnLink {
		t.Fatalf("applied %+v", got)
	}
	resolv, err := os.ReadFile(cfg.ResolvConf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(resolv), "\nnameserver 10.43.0.10\nnameserver 10.43.0.11\n") || !strings.HasPrefix(string(resolv), "#") {
		t.Fatalf("resolv.conf:\n%s", resolv)
	}
}

func TestLoadOnLinkGateway(t *testing.T) {
	cfg, network := loadFixture(t, `{"network":{"address":"10.42.0.12/32","gateway":"169.254.1.1","on_link":true}}`)
	if err := load(cfg); err != nil {
		t.Fatal(err)
	}
	if got := network.requests[0]; got.Gateway != "169.254.1.1" || !got.OnLink {
		t.Fatalf("applied %+v", got)
	}
	// A request that names no resolver leaves the guest none.
	resolv, err := os.ReadFile(cfg.ResolvConf)
	if err != nil || strings.Contains(string(resolv), "nameserver") {
		t.Fatalf("resolv.conf %q, %v", resolv, err)
	}
}

// What is applied is the parsed value in canonical form, whatever spelling
// the host chose.
func TestLoadAppliesCanonicalAddresses(t *testing.T) {
	cfg, network := loadFixture(t, `{"network":{"address":"FD00:0:0:0:0:0:0:2/64","gateway":"FD00:0:0:0:0:0:0:1","dns":["FD00::0:53"]}}`)
	if err := load(cfg); err != nil {
		t.Fatal(err)
	}
	if got := network.requests[0]; got.Address != "fd00::2/64" || got.Gateway != "fd00::1" {
		t.Fatalf("applied %+v", got)
	}
	resolv, _ := os.ReadFile(cfg.ResolvConf)
	if !strings.Contains(string(resolv), "nameserver fd00::53\n") {
		t.Fatalf("resolv.conf:\n%s", resolv)
	}
}

// A request the kernel refuses ends the load: a guest whose host asked for a
// network and that has none is not the guest its host launched.
func TestLoadFailsWhenTheNetworkDoesNotApply(t *testing.T) {
	cfg, _ := loadFixture(t, `{"network":{"address":"10.42.0.12/24"}}`)
	cfg.Network = func(*session.HostNetwork) error { return errors.New("no network device") }
	if err := load(cfg); err == nil || !strings.Contains(err.Error(), "no network device") {
		t.Fatalf("load: %v", err)
	}
	// A load with nothing to apply a network with stages the files and stops.
	cfg, _ = loadFixture(t, `{"network":{"address":"10.42.0.12/24"}}`)
	cfg.Network, cfg.ResolvConf = nil, ""
	if err := load(cfg); err != nil {
		t.Fatal(err)
	}
}

// The agent reads the host's request where load staged it, as load parsed
// it: the port its launcher carries the key service's connection on.
func TestLoadStagesTheHostsRequestForTheAgent(t *testing.T) {
	cfg, _ := loadFixture(t, `{"key_service_port": 70123, "network":{"address":"010.42.0.12/24"}}`)
	if err := load(cfg); err == nil {
		t.Fatal("an address with a leading zero was taken")
	}
	if _, err := os.Stat(filepath.Join(cfg.LaunchDir, session.HostConfigFile)); err == nil {
		t.Fatal("a refused request was staged")
	}
	for name, tc := range map[string]struct {
		host    string
		port    uint32
		network bool
	}{
		"a relay port alone":      {`{"key_service_port": 70123}`, 70123, false},
		"a relay port and a link": {`{"network":{"address":"10.42.0.12/24"},"key_service_port":1024}`, 1024, true},
		"a link alone":            {`{"network":{"address":"10.42.0.12/24"}}`, 0, true},
	} {
		cfg, network := loadFixture(t, tc.host)
		if err := load(cfg); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		staged, err := session.ReadHostConfig(filepath.Join(cfg.LaunchDir, session.HostConfigFile))
		if err != nil || staged == nil {
			t.Fatalf("%s: the staged request: %v, %v", name, staged, err)
		}
		if staged.KeyServicePort != tc.port {
			t.Errorf("%s: the agent would dial port %d, want %d", name, staged.KeyServicePort, tc.port)
		}
		if (len(network.requests) == 1) != tc.network {
			t.Errorf("%s: %d network requests applied", name, len(network.requests))
		}
	}
	// A guest handed no request stages none.
	cfg, _ = loadFixture(t, "")
	if err := load(cfg); err != nil {
		t.Fatal(err)
	}
	if staged, err := session.ReadHostConfig(filepath.Join(cfg.LaunchDir, session.HostConfigFile)); err != nil || staged != nil {
		t.Fatalf("no host.json staged %v, %v", staged, err)
	}
}

func TestLoadWithoutANetworkRequestAppliesNone(t *testing.T) {
	for name, host := range map[string]string{"no host.json": "", "empty request": `{}`} {
		cfg, network := loadFixture(t, host)
		if err := load(cfg); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(network.requests) != 0 {
			t.Fatalf("%s: a network was applied", name)
		}
		if _, err := os.Stat(cfg.ResolvConf); err == nil {
			t.Fatalf("%s: resolvers were written", name)
		}
	}
}

// host.json is hostile input. A value that is not exactly an address must
// never reach the kernel or a resolver file, where a newline would be a new
// line of configuration.
func TestLoadRejectsHostileHostConfig(t *testing.T) {
	for name, host := range map[string]string{
		"directive injection":     `{"network":{"address":"10.0.0.2/24\nDNS=6.6.6.6"}}`,
		"hostname as address":     `{"network":{"address":"evil.example/24"}}`,
		"gateway outside prefix":  `{"network":{"address":"10.0.0.2/24","gateway":"192.168.1.1"}}`,
		"gateway of other family": `{"network":{"address":"10.0.0.2/24","gateway":"fe80::1","on_link":true}}`,
		"dns injection":           `{"network":{"address":"10.0.0.2/24","dns":["1.1.1.1\nnameserver 6.6.6.6"]}}`,
		// netip takes any bytes after "%" as the zone of an IPv6 address.
		"line in a resolver's zone": `{"network":{"address":"10.0.0.2/24","dns":["fe80::1%x\noptions rotate"]}}`,
		"line in a gateway's zone":  `{"network":{"address":"fd00::2/64","gateway":"fe80::1%eth0\nx","on_link":true}}`,
		"zoned resolver":            `{"network":{"address":"10.0.0.2/24","dns":["fe80::1%eth0"]}}`,
		"oversized":                 `{"network":{"address":"10.0.0.2/24"},"pad":"` + strings.Repeat("x", 17*1024) + `"}`,
		"too many resolvers":        `{"network":{"address":"10.0.0.2/24","dns":["1.1.1.1","1.0.0.1","8.8.8.8","8.8.4.4"]}}`,
		"absurd mtu":                `{"network":{"address":"10.0.0.2/24","mtu":9000000}}`,
		"unknown field":             `{"network":{"address":"10.0.0.2/24"},"exec":"/bin/sh"}`,
		"trailing document":         `{}{"network":{"address":"10.0.0.2/24"}}`,
		"multicast address":         `{"network":{"address":"224.0.0.1/24"}}`,
		// The kernel reads the largest port as any port.
		"relay port that is any port": `{"key_service_port":4294967295}`,
		"relay port beyond the range": `{"key_service_port":4294967296}`,
		"negative relay port":         `{"key_service_port":-1}`,
		"relay port as text":          `{"key_service_port":"4050"}`,
		"relay port with a fraction":  `{"key_service_port":4050.5}`,
	} {
		t.Run(name, func(t *testing.T) {
			cfg, network := loadFixture(t, host)
			if err := load(cfg); err == nil {
				t.Fatal("accepted")
			}
			if len(network.requests) != 0 {
				t.Fatal("a refused host config still reached the network")
			}
			if _, err := os.Stat(cfg.ResolvConf); err == nil {
				t.Fatal("a refused host config still wrote resolvers")
			}
			if _, err := os.Stat(filepath.Join(cfg.LaunchDir, session.HostConfigFile)); err == nil {
				t.Fatal("a refused host config was still staged for the agent")
			}
		})
	}
}

func TestLoadRequiresTheLaunchDocument(t *testing.T) {
	cfg, _ := loadFixture(t, "")
	if err := os.Remove(filepath.Join(cfg.SourceDir, session.SignatureFile)); err != nil {
		t.Fatal(err)
	}
	if err := load(cfg); err == nil {
		t.Fatal("loaded a volume with no signature")
	}
}

func TestQGSCodec(t *testing.T) {
	report := make([]byte, tdReportSize)
	req, err := qgsRequest(report)
	if err != nil || len(req) != 4+16+8+tdReportSize {
		t.Fatalf("request is %d bytes, %v", len(req), err)
	}
	if _, err := qgsRequest(report[:10]); err == nil {
		t.Fatal("accepted a short TDREPORT")
	}
	quote := []byte("quote-bytes")
	body := func(major uint16, kind, declared, code, idSize, quoteSize uint32, tail []byte) []byte {
		b := make([]byte, 24, 24+len(tail))
		b[0], b[1] = byte(major), byte(major>>8)
		put := func(off int, v uint32) {
			b[off], b[off+1], b[off+2], b[off+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
		}
		put(4, kind)
		put(8, declared)
		put(12, code)
		put(16, idSize)
		put(20, quoteSize)
		return append(b, tail...)
	}
	n := uint32(24 + len(quote))
	got, err := qgsQuote(body(1, qgsGetQuoteResp, n, 0, 0, uint32(len(quote)), quote))
	if err != nil || string(got) != string(quote) {
		t.Fatalf("quote = %q, %v", got, err)
	}
	withID := append([]byte("idid"), quote...)
	got, err = qgsQuote(body(1, qgsGetQuoteResp, n+4, 0, 4, uint32(len(quote)), withID))
	if err != nil || string(got) != string(quote) {
		t.Fatalf("quote after id list = %q, %v", got, err)
	}
	for name, b := range map[string][]byte{
		"short":                make([]byte, 10),
		"wrong major":          body(2, qgsGetQuoteResp, n, 0, 0, uint32(len(quote)), quote),
		"wrong type":           body(1, qgsGetQuoteReq, n, 0, 0, uint32(len(quote)), quote),
		"size mismatch":        body(1, qgsGetQuoteResp, n+1, 0, 0, uint32(len(quote)), quote),
		"error code":           body(1, qgsGetQuoteResp, n, 0xe011, 0, uint32(len(quote)), quote),
		"empty quote":          body(1, qgsGetQuoteResp, 24, 0, 0, 0, nil),
		"quote past the end":   body(1, qgsGetQuoteResp, n, 0, 0, uint32(len(quote))+1, quote),
		"id list past the end": body(1, qgsGetQuoteResp, n, 0, 0xffffffff, uint32(len(quote)), quote),
	} {
		if _, err := qgsQuote(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestClaimsFromTDReport(t *testing.T) {
	report := make([]byte, tdReportSize)
	for i := range report {
		report[i] = byte(i)
	}
	// Clear the attributes so the debug bit is off.
	for i := tdAttributes; i < tdAttributes+8; i++ {
		report[i] = 0
	}
	res, err := claimsFromTDReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if debug, err := res.Claims.DebugEnabled(); err != nil || debug {
		t.Fatalf("debug = %v, %v", debug, err)
	}
	mrtd, err := res.Claims.LaunchMeasurement()
	if err != nil || mrtd[0] != byte(tdMRTD%256) || len(mrtd) != 48 {
		t.Fatalf("MRTD = %x, %v", mrtd, err)
	}
	for i := 0; i < 4; i++ {
		rtmr, err := res.Claims.RTMR(i)
		if err != nil || rtmr[0] != byte((tdRTMR0+i*48)%256) {
			t.Fatalf("RTMR[%d] = %x, %v", i, rtmr, err)
		}
	}
	report[tdAttributes] |= 1
	res, _ = claimsFromTDReport(report)
	if debug, _ := res.Claims.DebugEnabled(); !debug {
		t.Fatal("the debug attribute was not reported")
	}
	if _, err := claimsFromTDReport(report[:100]); err == nil {
		t.Fatal("accepted a short TDREPORT")
	}
}
