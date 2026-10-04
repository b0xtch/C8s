package sessionagent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

func loadFixture(t *testing.T, host string) LoadConfig {
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
	return LoadConfig{SourceDir: src, LaunchDir: filepath.Join(t.TempDir(), "launch"), NetworkDir: filepath.Join(t.TempDir(), "network")}
}

func TestLoadCopiesLaunchFilesAndRendersNetwork(t *testing.T) {
	cfg := loadFixture(t, `{"network":{"address":"10.42.0.12/24","gateway":"10.42.0.1","dns":["10.43.0.10"],"mtu":1450}}`)
	if err := load(cfg); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{session.DocumentFile, session.SignatureFile} {
		info, err := os.Stat(filepath.Join(cfg.LaunchDir, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v, %v", name, info, err)
		}
	}
	unit, err := os.ReadFile(filepath.Join(cfg.NetworkDir, networkUnitName))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[Address]\nAddress=10.42.0.12/24\nScope=global\n", "Gateway=10.42.0.1\n", "DNS=10.43.0.10\n", "MTUBytes=1450\n", "DHCP=no\n"} {
		if !strings.Contains(string(unit), want) {
			t.Fatalf("network unit lacks %q:\n%s", want, unit)
		}
	}
	if strings.Contains(string(unit), "GatewayOnLink") {
		t.Fatalf("an in-prefix gateway was marked on-link:\n%s", unit)
	}
}

func TestLoadOnLinkGateway(t *testing.T) {
	cfg := loadFixture(t, `{"network":{"address":"10.42.0.12/32","gateway":"169.254.1.1","on_link":true}}`)
	if err := load(cfg); err != nil {
		t.Fatal(err)
	}
	unit, _ := os.ReadFile(filepath.Join(cfg.NetworkDir, networkUnitName))
	if !strings.Contains(string(unit), "Gateway=169.254.1.1\nGatewayOnLink=yes\n") {
		t.Fatalf("unit:\n%s", unit)
	}
}

// What reaches the unit is the parsed value in canonical form, whatever
// spelling the host chose.
func TestLoadRendersCanonicalAddresses(t *testing.T) {
	cfg := loadFixture(t, `{"network":{"address":"FD00:0:0:0:0:0:0:2/64","gateway":"FD00:0:0:0:0:0:0:1","dns":["FD00::0:53"]}}`)
	if err := load(cfg); err != nil {
		t.Fatal(err)
	}
	unit, _ := os.ReadFile(filepath.Join(cfg.NetworkDir, networkUnitName))
	for _, want := range []string{"Address=fd00::2/64\n", "Gateway=fd00::1\n", "DNS=fd00::53\n"} {
		if !strings.Contains(string(unit), want) {
			t.Fatalf("network unit lacks %q:\n%s", want, unit)
		}
	}
	// The kernel decides an IPv6 address's scope.
	if strings.Contains(string(unit), "Scope=") {
		t.Fatalf("an IPv6 address was given a scope:\n%s", unit)
	}
}

// A host that numbers the guest's link from 169.254.0.0/16 gives it the only
// address it has. networkd would
// make that address link scope, and the guest would then send beyond the link
// from 0.0.0.0. The unit says global.
func TestLoadGivesALinkLocalAddressGlobalScope(t *testing.T) {
	cfg := loadFixture(t, `{"network":{"address":"169.254.17.2/30","gateway":"169.254.17.1","dns":["169.254.17.1"],"mtu":1500}}`)
	if err := load(cfg); err != nil {
		t.Fatal(err)
	}
	unit, _ := os.ReadFile(filepath.Join(cfg.NetworkDir, networkUnitName))
	if !strings.Contains(string(unit), "[Address]\nAddress=169.254.17.2/30\nScope=global\n\n[Route]\nGateway=169.254.17.1\n") {
		t.Fatalf("unit:\n%s", unit)
	}
}

func TestLoadWithoutANetworkRequestLeavesDHCP(t *testing.T) {
	for name, host := range map[string]string{"no host.json": "", "empty request": `{}`} {
		cfg := loadFixture(t, host)
		if err := load(cfg); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := os.Stat(filepath.Join(cfg.NetworkDir, networkUnitName)); err == nil {
			t.Fatalf("%s: a network unit was written", name)
		}
	}
}

// host.json is hostile input. A value that is not exactly an address must
// never reach a unit file, where a newline would be a new directive.
func TestLoadRejectsHostileHostConfig(t *testing.T) {
	for name, host := range map[string]string{
		"directive injection":     `{"network":{"address":"10.0.0.2/24\nDNS=6.6.6.6"}}`,
		"hostname as address":     `{"network":{"address":"evil.example/24"}}`,
		"gateway outside prefix":  `{"network":{"address":"10.0.0.2/24","gateway":"192.168.1.1"}}`,
		"gateway of other family": `{"network":{"address":"10.0.0.2/24","gateway":"fe80::1","on_link":true}}`,
		"dns injection":           `{"network":{"address":"10.0.0.2/24","dns":["1.1.1.1\n[Route]"]}}`,
		// netip takes any bytes after "%" as the zone of an IPv6 address.
		"directive in a resolver's zone": `{"network":{"address":"10.0.0.2/24","dns":["fe80::1%x\nIPv4RouteLocalnet=yes"]}}`,
		"directive in a gateway's zone":  `{"network":{"address":"fd00::2/64","gateway":"fe80::1%eth0\nIPForward=yes","on_link":true}}`,
		"zoned resolver":                 `{"network":{"address":"10.0.0.2/24","dns":["fe80::1%eth0"]}}`,
		"oversized":                      `{"network":{"address":"10.0.0.2/24"},"pad":"` + strings.Repeat("x", 17*1024) + `"}`,
		"too many resolvers":             `{"network":{"address":"10.0.0.2/24","dns":["1.1.1.1","1.0.0.1","8.8.8.8","8.8.4.4"]}}`,
		"absurd mtu":                     `{"network":{"address":"10.0.0.2/24","mtu":9000000}}`,
		"unknown field":                  `{"network":{"address":"10.0.0.2/24"},"exec":"/bin/sh"}`,
		"trailing document":              `{}{"network":{"address":"10.0.0.2/24"}}`,
		"multicast address":              `{"network":{"address":"224.0.0.1/24"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			cfg := loadFixture(t, host)
			if err := load(cfg); err == nil {
				t.Fatal("accepted")
			}
			if _, err := os.Stat(filepath.Join(cfg.NetworkDir, networkUnitName)); err == nil {
				t.Fatal("a refused host config still wrote a network unit")
			}
		})
	}
}

func TestLoadRequiresTheLaunchDocument(t *testing.T) {
	cfg := loadFixture(t, "")
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
