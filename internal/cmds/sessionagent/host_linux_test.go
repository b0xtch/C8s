//go:build linux

package sessionagent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// A guest dials its key service and asks for Intel's documents through its
// host when the host says where. When the host says nothing it dials the key
// service's address and asks nobody.
func TestHostDials(t *testing.T) {
	for name, tc := range map[string]struct {
		host                   string
		keyService, collateral bool
		refused                bool
	}{
		"no request":                {"", false, false, false},
		"no port":                   {`{"network":{"address":"10.42.0.12/24"}}`, false, false, false},
		"a relay port":              {`{"key_service_port":70123}`, true, false, false},
		"a collateral port":         {`{"collateral_port":70124}`, false, true, false},
		"both":                      {`{"key_service_port":70123,"collateral_port":70124}`, true, true, false},
		"a hostile relay port":      {`{"key_service_port":4294967295}`, false, false, true},
		"a hostile collateral port": {`{"collateral_port":4294967295}`, false, false, true},
	} {
		dir := t.TempDir()
		if tc.host != "" {
			if err := os.WriteFile(filepath.Join(dir, session.HostConfigFile), []byte(tc.host), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		dials, err := readHostDials(dir)
		if (err != nil) != tc.refused {
			t.Errorf("%s: %v", name, err)
		}
		if (dials.KeyService != nil) != tc.keyService {
			t.Errorf("%s: dials its key service through the host: %v", name, dials.KeyService != nil)
		}
		if (dials.Collateral != nil) != tc.collateral {
			t.Errorf("%s: asks its host for Intel's documents: %v", name, dials.Collateral != nil)
		}
		if dials.Vendor != nil {
			t.Errorf("%s: a road to the vendor that its host did not name", name)
		}
	}
}

// A guest with no network device reaches the vendor's service over the
// connections its host carries, and nothing else: a service its host named no
// port for is not reached, and neither is any when the host named none.
func TestVendorDialReachesOnlyWhatTheHostCarries(t *testing.T) {
	write := func(host string) string {
		dir := t.TempDir()
		if host != "" {
			if err := os.WriteFile(filepath.Join(dir, session.HostConfigFile), []byte(host), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	ctx := context.Background()
	for name, host := range map[string]string{"no request": "", "a request with no road": `{"key_service_port":70123}`} {
		dial, err := VendorDial(write(host))
		if err != nil || dial == nil {
			t.Fatalf("%s: %v", name, err)
		}
		if conn, err := dial(ctx, "tcp", "api.trustedservices.intel.com:443"); err == nil || !strings.Contains(err.Error(), "named no road") {
			t.Fatalf("%s: the vendor's service was reached: %v, %v", name, conn, err)
		}
	}
	// A port nothing listens on: the dial goes to the host's port for the
	// service, and to nowhere for a service the host did not name.
	dial, err := VendorDial(write(`{"vendor_ports":{"api.trustedservices.intel.com:443":70125}}`))
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := dial(ctx, "tcp", "certificates.trustedservices.intel.com:443"); err == nil || !strings.Contains(err.Error(), "carries no connection to certificates.trustedservices.intel.com:443") {
		t.Fatalf("a service the host named no road to was reached: %v, %v", conn, err)
	}
	if conn, err := dial(ctx, "tcp", "api.trustedservices.intel.com:443"); err == nil || !strings.Contains(err.Error(), "port 70125") {
		t.Fatalf("the dial did not go to the host's port for the service: %v, %v", conn, err)
	}
	for name, host := range map[string]string{
		"a port that is none":    `{"vendor_ports":{"api.trustedservices.intel.com:443":4294967295}}`,
		"a port of zero":         `{"vendor_ports":{"api.trustedservices.intel.com:443":0}}`,
		"an address for a name":  `{"vendor_ports":{"10.0.2.2:443":70125}}`,
		"a name with no port":    `{"vendor_ports":{"api.trustedservices.intel.com":70125}}`,
		"a name with a path":     `{"vendor_ports":{"api.trustedservices.intel.com:443/x":70125}}`,
		"a name with a space":    `{"vendor_ports":{"api.trusted services.intel.com:443":70125}}`,
		"a name in capitals":     `{"vendor_ports":{"API.trustedservices.intel.com:443":70125}}`,
		"a port that is no port": `{"vendor_ports":{"api.trustedservices.intel.com:0":70125}}`,
		"more services than any": `{"vendor_ports":{"a.example.com:443":1,"b.example.com:443":2,"c.example.com:443":3,"d.example.com:443":4,"e.example.com:443":5,"f.example.com:443":6,"g.example.com:443":7,"h.example.com:443":8,"i.example.com:443":9}}`,
	} {
		if _, err := VendorDial(write(host)); err == nil {
			t.Errorf("%s was taken", name)
		}
	}
}
