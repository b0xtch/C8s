//go:build linux

package sessionagent

import (
	"os"
	"path/filepath"
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
	}
}
