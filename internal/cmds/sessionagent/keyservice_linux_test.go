//go:build linux

package sessionagent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// A guest dials its key service through its host when the host says where,
// and dials the key service's address when it says nothing.
func TestHostKeyServiceDial(t *testing.T) {
	for name, tc := range map[string]struct {
		host    string
		through bool
		refused bool
	}{
		"no request":        {"", false, false},
		"no relay port":     {`{"network":{"address":"10.42.0.12/24"}}`, false, false},
		"a relay port":      {`{"key_service_port":70123}`, true, false},
		"a hostile request": {`{"key_service_port":4294967295}`, false, true},
	} {
		dir := t.TempDir()
		if tc.host != "" {
			if err := os.WriteFile(filepath.Join(dir, session.HostConfigFile), []byte(tc.host), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		dial, err := hostKeyServiceDial(dir)
		if (err != nil) != tc.refused {
			t.Errorf("%s: %v", name, err)
		}
		if (dial != nil) != tc.through {
			t.Errorf("%s: dials through the host: %v", name, dial != nil)
		}
	}
}
