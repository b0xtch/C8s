//go:build c8s_simtee

package version

import (
	"strings"
	"testing"
)

func TestSimulatingBuildSaysSoInItsVersion(t *testing.T) {
	if !strings.HasSuffix(Version, "+c8s_simtee") || strings.Count(Version, "c8s_simtee") != 1 {
		t.Fatalf("a build made with the c8s_simtee tag states its version as %q", Version)
	}
}
