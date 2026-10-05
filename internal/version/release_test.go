//go:build !c8s_simtee

package version

import (
	"strings"
	"testing"
)

func TestReleaseBuildsVersionNamesNoSimulation(t *testing.T) {
	if strings.Contains(Version, "simtee") {
		t.Fatalf("a build made without the c8s_simtee tag states its version as %q", Version)
	}
}
