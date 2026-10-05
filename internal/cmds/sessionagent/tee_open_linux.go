//go:build linux && !c8s_simtee

package sessionagent

import (
	"fmt"
	"os"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// OpenTEE returns the native TEE interface for platform ("tdx" or "snp").
func OpenTEE(platform string) (TEE, error) {
	switch platform {
	case "tdx":
		if _, err := os.Stat(tdxGuestDevice); err != nil {
			return nil, fmt.Errorf("this is not a TDX guest: %w", err)
		}
		return &tdxTEE{}, nil
	default:
		// SEV-SNP needs /dev/sev-guest report and extended-report support here.
		return nil, fmt.Errorf("platform %q has no in-guest attester yet", platform)
	}
}

// GuestEngine verifies evidence for a guest: of the key service its launch
// document pins. A guest has no road to the vendor, and judges by the
// documents its host hands it.
func GuestEngine() (session.Engine, error) {
	return session.NewEngine(session.EngineOptions{HandedCollateralOnly: true}), nil
}

// ReplicaEngine verifies evidence for a key service replica: of the guests
// of its pools, on the vendor's documents as it takes them from the vendor
// over the road opts names.
func ReplicaEngine(opts session.EngineOptions) (session.Engine, error) {
	return session.NewEngine(opts), nil
}

// hardwareFiles are the files a guest copies off its launch volume besides
// the ones every guest has, each with the most it may hold: none.
func hardwareFiles() map[string]int64 { return nil }
