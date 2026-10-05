//go:build c8s_simtee

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"

	"github.com/confidential-dot-ai/c8s/internal/simtee"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// simulatedTEE is the simulated authority's directory, for a run against
// guests with no TEE: the second baseline of docs/session-performance.md.
var simulatedTEE string

func simulationFlags() {
	flag.StringVar(&simulatedTEE, "simulated-tee", "",
		"DEVELOPMENT ONLY: judge the guests under the simulated authority in this directory ('c8s session simtee new') in place of Intel's root, for a pool whose guests run with no TEE. The run's record says so")
}

// simulatedRun is what a run's record says of a TEE that is simulated.
type simulatedRun struct {
	Kind string `json:"kind"`
	// Simulated says the guests ran in no TEE: their registers were
	// declared by their launchers, and their quotes signed in the guests.
	Simulated bool   `json:"simulated"`
	BuildTag  string `json:"build_tag"`
	// Authority is the directory, Root the SHA-256 of the authority's root
	// certificate, and Vendor where its documents were served.
	Authority string `json:"authority"`
	Root      string `json:"root"`
	Vendor    string `json:"vendor"`
}

// newEngine is the verifier of every round: Intel's root, or with
// --simulated-tee the simulated authority's in its place.
func newEngine(opts session.EngineOptions) (session.Engine, any, error) {
	if simulatedTEE == "" {
		return session.NewEngine(opts), nil, nil
	}
	root, err := simtee.LoadRoot(simulatedTEE)
	if err != nil {
		return nil, nil, fmt.Errorf("--simulated-tee: %w", err)
	}
	vendor, err := simtee.LoadVendor(simulatedTEE)
	if err != nil {
		return nil, nil, fmt.Errorf("--simulated-tee: %w", err)
	}
	engine, err := session.NewSimulatedEngine(opts, root, simtee.NewRemote(vendor, nil))
	if err != nil {
		return nil, nil, fmt.Errorf("--simulated-tee: %w", err)
	}
	of := sha256.Sum256(root.Raw)
	return engine, &simulatedRun{
		Kind: "tee", Simulated: true, BuildTag: "c8s_simtee",
		Authority: simulatedTEE, Root: hex.EncodeToString(of[:]), Vendor: vendor,
	}, nil
}
