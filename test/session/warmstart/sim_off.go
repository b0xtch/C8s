//go:build !c8s_simtee

package main

import "github.com/confidential-dot-ai/c8s/pkg/session"

// simulationFlags registers what names a simulated TEE: nothing, in this
// build.
func simulationFlags() {}

// newEngine is the verifier of every round, and what the run's record says
// of a TEE that is simulated: nothing, in this build.
func newEngine(opts session.EngineOptions) (session.Engine, any, error) {
	return session.NewEngine(opts), nil, nil
}
