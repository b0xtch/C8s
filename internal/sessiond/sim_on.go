//go:build c8s_simtee

package sessiond

// Simulation is a TEE simulated in software for a host's guests: the second
// baseline of docs/session-performance.md, in a build made with the
// c8s_simtee tag. With vmm.simulatedTEE every guest of the host boots with
// no TEE, from an image built for it, and its launcher declares its
// registers. Such a host protects no guest from anybody.
type Simulation struct {
	// SimulatedTEE is the simulated authority's directory
	// ('c8s session simtee new').
	SimulatedTEE string `yaml:"simulatedTEE,omitempty"`
}

// paths are the configuration's paths that are taken from its directory.
func (s *Simulation) paths() []*string { return []*string{&s.SimulatedTEE} }

// launcherArgs is what a guest's launcher is told of the simulation.
func (s Simulation) launcherArgs() []string {
	if s.SimulatedTEE == "" {
		return nil
	}
	return []string{"--simulated-tee", s.SimulatedTEE}
}
