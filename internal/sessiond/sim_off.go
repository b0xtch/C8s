//go:build !c8s_simtee

package sessiond

// Simulation is a TEE simulated in software for a host's guests. This build
// has none: its configuration takes no word for one, and every guest it
// launches runs in the host's TEE.
type Simulation struct{}

// paths are the configuration's paths that are taken from its directory.
func (*Simulation) paths() []*string { return nil }

// launcherArgs is what a guest's launcher is told of the simulation.
func (Simulation) launcherArgs() []string { return nil }
