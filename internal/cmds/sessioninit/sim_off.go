//go:build !c8s_simtee

package sessioninit

// bindSimulated binds the launch key in a build whose TEE is simulated in
// software. This build is none, and binds a key in hardware or not at all.
func bindSimulated(platform, []byte) (bool, error) { return false, nil }
