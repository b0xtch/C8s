//go:build c8s_simtee

package version

// A build that can simulate a session guest's TEE (the c8s_simtee tag) says
// so wherever it states its version: no record takes it for a release build.
func init() { Version += "+c8s_simtee" }
