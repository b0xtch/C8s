//go:build !linux

package podagent

// requireRAMBacked cannot be checked off Linux, where only tests run.
func requireRAMBacked(string) error { return nil }
