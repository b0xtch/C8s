//go:build !linux

package sessionagent

// requireRAMBacked cannot be checked off Linux, where only tests run.
func requireRAMBacked(string) error { return nil }
