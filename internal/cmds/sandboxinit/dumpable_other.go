//go:build unix && !linux

package sandboxinit

// undumpable does nothing off Linux, where only tests run.
func undumpable() {}
