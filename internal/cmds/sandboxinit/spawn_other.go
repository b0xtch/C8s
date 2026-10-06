//go:build unix && !linux

package sandboxinit

// spawn needs Linux: a descriptor for a process it starts.
func spawn() int { return FailureStatus }
