//go:build unix && !linux

package imagestore

// syncFilesystem does nothing off Linux, where only tests run.
func syncFilesystem(string) error { return nil }
