package imagestore

import (
	"os"

	"golang.org/x/sys/unix"
)

// syncFilesystem writes out everything the file system that holds path has
// in memory, and returns when it is on its disk.
func syncFilesystem(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return unix.Syncfs(int(dir.Fd()))
}
