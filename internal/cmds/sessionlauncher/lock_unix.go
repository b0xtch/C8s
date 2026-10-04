//go:build unix

package sessionlauncher

import (
	"errors"
	"os"
	"syscall"
)

// tryLock takes the file's lock for this process if no other holds it. The
// lock goes when the file is closed, and when the process ends.
func tryLock(f *os.File) (bool, error) {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, syscall.EINTR):
		case errors.Is(err, syscall.EWOULDBLOCK):
			return false, nil
		default:
			return false, err
		}
	}
}
