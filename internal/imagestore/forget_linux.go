package imagestore

import (
	"os"

	"golang.org/x/sys/unix"
)

// ForgetFile has the kernel drop its cached pages of n bytes of f from off,
// or to the end of f when n is zero. Dirty pages stay, and so does a page
// the range covers in part.
func ForgetFile(f *os.File, off, n int64) {
	raw, err := f.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) { _ = unix.Fadvise(int(fd), off, n, unix.FADV_DONTNEED) })
}
