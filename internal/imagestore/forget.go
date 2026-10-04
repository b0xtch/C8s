//go:build unix

package imagestore

import (
	"io"
	"os"
)

// forgetEvery is how much a reader may leave in the page cache behind it.
// A guest's host backs every page the guest has ever used, so what a pull
// reads once and never again must not stay.
const forgetEvery = 4 << 20

// forgetFile has the kernel drop its cached pages of n bytes of f from off,
// or to the end of f when n is zero. Dirty pages stay. Tests replace it.
var forgetFile = ForgetFile

// spent reads r and says how far it has read: every forgetEvery bytes, and
// when r ends or fails, with -1. It counts from the start each time, because
// the kernel drops whole pages only: a range that began where the last one
// ended would keep the page the two share.
type spent struct {
	r          io.Reader
	read, told int64
	done       func(n int64)
}

func (s *spent) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	s.read += int64(n)
	switch {
	case err != nil:
		s.done(-1)
	case s.read-s.told >= forgetEvery:
		s.told = s.read
		s.done(s.read)
	}
	return n, err
}

// forgetting reads r, which reads the file at path from its start, and has
// the kernel drop the file's pages behind it. The returned function ends it.
// A file that cannot be opened is read as it was.
func forgetting(r io.Reader, path string) (io.Reader, func()) {
	f, err := os.Open(path)
	if err != nil {
		return r, func() {}
	}
	return &spent{r: r, done: func(n int64) { forgetFile(f, 0, max(n, 0)) }}, func() { _ = f.Close() }
}

// forgetPath has the kernel drop its cached pages of the file at path.
func forgetPath(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	forgetFile(f, 0, 0)
	_ = f.Close()
}
