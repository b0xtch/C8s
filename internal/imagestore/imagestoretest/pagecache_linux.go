package imagestoretest

import (
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Resident is how many of a file's pages the kernel holds in its page cache.
func Resident(t testing.TB, path string) (in, of int) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	data, err := unix.Mmap(int(f.Fd()), 0, int(info.Size()), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Munmap(data) }()
	pages := make([]byte, (len(data)+os.Getpagesize()-1)/os.Getpagesize())
	if _, _, errno := unix.Syscall(unix.SYS_MINCORE, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(&pages[0]))); errno != 0 {
		t.Fatal(errno)
	}
	for _, page := range pages {
		in += int(page & 1)
	}
	return in, len(pages)
}

// OnDisk is a directory on a file system whose pages the kernel can drop:
// one under C8S_TEST_DISK_DIR, or the test's own temporary directory unless
// that is kept in memory, in which case the test is skipped.
func OnDisk(t testing.TB) string {
	t.Helper()
	dir := t.TempDir()
	if base := os.Getenv("C8S_TEST_DISK_DIR"); base != "" {
		var err error
		if dir, err = os.MkdirTemp(base, "pagecache"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(dir, &fs); err != nil {
		t.Fatal(err)
	}
	if fs.Type == unix.TMPFS_MAGIC || fs.Type == unix.RAMFS_MAGIC {
		t.Skipf("%s is kept in memory, where no page can be dropped: set C8S_TEST_DISK_DIR to a directory on a disk", dir)
	}
	return dir
}
