//go:build unix

package fileutil

import (
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
)

func TestWriteAtomicWriteFailureCleansUpTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")

	// Drop the process file-size limit to zero so the tmp.Write fails with
	// EFBIG, exercising the write error path and tmp cleanup. SIGXFSZ must
	// be ignored or the kernel would kill the process instead of returning
	// the error from write(2).
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatalf("getrlimit: %v", err)
	}
	if old.Cur == 0 {
		t.Skip("RLIMIT_FSIZE already zero")
	}
	signal.Ignore(syscall.SIGXFSZ)
	defer signal.Reset(syscall.SIGXFSZ)
	zero := syscall.Rlimit{Cur: 0, Max: old.Max}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &zero); err != nil {
		t.Skipf("setrlimit not permitted: %v", err)
	}
	defer func() {
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
			t.Fatalf("restore rlimit: %v", err)
		}
	}()

	if err := WriteAtomic(path, []byte("x"), 0o644); err == nil {
		t.Fatal("expected write error with RLIMIT_FSIZE=0")
	}

	// Restore before reading the directory back.
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatalf("restore rlimit: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("temp file not cleaned up, dir contains: %v", entries)
	}
}

// The temp file is handed over before the rename: when that fails, the name
// still holds what it held and no temp file is left behind.
func TestWriteAtomicRootOwnedHandsOverBeforeTheRename(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root may hand a file to anyone")
	}
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := WriteAtomicRootOwned(root, "out", []byte("mine"), 0o600, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("to this user: %v", err)
	}
	if err := WriteAtomicRootOwned(root, "out", []byte("also mine"), 0o600, -1, os.Getgid()); err != nil {
		t.Fatalf("to this group alone: %v", err)
	}
	// A group this user is not in, to which it may hand nothing.
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	foreign := 0
	for slices.Contains(groups, foreign) || foreign == os.Getgid() {
		foreign++
	}
	for name, owner := range map[string][2]int{"root": {0, 0}, "the user alone": {0, -1}, "the group alone": {-1, foreign}} {
		if err := WriteAtomicRootOwned(root, "out", []byte("another's"), 0o600, owner[0], owner[1]); err == nil {
			t.Fatalf("%s: handed a file over without the right to", name)
		}
	}
	if got, err := os.ReadFile(filepath.Join(dir, "out")); err != nil || string(got) != "also mine" {
		t.Fatalf("the file holds %q, %v", got, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("the directory holds %v, %v", entries, err)
	}
}
