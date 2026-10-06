//go:build unix

package sessiondaemon

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A profile is written for each stretch from a SIGUSR1 to the next SIGUSR2,
// numbered in order, a second SIGUSR1 inside a stretch starts none, and a
// stretch that the daemon's end cuts short is kept too.
func TestProfileCoversEachStretchBetweenItsSignals(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.pprof")
	stop := profileOnSignals(path, slog.New(slog.NewTextHandler(io.Discard, nil)))
	self := syscall.Getpid()
	send := func(sig syscall.Signal) {
		t.Helper()
		if err := syscall.Kill(self, sig); err != nil {
			t.Fatal(err)
		}
	}
	written := func(n int) bool {
		info, err := os.Stat(path + "." + string(rune('0'+n)))
		return err == nil && info.Size() > 0
	}
	wait := func(what string, ok func() bool) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); !ok(); time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("%s", what)
			}
		}
	}
	exists := func(n int) bool {
		_, err := os.Stat(path + "." + string(rune('0'+n)))
		return err == nil
	}
	send(syscall.SIGUSR1)
	wait("the first stretch's file was not made", func() bool { return exists(0) })
	send(syscall.SIGUSR1)
	send(syscall.SIGUSR2)
	wait("the first stretch's profile was not written", func() bool { return written(0) })
	if exists(1) {
		t.Fatal("a SIGUSR1 inside a stretch began a second profile")
	}
	send(syscall.SIGUSR1)
	wait("the second stretch's file was not made", func() bool { return exists(1) })
	stop()
	if !written(1) {
		t.Fatal("the stretch that the end cut short left no profile")
	}
	if exists(2) {
		t.Fatal("a third profile was made")
	}
}
