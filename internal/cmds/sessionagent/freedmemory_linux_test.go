//go:build linux

package sessionagent

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A kernel's log gives the kernel's own line on the memory it zeroes to a
// reader who may read it, for as long as the log still has its start.
func TestKernelLogHasTheKernelsLineOnFreedMemory(t *testing.T) {
	fd, err := unix.Open(kernelLog, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOENT) {
		t.Skipf("this kernel's log is not this test's to read: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	record := make([]byte, 8192)
	n, err := unix.Read(fd, record)
	_ = unix.Close(fd)
	if err != nil {
		t.Fatalf("read the log's oldest record: %v", err)
	}
	// A record's second field numbers it, from 0.
	if fields := strings.SplitN(string(record[:n]), ",", 3); len(fields) < 3 || fields[1] != "0" {
		t.Skipf("this kernel's log has lost its start: its oldest record is %.40q", record[:n])
	}
	line, err := kernelOnFreedMemory()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, freedMemoryLine) || !strings.Contains(line, ", heap free:o") {
		t.Fatalf("the kernel's line on the memory it zeroes: %q", line)
	}
	t.Logf("this kernel says %q, which is that it zeroes what it frees: %v", line, zeroesFreedMemory(line))
}
