//go:build linux

package sessionagent

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// kernelLog gives a kernel's log a record a read, from the oldest it holds.
const kernelLog = "/dev/kmsg"

// kernelOnFreedMemory is the kernel's own line on the memory it zeroes, read
// from its log.
func kernelOnFreedMemory() (string, error) {
	// By descriptor: the runtime's poller would wait at the log's end.
	fd, err := unix.Open(kernelLog, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("open the kernel's log: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	// No record is longer than this, and no log holds as many as are read.
	record := make([]byte, 8192)
	for range 1 << 20 {
		n, err := unix.Read(fd, record)
		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EPIPE):
			// The log dropped records under this reader, which goes on from
			// the oldest that is left.
			continue
		case errors.Is(err, unix.EAGAIN):
			return "", errors.New("the kernel's log has no line on the memory it zeroes")
		case err != nil:
			return "", fmt.Errorf("read the kernel's log: %w", err)
		}
		if line := freedMemoryRecord(string(record[:n])); line != "" {
			return line, nil
		}
	}
	return "", errors.New("the kernel's log does not end")
}
