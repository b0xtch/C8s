//go:build linux

package devmapper

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ControlPath is the device every request goes to. devtmpfs makes it.
const ControlPath = "/dev/mapper/control"

// Mapper talks to the kernel's device-mapper.
type Mapper struct{ control *os.File }

// Open opens the control device.
func Open() (*Mapper, error) {
	f, err := os.OpenFile(ControlPath, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("device-mapper: %w", err)
	}
	return &Mapper{control: f}, nil
}

// Close releases the control device. The devices it made stay.
func (m *Mapper) Close() error { return m.control.Close() }

func (m *Mapper) ioctl(cmd uintptr, buf []byte) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, m.control.Fd(), request(cmd), uintptr(unsafe.Pointer(&buf[0])))
	if errno != 0 {
		return errno
	}
	return nil
}

// Create makes the device name with this table and brings it up. It returns
// the device's numbers: its node is /dev/dm-<minor> wherever devtmpfs is
// mounted. A device that could not be brought up is removed again.
func (m *Mapper) Create(name string, targets []Target, opts Options) (Device, error) {
	var flags uint32
	if opts.ReadOnly {
		flags |= flagReadOnly
	}
	if opts.Secure {
		flags |= flagSecureData
	}
	table, err := encodeTable(name, flags, targets)
	if err != nil {
		return Device{}, err
	}
	if opts.Secure {
		defer wipe(table)
	}
	create := make([]byte, headerSize)
	if err := header(create, name, flags&flagReadOnly); err != nil {
		return Device{}, err
	}
	if err := m.ioctl(cmdDevCreate, create); err != nil {
		return Device{}, fmt.Errorf("device-mapper: create %s: %w", name, err)
	}
	dev := decodeDev(create)
	if err := m.ioctl(cmdTableLoad, table); err != nil {
		_ = m.Remove(name)
		return Device{}, fmt.Errorf("device-mapper: load the table of %s: %w", name, err)
	}
	// A suspend request without the suspend flag resumes: it swaps the loaded
	// table in.
	resume := make([]byte, headerSize)
	if err := header(resume, name, 0); err != nil {
		_ = m.Remove(name)
		return Device{}, err
	}
	if err := m.ioctl(cmdDevSuspend, resume); err != nil {
		_ = m.Remove(name)
		return Device{}, fmt.Errorf("device-mapper: resume %s: %w", name, err)
	}
	return dev, nil
}

// Remove takes the device name down.
func (m *Mapper) Remove(name string) error {
	buf := make([]byte, headerSize)
	if err := header(buf, name, 0); err != nil {
		return err
	}
	if err := m.ioctl(cmdDevRemove, buf); err != nil {
		return fmt.Errorf("device-mapper: remove %s: %w", name, err)
	}
	return nil
}

// DeviceOf returns the numbers of the block device at path.
func DeviceOf(path string) (Device, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return Device{}, fmt.Errorf("%s: %w", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFBLK {
		return Device{}, fmt.Errorf("%s is not a block device", path)
	}
	return Device{Major: unix.Major(uint64(st.Rdev)), Minor: unix.Minor(uint64(st.Rdev))}, nil
}
