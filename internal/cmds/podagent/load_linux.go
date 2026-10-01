//go:build linux

package podagent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	opkeyLabel = "opkeydata"
	// The ISO9660 primary volume descriptor sits in sector 16; its volume
	// identifier is 32 bytes at offset 40.
	isoPVDOffset  = 16 * 2048
	deviceTimeout = 10 * time.Second
)

// Load mounts the opkeydata volume read-only, runs load, and unmounts it.
func Load(cfg LoadConfig) error {
	device, err := findOpkeyDevice()
	if err != nil {
		return err
	}
	mountpoint, err := os.MkdirTemp("/run", "c8s-opkey-")
	if err != nil {
		return err
	}
	defer os.Remove(mountpoint)
	flags := uintptr(unix.MS_RDONLY | unix.MS_NODEV | unix.MS_NOSUID | unix.MS_NOEXEC)
	if err := unix.Mount(device, mountpoint, "iso9660", flags, ""); err != nil {
		return fmt.Errorf("mount %s: %w", device, err)
	}
	defer func() { _ = unix.Unmount(mountpoint, unix.MNT_DETACH) }()
	cfg.SourceDir = mountpoint
	return load(cfg)
}

// findOpkeyDevice finds the virtio disk whose ISO9660 label is opkeydata. It
// reads the label itself, so it does not wait on udev to publish one.
func findOpkeyDevice() (string, error) {
	for deadline := time.Now().Add(deviceTimeout); ; time.Sleep(50 * time.Millisecond) {
		disks, _ := filepath.Glob("/sys/block/vd*")
		for _, sys := range disks {
			device := "/dev/" + filepath.Base(sys)
			if label, err := isoLabel(device); err == nil && label == opkeyLabel {
				return device, nil
			}
		}
		if time.Now().After(deadline) {
			return "", errors.New("no opkeydata volume: this guest was launched without a launch document")
		}
	}
}

func isoLabel(device string) (string, error) {
	f, err := os.Open(device)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var pvd [72]byte
	if _, err := f.ReadAt(pvd[:], isoPVDOffset); err != nil {
		return "", err
	}
	if pvd[0] != 1 || string(pvd[1:6]) != "CD001" {
		return "", errors.New("not an ISO9660 volume")
	}
	return strings.TrimRight(string(pvd[40:72]), " "), nil
}
