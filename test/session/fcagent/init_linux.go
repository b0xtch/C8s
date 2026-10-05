package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// becomeInit makes a guest whose kernel has just started this program a
// system a command can run in: the kernel's own file systems, memory to
// write to where the root has a place for it, the environment of the file
// env beside this program, and the credentials' directory in memory.
func becomeInit() error {
	for _, m := range []struct{ source, target, kind string }{
		{"proc", "/proc", "proc"}, {"sysfs", "/sys", "sysfs"}, {"devtmpfs", "/dev", "devtmpfs"},
		{"tmpfs", "/tmp", "tmpfs"}, {"tmpfs", "/run", "tmpfs"},
	} {
		if _, err := os.Stat(m.target); err != nil {
			continue
		}
		// A kernel that mounts /dev before its init says the next is busy.
		if err := unix.Mount(m.source, m.target, m.kind, 0, ""); err != nil && !errors.Is(err, unix.EBUSY) {
			return fmt.Errorf("mount %s: %w", m.target, err)
		}
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(self), "env"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, variable := range environment(data) {
		if err := os.Setenv(variable[0], variable[1]); err != nil {
			return err
		}
	}
	if dir := os.Getenv(credentialsDir); dir != "" {
		if err := unix.Mount("tmpfs", dir, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "mode=0700"); err != nil {
			return fmt.Errorf("mount %s: %w", dir, err)
		}
	}
	return nil
}
