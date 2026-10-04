//go:build linux

package sessionlauncher

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// directIO is the open flag of a disk QEMU does not cache.
const directIO = unix.O_DIRECT

// kvmDevice is the one device node QEMU opens by path. Everything else it
// uses reaches it open. A variable so a test can run where there is no KVM.
var kvmDevice = "/dev/kvm"

// sysProcAttr is how the kernel starts the confined VMM: in its namespaces
// first, then as its user. With the last of root's user ids the kernel takes
// every capability, and the exec that follows grants none back.
func (c *Confinement) sysProcAttr(network string) (*syscall.SysProcAttr, error) {
	if missing, err := missingCapabilities(); err != nil {
		return nil, err
	} else if len(missing) > 0 {
		return nil, fmt.Errorf("the launcher lacks %s", strings.Join(missing, ", "))
	}
	groups, err := c.groupsFor(kvmDevice)
	if err != nil {
		return nil, err
	}
	attr := &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: c.UID, Gid: c.GID, Groups: groups},
		Cloneflags: syscall.CLONE_NEWPID | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
	}
	// The tap and vhost descriptors QEMU inherits keep working in a namespace
	// with no interface. Its user-mode stack connects from its own namespace.
	if network != NetworkUser {
		attr.Cloneflags |= syscall.CLONE_NEWNET
	}
	return attr, nil
}

// groupsFor is the supplementary groups the confined user needs to open
// device for reading and writing: none where its own ids or everyone may, or
// the device's group. A user that cannot be given access is an error here,
// where it is legible, instead of QEMU's.
func (c *Confinement) groupsFor(device string) ([]uint32, error) {
	info, err := os.Stat(device)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("%s: no owner to read", device)
	}
	mode := info.Mode().Perm()
	switch {
	case mode&0o006 == 0o006,
		stat.Uid == c.UID && mode&0o600 == 0o600,
		stat.Gid == c.GID && mode&0o060 == 0o060:
		return nil, nil
	case mode&0o060 == 0o060:
		return []uint32{stat.Gid}, nil
	}
	return nil, fmt.Errorf("%s is %s owned by %d:%d, which user %d cannot be given", device, mode, stat.Uid, stat.Gid, c.UID)
}

// confining is what a launcher holds to confine the VMM: to make it another
// user, to give it namespaces, and to stop a process that is no longer its
// own user's. Without the last the launcher would start a guest it cannot end.
var confining = []struct {
	name string
	bit  uint
}{
	{"CAP_SETGID", unix.CAP_SETGID},
	{"CAP_SETUID", unix.CAP_SETUID},
	{"CAP_SYS_ADMIN", unix.CAP_SYS_ADMIN},
	{"CAP_KILL", unix.CAP_KILL},
}

// missingCapabilities names those of confining this process does not hold.
func missingCapabilities() ([]string, error) {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		return nil, fmt.Errorf("read this process's capabilities: %w", err)
	}
	var missing []string
	for _, c := range confining {
		if data[c.bit/32].Effective&(1<<(c.bit%32)) == 0 {
			missing = append(missing, c.name)
		}
	}
	return missing, nil
}
