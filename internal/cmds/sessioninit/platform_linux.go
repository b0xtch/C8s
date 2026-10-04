//go:build linux

package sessioninit

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/devmapper"
)

// kernel is the guest's own kernel, asked directly.
type kernel struct {
	mapper *devmapper.Mapper
	log    *os.File
	// null and console are what children get as their three descriptors:
	// nothing to read, and the console to write to, which in a locked guest
	// discards.
	null, console *os.File
}

func (k *kernel) Mount(source, target, fstype string, flags uintptr, data string) error {
	return unix.Mount(source, target, fstype, flags, data)
}

func (k *kernel) Unmount(target string) error { return unix.Unmount(target, 0) }

func (k *kernel) MkdirAll(path string, mode os.FileMode) error { return os.MkdirAll(path, mode) }

func (k *kernel) ReadFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s holds more than %d bytes", path, limit)
	}
	return data, nil
}

// WriteFile creates a file with mode, or with mode 0 writes data in one
// write to a file that exists: a kernel attribute takes its value whole.
func (k *kernel) WriteFile(path string, data []byte, mode os.FileMode) error {
	flags := os.O_WRONLY
	if mode != 0 {
		flags |= os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

func (k *kernel) ReadDirFiles(dir string, limit int64) (map[string][]byte, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string][]byte{}, nil
	}
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		// A symlink to a file counts; systemd masks a file with one to /dev/null.
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		data, err := k.ReadFile(path, limit)
		if err != nil {
			return nil, err
		}
		files[entry.Name()] = data
	}
	return files, nil
}

func (k *kernel) IsDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func (k *kernel) Exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func (k *kernel) CopyOwnerAndMode(from, to string) error {
	var st unix.Stat_t
	if err := unix.Stat(from, &st); err != nil {
		return fmt.Errorf("%s: %w", from, err)
	}
	if err := unix.Chown(to, int(st.Uid), int(st.Gid)); err != nil {
		return fmt.Errorf("%s: %w", to, err)
	}
	// Chown clears the set-id bits; the mode goes last.
	return unix.Chmod(to, st.Mode&0o7777)
}

// Disks lists the guest's whole disks. Loop, RAM and device-mapper devices
// are not disks a host attached.
func (k *kernel) Disks() ([]blockDevice, error) {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil, err
	}
	var disks []blockDevice
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "dm-") || strings.HasPrefix(name, "zram") {
			continue
		}
		b := blockDevice{Name: name}
		if serial, err := os.ReadFile(filepath.Join("/sys/block", name, "serial")); err == nil {
			b.Serial = strings.TrimSpace(string(serial))
		}
		if size, err := os.ReadFile(filepath.Join("/sys/block", name, "size")); err == nil {
			b.Sectors, _ = strconv.ParseUint(strings.TrimSpace(string(size)), 10, 64)
		}
		disks = append(disks, b)
	}
	sort.Slice(disks, func(i, j int) bool { return disks[i].Name < disks[j].Name })
	return disks, nil
}

func (k *kernel) OpenDisk(name string) (disk, error) {
	if strings.ContainsAny(name, "/.") {
		return nil, fmt.Errorf("disk name %q", name)
	}
	return os.Open("/dev/" + name)
}

func sysfsDevice(path string) (devmapper.Device, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return devmapper.Device{}, err
	}
	major, minor, ok := strings.Cut(strings.TrimSpace(string(data)), ":")
	ma, errMajor := strconv.ParseUint(major, 10, 32)
	mi, errMinor := strconv.ParseUint(minor, 10, 32)
	if !ok || errMajor != nil || errMinor != nil {
		return devmapper.Device{}, fmt.Errorf("%s: %q is no device number", path, data)
	}
	return devmapper.Device{Major: uint32(ma), Minor: uint32(mi)}, nil
}

func (k *kernel) DiskDevice(name string) (devmapper.Device, error) {
	return sysfsDevice(filepath.Join("/sys/block", name, "dev"))
}

// PartitionDevice finds a partition by its number, whatever the kernel named
// it: vda2, nvme0n1p2.
func (k *kernel) PartitionDevice(name string, number int) (devmapper.Device, error) {
	entries, err := os.ReadDir(filepath.Join("/sys/block", name))
	if err != nil {
		return devmapper.Device{}, err
	}
	for _, entry := range entries {
		dir := filepath.Join("/sys/block", name, entry.Name())
		data, err := os.ReadFile(filepath.Join(dir, "partition"))
		if err != nil {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && n == number {
			return sysfsDevice(filepath.Join(dir, "dev"))
		}
	}
	return devmapper.Device{}, fmt.Errorf("%s has no partition %d", name, number)
}

func (k *kernel) CreateMapping(name string, target devmapper.Target, opts devmapper.Options) (devmapper.Device, error) {
	if k.mapper == nil {
		m, err := devmapper.Open()
		if err != nil {
			return devmapper.Device{}, err
		}
		k.mapper = m
	}
	return k.mapper.Create(name, []devmapper.Target{target}, opts)
}

// ReadAhead reads a file into the page cache in the background. The kernel's
// own readahead call covers one window; a program of tens of megabytes takes
// a reader.
func (k *kernel) ReadAhead(path string) {
	go func() {
		f, err := os.Open(path)
		if err != nil {
			return
		}
		defer f.Close()
		_, _ = io.Copy(io.Discard, f)
	}()
}

func (k *kernel) RandomKey() ([]byte, error) {
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func (k *kernel) Sleep(d time.Duration) { time.Sleep(d) }

// Log writes to the kernel's log. A locked guest has no console and nobody
// reads its log; a dev guest's console shows it.
func (k *kernel) Log(format string, args ...any) {
	if k.log == nil {
		f, err := os.OpenFile("/dev/kmsg", os.O_WRONLY, 0)
		if err != nil {
			return
		}
		k.log = f
	}
	// One write is one record. 6 is the "info" level.
	_, _ = k.log.WriteString("<6>c8s-session-init: " + fmt.Sprintf(format, args...) + "\n")
}

// files are a child's three descriptors.
func (k *kernel) files() ([]uintptr, error) {
	if k.null == nil {
		f, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
		if err != nil {
			return nil, err
		}
		k.null = f
	}
	if k.console == nil {
		// A guest whose kernel has no console at all still has /dev/null.
		f, err := os.OpenFile("/dev/console", os.O_WRONLY|unix.O_NOCTTY, 0)
		if err != nil {
			f = k.null
		}
		k.console = f
	}
	return []uintptr{k.null.Fd(), k.console.Fd(), k.console.Fd()}, nil
}

// RunIn runs a program of root to its end inside root.
func (k *kernel) RunIn(root string, argv []string) error {
	files, err := k.files()
	if err != nil {
		return err
	}
	pid, err := syscall.ForkExec(argv[0], argv, &syscall.ProcAttr{
		Dir: "/", Env: childEnv, Files: files,
		Sys: &syscall.SysProcAttr{Chroot: root},
	})
	if err != nil {
		return err
	}
	var status unix.WaitStatus
	for {
		_, err := unix.Wait4(pid, &status, 0, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		break
	}
	if code := exitCode(status); code != 0 {
		return fmt.Errorf("%s ended with status %d", argv[0], code)
	}
	return nil
}

func exitCode(status unix.WaitStatus) int {
	if status.Signaled() {
		return 128 + int(status.Signal())
	}
	return status.ExitStatus()
}

// SwitchRoot moves the mounted root over the initramfs and enters it. The
// initramfs stays below, unreachable; it held this program and nothing else.
func (k *kernel) SwitchRoot(dir string) error {
	if err := unix.Chdir(dir); err != nil {
		return err
	}
	if err := unix.Mount(".", "/", "", unix.MS_MOVE, ""); err != nil {
		return fmt.Errorf("move the root mount: %w", err)
	}
	if err := unix.Chroot("."); err != nil {
		return err
	}
	return unix.Chdir("/")
}

func (k *kernel) SetHostname(name string) error { return unix.Sethostname([]byte(name)) }

// LoopbackUp brings the loopback interface up, which nothing else in a guest
// without a network manager does.
func (k *kernel) LoopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

func (k *kernel) WriteSysctl(key, value string) error {
	paths := []string{filepath.Join("/proc/sys", key)}
	if strings.Contains(key, "*") {
		matches, err := filepath.Glob(paths[0])
		if err != nil {
			return err
		}
		if len(matches) == 0 {
			return fs.ErrNotExist
		}
		paths = matches
	}
	for _, path := range paths {
		if !strings.HasPrefix(filepath.Clean(path), "/proc/sys/") {
			return fmt.Errorf("%s is outside /proc/sys", path)
		}
		if err := k.WriteFile(path, []byte(value), 0); err != nil {
			return err
		}
	}
	return nil
}

func (k *kernel) NoNewPrivileges() error {
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}

func (k *kernel) SetOpenFiles(limit uint64) error {
	return unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{Cur: limit, Max: limit})
}

// Start starts argv as a child in a session of its own.
func (k *kernel) Start(argv, env []string, cgroup string, oomScore int) (int, error) {
	files, err := k.files()
	if err != nil {
		return 0, err
	}
	attr := &syscall.ProcAttr{Dir: "/", Env: env, Files: files, Sys: &syscall.SysProcAttr{Setsid: true}}
	if cgroup != "" {
		dir, err := os.Open(cgroup)
		if err != nil {
			return 0, err
		}
		defer dir.Close()
		attr.Sys.UseCgroupFD, attr.Sys.CgroupFD = true, int(dir.Fd())
	}
	// A child takes the score of its parent at the fork. Process 1 is exempt
	// from the kernel's choice whatever its own score says.
	if oomScore != 0 {
		if err := k.WriteFile("/proc/self/oom_score_adj", []byte(strconv.Itoa(oomScore)), 0); err != nil {
			return 0, err
		}
		defer func() { _ = k.WriteFile("/proc/self/oom_score_adj", []byte("0"), 0) }()
	}
	return syscall.ForkExec(argv[0], argv, attr)
}

func (k *kernel) Wait() (int, int, error) {
	var status unix.WaitStatus
	for {
		pid, err := unix.Wait4(-1, &status, 0, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return 0, 0, err
		}
		if status.Exited() || status.Signaled() {
			return pid, exitCode(status), nil
		}
	}
}

// powerOff ends the guest. A session guest never reboots: whatever comes up
// after it is another guest, attested afresh.
func powerOff() {
	unix.Sync()
	_ = unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
	// Not reached while the kernel honours the call. Process 1 must not exit.
	for {
		time.Sleep(time.Hour)
	}
}

// Main is process 1 of a session guest.
func Main() int {
	k := &kernel{}
	if err := prepareRoot(k); err != nil {
		k.Log("FATAL before the root: %v", err)
		powerOff()
	}
	err := runGuest(k)
	k.Log("the guest ends: %v", err)
	powerOff()
	return 1
}
