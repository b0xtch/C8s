package sessioninit

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/guestend"
	"github.com/confidential-dot-ai/c8s/pkg/session/disclosure"
)

// Mount flags, with the kernel's values: this file builds wherever its tests
// run.
const (
	msReadOnly    = 0x1
	msNoSuid      = 0x2
	msNoDev       = 0x4
	msNoExec      = 0x8
	msRemount     = 0x20
	msNoSymFollow = 0x100
	msBind        = 0x1000
	msStrictAtime = 0x1000000
)

const (
	// serviceCgroup is the cgroup the guest's service starts in. The agent
	// makes its commands' and its sandbox's cgroups below it.
	serviceCgroup = "/sys/fs/cgroup/c8s-session"
	// serviceOOMScore keeps the kernel from choosing the service when the
	// guest runs out of memory: what a session ran is what should go.
	serviceOOMScore = -900
	// openFiles is the service's limit on open files.
	openFiles = 65536
)

// childEnv is the environment of everything the init starts.
var childEnv = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C.UTF-8"}

// guestPlatform is what the init asks of the kernel once it runs from the
// root file system.
type guestPlatform interface {
	platform
	// SwitchRoot makes dir the root of this process and of all it starts.
	SwitchRoot(dir string) error
	SetHostname(name string) error
	LoopbackUp() error
	// WriteSysctl writes one setting. The key may hold a * for every entry
	// of a directory.
	WriteSysctl(key, value string) error
	NoNewPrivileges() error
	SetOpenFiles(limit uint64) error
	// Start starts a program as a child, in the cgroup at dir when dir is
	// not empty, and returns its process id.
	Start(argv, env []string, cgroup string, oomScore int) (int, error)
	// Wait returns the next child that ended, whichever it is, and how: as
	// process 1 the init is also the parent of every orphan in the guest.
	Wait() (pid int, how ending, err error)
	// DialHost connects to a vsock port of the guest's host.
	DialHost(port uint32) (guestend.Stream, error)
}

// ending is how a process ended: the status it exited with, or the signal
// that killed it.
type ending struct {
	status, signal int
}

// code is the ending as a shell states one: the status, or 128 and the
// signal's number.
func (e ending) code() int {
	if e.signal != 0 {
		return 128 + e.signal
	}
	return e.status
}

// guestEnd is why a guest ends once its service has: in full for the init's
// own log, and as the word its launcher is told.
type guestEnd struct {
	word disclosure.End
	text string
}

func (e *guestEnd) Error() string { return e.text }

// mountsAfterMove are the kernel file systems a guest's programs expect,
// beyond the three the init mounted for itself.
var mountsAfterMove = []struct {
	source, target, fstype string
	flags                  uintptr
	data                   string
	// optional mounts may fail: a kernel without the file system is one the
	// image did not ask for it in.
	optional bool
}{
	{"cgroup2", "/sys/fs/cgroup", "cgroup2", msNoSuid | msNoDev | msNoExec, "nsdelegate", false},
	{"devpts", "/dev/pts", "devpts", msNoSuid | msNoExec, "mode=620,ptmxmode=666,gid=5", false},
	{"tmpfs", "/dev/shm", "tmpfs", msNoSuid | msNoDev, "mode=1777", false},
	{"tmpfs", "/tmp", "tmpfs", msNoSuid | msNoDev, "mode=1777,size=50%,nr_inodes=1m", false},
	{"configfs", "/sys/kernel/config", "configfs", msNoSuid | msNoDev | msNoExec, "", true},
}

// runGuest moves into the root and runs the guest to its end. It returns the
// reason the guest ends, which is never nil: a guest's service is not
// expected to exit, and a guest without its service has nothing to be.
func runGuest(p guestPlatform) error {
	if err := p.SwitchRoot(newRoot); err != nil {
		return fmt.Errorf("move into the root: %w", err)
	}
	for _, m := range mountsAfterMove {
		if err := mountAt(p, m.source, m.target, m.fstype, m.flags, m.data); err != nil && !m.optional {
			return err
		}
	}
	p.Log("root: moved in")
	data, err := p.ReadFile(bootConfigPath, maxBootConfig)
	if err != nil {
		return err
	}
	cfg, err := parseBootConfig(data)
	if err != nil {
		return err
	}
	if cfg.Hostname != "" {
		if err := p.SetHostname(cfg.Hostname); err != nil {
			return fmt.Errorf("host name: %w", err)
		}
	}
	if err := applySysctls(p); err != nil {
		return err
	}
	if err := p.LoopbackUp(); err != nil {
		return fmt.Errorf("loopback: %w", err)
	}
	// The controllers a service may hand on to its own children. A kernel
	// without one of them refuses the whole line, so each is asked for alone.
	for _, controller := range []string{"cpu", "io", "pids", "cpuset", "memory"} {
		_ = p.WriteFile("/sys/fs/cgroup/cgroup.subtree_control", []byte("+"+controller), 0)
	}
	if err := p.MkdirAll(serviceCgroup, 0o755); err != nil {
		return fmt.Errorf("service cgroup: %w", err)
	}
	if err := p.SetOpenFiles(openFiles); err != nil {
		return fmt.Errorf("open files limit: %w", err)
	}
	// Nothing the init starts, and nothing those start, gains privilege by
	// running a file: the sandbox and every command of a session inherit it.
	if err := p.NoNewPrivileges(); err != nil {
		return fmt.Errorf("no new privileges: %w", err)
	}
	for _, argv := range cfg.Steps {
		pid, err := p.Start(argv, childEnv, "", 0)
		if err != nil {
			return fmt.Errorf("%s: %w", argv[0], err)
		}
		how, err := waitFor(p, pid)
		if err != nil {
			return err
		}
		if how.code() != 0 {
			return fmt.Errorf("%s ended with status %d", strings.Join(argv, " "), how.code())
		}
		p.Log("step: %s done", strings.Join(argv, " "))
	}
	pid, err := p.Start(cfg.Service, childEnv, serviceCgroup, serviceOOMScore)
	if err != nil {
		return fmt.Errorf("%s: %w", cfg.Service[0], err)
	}
	p.Log("service: %s", cfg.Service[0])
	how, err := waitFor(p, pid)
	if err != nil {
		return err
	}
	return &guestEnd{word: serviceWord(p, how), text: fmt.Sprintf("%s ended with status %d", cfg.Service[0], how.code())}
}

// waitFor reaps children until pid has ended, and returns how it did.
func waitFor(p guestPlatform, pid int) (ending, error) {
	for {
		ended, how, err := p.Wait()
		if err != nil {
			return ending{}, fmt.Errorf("wait for process %d: %w", pid, err)
		}
		if ended == pid {
			return how, nil
		}
	}
}

// serviceWord is the guest's last word once its service has ended: the phase
// the service last wrote, and why it ended. A service that ended for a reason
// of its own exited with that reason's status. Any other status is given as
// it is, and a signal with whether the kernel sent it for memory.
func serviceWord(p guestPlatform, how ending) disclosure.End {
	written, _ := p.ReadFile(guestend.PhaseFile, 64)
	word := disclosure.End{Phase: guestend.Phase(written)}
	code, own := disclosure.EndOfStatus(how.status)
	switch {
	case how.signal != 0:
		word.Code, word.Signal, word.Memory = disclosure.EndKilled, &how.signal, killedForMemory(p)
	case own:
		word.Code = code
	default:
		word.Code, word.Status = disclosure.EndExited, &how.status
	}
	return word
}

// killedForMemory reports whether the kernel killed a process of the
// service's own cgroup for memory. The sandbox and the commands have cgroups
// of their own below it, whose kills this count leaves out.
func killedForMemory(p guestPlatform) bool {
	events, err := p.ReadFile(serviceCgroup+"/memory.events.local", 4096)
	if err != nil {
		return false
	}
	for _, line := range bytes.Split(events, []byte("\n")) {
		if count, ok := bytes.CutPrefix(line, []byte("oom_kill ")); ok {
			n, err := strconv.Atoi(string(bytes.TrimSpace(count)))
			return err == nil && n > 0
		}
	}
	return false
}

// lastWord is the word for whatever ended the guest: the service's own, or
// that the boot failed before there was a service.
func lastWord(err error) disclosure.End {
	var ended *guestEnd
	if errors.As(err, &ended) {
		return ended.word
	}
	return disclosure.End{Phase: disclosure.EndedBooting, Code: disclosure.EndBoot}
}

// sayLastWord tells the guest's launcher why the guest ends, on the port the
// host's file names, and waits for nobody: a guest that reaches no launcher
// ends all the same.
func sayLastWord(p guestPlatform, word disclosure.End) {
	config, err := p.ReadFile(guestend.HostConfigFile, 16<<10)
	if err != nil {
		p.Log("no last word: the host's file is not staged")
		return
	}
	port := guestend.Port(config)
	if port == 0 {
		p.Log("no last word: the host named no port for it")
		return
	}
	conn, err := p.DialHost(port)
	if err != nil {
		p.Log("no last word: %v", err)
		return
	}
	if err := guestend.Send(conn, word, guestend.Wait); err != nil {
		p.Log("no last word: %v", err)
	}
}

// applySysctls applies the image's kernel settings: the builder's hardening
// and the profile's own, from the same directories systemd-sysctl reads.
func applySysctls(p guestPlatform) error {
	var dirs []map[string][]byte
	for _, dir := range []string{"/usr/lib/sysctl.d", "/etc/sysctl.d"} {
		files, err := p.ReadDirFiles(dir, 64*1024)
		if err != nil {
			return err
		}
		dirs = append(dirs, files)
	}
	settings, err := sysctlSettings(dirs)
	if err != nil {
		return err
	}
	var failed []string
	for _, s := range settings {
		err := p.WriteSysctl(s.Key, s.Value)
		// A setting this kernel does not have is one of a feature it was
		// built without, as systemd-sysctl takes it.
		if err == nil || s.Optional || errors.Is(err, fs.ErrNotExist) {
			continue
		}
		failed = append(failed, fmt.Sprintf("%s: %v", s.Key, err))
	}
	if len(failed) > 0 {
		// A hardening setting that did not take is a guest that is not the
		// one its image describes.
		return errors.New("kernel settings: " + strings.Join(failed, "; "))
	}
	return nil
}
