//go:build linux

package sessiond

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionlauncher"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

const (
	// stopGrace is how long a launcher gets to end its guest once it was
	// told to. Then its whole process group is killed.
	stopGrace = 20 * time.Second
	// gonePoll is how often a process the daemon did not start is looked for.
	gonePoll = 250 * time.Millisecond
	// launcherLog is the launcher's output, in the TD's directory.
	launcherLog = "launcher.log"
)

var ifaceRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// QEMURunner boots each TD under a launcher of its own: a process that
// outlives the daemon, hands its guest the vendor's documents and removes the
// guest's disks when the guest is gone.
type QEMURunner struct {
	cfg *Config
	log *slog.Logger
	// self is this binary, which is the launcher too.
	self  string
	block netip.Prefix
}

// NewQEMURunner checks what the host must offer and, in tap mode, loads the
// daemon's table into the host's packet filter. The table stays when the
// daemon exits: its TDs run on.
func NewQEMURunner(cfg *Config, log *slog.Logger) (Runner, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	r := &QEMURunner{cfg: cfg, log: log, self: self}
	if cfg.Network.Mode != NetworkTap {
		return r, nil
	}
	if r.block, err = netip.ParsePrefix(cfg.Network.GuestCIDR); err != nil {
		return nil, err
	}
	egress := cfg.Network.EgressInterface
	if egress != "" {
		if !ifaceRE.MatchString(egress) {
			return nil, fmt.Errorf("network.egressInterface %q is no interface name", egress)
		}
		if _, err := netlink.LinkByName(egress); err != nil {
			return nil, fmt.Errorf("network.egressInterface %s: %w", egress, err)
		}
		// A host setting, and so not the daemon's to change.
		forwarding, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if err != nil || strings.TrimSpace(string(forwarding)) != "1" {
			return nil, errors.New("network.egressInterface needs net.ipv4.ip_forward=1 on this host")
		}
	}
	reach, err := cfg.Network.reach()
	if err != nil {
		return nil, err
	}
	nft := exec.Command("nft", "-f", "-")
	nft.Stdin = strings.NewReader(filterRuleset(egress, reach))
	if out, err := nft.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("load the guests' packet filter: %w: %s", err, bytes.TrimSpace(out))
	}
	return r, nil
}

func (r *QEMURunner) Start(_ context.Context, spec Spec) (Instance, error) {
	vmm := r.cfg.VMM
	args := []string{
		"session-launcher", "run",
		"--platform", spec.Pool.platform,
		"--image-dir", spec.Pool.ImageDir,
		"--launch-dir", spec.Pool.LaunchDir,
		"--work-dir", filepath.Join(spec.Dir, workDir),
		"--name", spec.ID,
		"--vcpus", strconv.Itoa(spec.Class.VCPUs),
		"--memory", spec.Class.Memory,
		"--vsock-cid", "auto",
		"--collateral-cache", filepath.Join(r.cfg.StateDir, collateralDir),
	}
	for _, option := range [][2]string{
		{"--qemu", vmm.QEMU}, {"--quote-socket", vmm.QuoteSocket}, {"--confine", vmm.Confine},
		{"--low-memory", spec.Class.LowMemory}, {"--scratch", spec.Class.Scratch}, {"--image-store", spec.Pool.ImageStore},
	} {
		if option[1] != "" {
			args = append(args, option[0], option[1])
		}
	}
	if vmm.Console {
		args = append(args, "--console")
	}
	var files []*os.File
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	var address string
	switch r.cfg.Network.Mode {
	case NetworkUser:
		port := r.cfg.Network.FirstPort + spec.Slot
		args = append(args, "--network", sessionlauncher.NetworkUser,
			"--port", fmt.Sprintf("127.0.0.1:%d:%d", port, session.AgentPort))
		address = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	case NetworkTap:
		host, guest, err := slotAddresses(r.block, spec.Slot)
		if err != nil {
			return nil, err
		}
		tap, vhost, err := r.tap(spec.Slot, host)
		if err != nil {
			return nil, fmt.Errorf("tap of slot %d: %w", spec.Slot, err)
		}
		// The launcher inherits them as descriptors 3 and 4.
		files = append(files, tap)
		args = append(args, "--network", sessionlauncher.NetworkFD, "--tap-fd", "3",
			"--guest-address", guest.String(), "--guest-gateway", host.String(), "--guest-mac", slotMAC(spec.Slot))
		if vhost != nil {
			files = append(files, vhost)
			args = append(args, "--vhost-fd", "4")
		}
		for _, dns := range r.cfg.Network.DNS {
			args = append(args, "--guest-dns", dns)
		}
		address = net.JoinHostPort(guest.Addr().String(), strconv.Itoa(session.AgentPort))
	}
	out, err := os.OpenFile(filepath.Join(spec.Dir, launcherLog), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	defer out.Close()
	cmd := exec.Command(r.self, args...)
	cmd.Stdout, cmd.Stderr = out, out
	cmd.ExtraFiles = files
	// A session of its own: the launcher outlives the daemon, and its group
	// is the launcher and its VMM and nothing else.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start the launcher: %w", err)
	}
	inst := &process{pid: cmd.Process.Pid, address: address, done: make(chan struct{})}
	// The launcher is this process's child, so its id is its own until Wait.
	if inst.start, err = processStart(inst.pid); err != nil {
		r.log.Warn("a launcher's start time could not be read: a later daemon will not find it", "td", spec.ID, "error", err)
	}
	go func() {
		_ = cmd.Wait()
		waitGroupGone(inst.pid)
		close(inst.done)
	}()
	return inst, nil
}

// tapAskEvery is how often, in milliseconds, the host asks a guest's end of
// its tap for its Ethernet address until it answers.
const tapAskEvery = "20"

// tap makes the TD's tap, gives the host's end its address and brings the tap
// up. The tap lives as long as a descriptor of it is open, which is as long
// as its VMM runs.
func (r *QEMURunner) tap(slot int, host netip.Addr) (tap, vhost *os.File, err error) {
	name := tapName(slot)
	if tap, err = sessionlauncher.OpenTap(name); err != nil {
		return nil, nil, err
	}
	fail := func(err error) (*os.File, *os.File, error) {
		tap.Close()
		return nil, nil, err
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fail(err)
	}
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: host.AsSlice(), Mask: net.CIDRMask(30, 32)}}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fail(fmt.Errorf("address %s: %w", host, err))
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fail(fmt.Errorf("bring it up: %w", err))
	}
	// The host's first packet to a guest waits until the guest's end answers
	// for its Ethernet address, and the kernel asks for that once a second.
	// A guest that came up just after one question would be found only at the
	// next. Asked every few milliseconds it is found as it comes up. An entry
	// set here for good would not last: the host's device manager gives a new
	// interface an address of its own a moment later, and the kernel forgets
	// what it knew of the interface's neighbours when that changes.
	if err := os.WriteFile(filepath.Join("/proc/sys/net/ipv4/neigh", name, "retrans_time_ms"), []byte(tapAskEvery), 0o644); err != nil {
		return fail(fmt.Errorf("how often its guest is asked for its address: %w", err))
	}
	// vhost-net moves the data path into the host's kernel. Without it the
	// VMM copies every packet in user space.
	if vhost, err = os.OpenFile("/dev/vhost-net", os.O_RDWR, 0); err != nil {
		vhost = nil
	}
	return tap, vhost, nil
}

func (r *QEMURunner) Adopt(spec Spec, handle Handle) (Instance, error) {
	start, err := processStart(handle.PID)
	if err != nil || handle.Start == 0 || start != handle.Start {
		return nil, fmt.Errorf("its launcher (process %d) is gone", handle.PID)
	}
	inst := &process{pid: handle.PID, start: handle.Start, done: make(chan struct{})}
	switch r.cfg.Network.Mode {
	case NetworkUser:
		inst.address = net.JoinHostPort("127.0.0.1", strconv.Itoa(r.cfg.Network.FirstPort+spec.Slot))
	case NetworkTap:
		_, guest, err := slotAddresses(r.block, spec.Slot)
		if err != nil {
			return nil, err
		}
		inst.address = net.JoinHostPort(guest.Addr().String(), strconv.Itoa(session.AgentPort))
	}
	// Not this process's child: it is looked for.
	go func() {
		for {
			if now, err := processStart(inst.pid); err != nil || now != inst.start {
				break
			}
			time.Sleep(gonePoll)
		}
		waitGroupGone(inst.pid)
		close(inst.done)
	}()
	return inst, nil
}

// process is a TD's launcher, and with it the VMM it started.
type process struct {
	pid     int
	start   uint64
	address string
	done    chan struct{}
	stop    sync.Once
}

func (p *process) Address() string       { return p.address }
func (p *process) Handle() Handle        { return Handle{PID: p.pid, Start: p.start} }
func (p *process) Done() <-chan struct{} { return p.done }

func (p *process) Stop() {
	p.stop.Do(func() {
		select {
		case <-p.done:
			return
		default:
		}
		// The launcher ends its VMM and waits for it.
		_ = syscall.Kill(p.pid, syscall.SIGTERM)
		go func() {
			select {
			case <-p.done:
			case <-time.After(stopGrace):
				_ = syscall.Kill(-p.pid, syscall.SIGKILL)
			}
		}()
	})
}

// waitGroupGone waits until no process of the launcher's group is left: a
// launcher that was killed leaves its VMM behind for as long as the VMM takes
// to give its memory back.
func waitGroupGone(pgid int) {
	for syscall.Kill(-pgid, 0) == nil {
		time.Sleep(gonePoll)
	}
}

// processStart is when the process started, in the kernel's clock ticks since
// boot: with the id, it names one process for good.
func processStart(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	// The command's name is in parentheses and may hold any byte.
	end := bytes.LastIndexByte(data, ')')
	if end < 0 {
		return 0, errors.New("unreadable stat")
	}
	fields := strings.Fields(string(data[end+1:]))
	// Field 22 of the line, the 20th after the name.
	if len(fields) < 20 {
		return 0, errors.New("short stat")
	}
	return strconv.ParseUint(fields[19], 10, 64)
}
