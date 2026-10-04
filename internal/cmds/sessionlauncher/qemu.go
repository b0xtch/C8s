package sessionlauncher

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// Guest image file names, as confidential-os-builder writes them.
const (
	diskFile        = "disk.raw"
	tdxFirmwareFile = "OVMF.tdx.fd"
	manifestFile    = "manifest.json"
	opkeyISO        = "opkey.iso"
	scratchFile     = "scratch.raw"
	// scratchSerial is what the measured initrd keys the encrypted state
	// volume on. Without it the guest's writable state is a 2G RAM tmpfs.
	scratchSerial = "confai-scratch"
)

// Network modes for the guest's one interface.
const (
	// NetworkTap hands an interface of the launcher's network namespace to
	// the guest, as a pod's launcher does with the pod's own: same address,
	// same MAC, traffic redirected at L2. Needs NET_ADMIN there.
	NetworkTap = "tap"
	// NetworkUser is QEMU's user-mode stack with forwarded TCP ports. It needs
	// no privilege and is slower; it exists for bring-up.
	NetworkUser = "user"
	// NetworkFD takes a tap its caller opened and an address its caller chose.
	// The launcher then touches no interface and needs no privilege: this is
	// for a caller that owns the guest's network, such as a daemon that keeps
	// each guest in a namespace of its own.
	NetworkFD = "fd"
)

// The addresses of QEMU's user-mode network, said to QEMU and to the guest
// alike. They are QEMU's defaults, written out so that neither side depends
// on the other's.
const (
	userNetdev  = "net=10.0.2.0/24,host=10.0.2.2,dns=10.0.2.3,dhcpstart=10.0.2.15"
	userAddress = "10.0.2.15/24"
	userGateway = "10.0.2.2"
	userDNS     = "10.0.2.3"
)

// userNetwork is the guest's side of the user-mode network.
func userNetwork() *session.HostNetwork {
	return &session.HostNetwork{Address: userAddress, Gateway: userGateway, DNS: []string{userDNS}}
}

// Config describes one guest. Nothing in it is trusted by the guest or by a
// verifier: a wrong value yields a guest that fails to boot or fails to verify.
type Config struct {
	// Platform is the TEE to launch on: "tdx" or "snp".
	Platform string
	QEMU     string
	// ImageDir is the published guest image directory.
	ImageDir string
	// LaunchDir holds pubkey, launch.yaml and launch.yaml.sig.
	LaunchDir string
	// WorkDir receives the launch disk and the scratch disk for this guest.
	WorkDir   string
	Name      string
	VCPUs     int
	MemoryMiB int
	// LowMemoryMiB is how much of the guest's memory the machine places below
	// 4 GiB; the rest sits above. A confidential guest's firmware accepts
	// everything below 4 GiB before the kernel starts and nothing above, so
	// this is what a guest holds before it has used any. Zero leaves the
	// machine's own split, which puts up to 2 GiB and more below.
	LowMemoryMiB int
	ScratchMiB   int
	Network      string
	// Interface is the interface a tap guest takes over.
	Interface string
	// Forwards are the guest TCP ports published in user mode.
	Forwards []Forward
	// TapFD and VhostFD are descriptors this process inherited, for an fd
	// guest: an open tap and vhost-net for it. VhostFD is -1 for none.
	TapFD, VhostFD int
	// Guest is the network an fd guest is told to configure, and MAC the
	// address of its interface.
	Guest session.HostNetwork
	MAC   string
	// QuoteSocket is where QEMU reaches the host quoting service to answer the
	// guest's GetQuote (TDX): a unix socket path, or vsock:<cid>:<port>.
	// Without it the guest can only get a quote over its own vsock device.
	QuoteSocket string
	// VsockCID gives the guest a vsock device with this context id, which the
	// guest's quote path prefers. Zero attaches none.
	VsockCID uint32
	// VsockAuto gives the guest a vsock device with a context id no other
	// guest on this host holds, reserved through the kernel.
	VsockAuto bool
	// Collateral has the launcher fetch Intel's documents for the guest's
	// platform and hand them to the guest over its vsock device, so that a
	// verifier takes them from the guest and need not ask Intel (TDX).
	Collateral bool
	// AvoidFirstCPU keeps the VMM off the first online CPU of each package,
	// on TDX: see packageFirstCPUs.
	AvoidFirstCPU bool
	// Console attaches a virtio console wired to this process's stdout. A
	// locked image never gets one: the device is one more thing the host can
	// reach, and a console getty would answer on it.
	Console bool
	// ImageStore is a file of public images the guest may take its sandbox
	// image from: see `c8s session image-store`. Every guest of a host reads the
	// same one, and none can write it. Empty attaches none.
	ImageStore string
	// Confine holds the VMM as an unprivileged user in namespaces of its own.
	// Nil runs it as the launcher, where the launcher is.
	Confine *Confinement
	// tap, vsock and disks are filled in by Run from the descriptors QEMU
	// inherits.
	tap   *tapDevice
	vsock *vsockDevice
	disks *diskFiles
}

// Confinement is how the launcher holds the VMM, the one process on the host
// that reads what a guest sends it. It runs as a user with no capability,
// which owns no file and can open none in the work directory, in process, IPC
// and host name namespaces nothing else is in, and, unless the guest's
// network is QEMU's own user-mode stack, in a network namespace with no
// interface. The launcher needs CAP_SETUID, CAP_SETGID and CAP_SYS_ADMIN to
// start it so, and CAP_KILL to stop it.
type Confinement struct {
	UID, GID uint32
}

// ParseConfinement reads "uid[:gid]". The group defaults to the user's number.
func ParseConfinement(s string) (*Confinement, error) {
	user, group, hasGroup := strings.Cut(s, ":")
	uid, err := strconv.ParseUint(user, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("%q is not a numeric user id", user)
	}
	gid := uid
	if hasGroup {
		if gid, err = strconv.ParseUint(group, 10, 32); err != nil {
			return nil, fmt.Errorf("%q is not a numeric group id", group)
		}
	}
	// 2^32-1 is the kernel's "leave unchanged".
	if uid == 0 || gid == 0 || uid == 1<<32-1 || gid == 1<<32-1 {
		return nil, fmt.Errorf("the VMM is confined as a user and group other than root, got %s", s)
	}
	return &Confinement{UID: uint32(uid), GID: uint32(gid)}, nil
}

// Forward publishes one guest TCP port on the launcher's side of a user-mode
// network.
type Forward struct {
	// Address is the IPv4 address to listen on; empty listens on all of them.
	Address string
	Host    int
	Guest   int
}

// ParseForward reads "[address:]host:guest", or one port number for both.
func ParseForward(s string) (Forward, error) {
	parts := strings.Split(s, ":")
	if len(parts) > 3 {
		return Forward{}, fmt.Errorf("%q must be [address:]host:guest or a single port", s)
	}
	var f Forward
	if len(parts) == 3 {
		f.Address, parts = parts[0], parts[1:]
	}
	var err error
	if f.Host, err = strconv.Atoi(parts[0]); err != nil {
		return Forward{}, fmt.Errorf("%q: %q is not a port", s, parts[0])
	}
	f.Guest = f.Host
	if len(parts) == 2 {
		if f.Guest, err = strconv.Atoi(parts[1]); err != nil {
			return Forward{}, fmt.Errorf("%q: %q is not a port", s, parts[1])
		}
	}
	return f, f.validate()
}

func (f Forward) validate() error {
	for _, port := range []int{f.Host, f.Guest} {
		if port < 1 || port > 65535 {
			return fmt.Errorf("%d is not a TCP port", port)
		}
	}
	if f.Address != "" {
		// QEMU's hostfwd separates its fields with colons, which rules IPv6 out.
		if addr, err := netip.ParseAddr(f.Address); err != nil || !addr.Is4() {
			return fmt.Errorf("%q is not an IPv4 address", f.Address)
		}
	}
	return nil
}

// quoteSocketAddress renders --quote-socket as a QEMU SocketAddress. Intel's
// qgsd listens on a unix socket, on vsock, or on both, depending on its
// version and configuration.
func quoteSocketAddress(s string) (map[string]string, error) {
	if rest, ok := strings.CutPrefix(s, "vsock:"); ok {
		cid, port, found := strings.Cut(rest, ":")
		c, errCID := strconv.ParseUint(cid, 10, 32)
		p, errPort := strconv.ParseUint(port, 10, 32)
		if !found || errCID != nil || errPort != nil || p == 0 {
			return nil, fmt.Errorf("--quote-socket %q must be vsock:<cid>:<port>", s)
		}
		return map[string]string{"type": "vsock", "cid": strconv.FormatUint(c, 10), "port": strconv.FormatUint(p, 10)}, nil
	}
	if !filepath.IsAbs(s) || strings.Contains(s, ",") {
		return nil, fmt.Errorf("--quote-socket must be an absolute path with no comma, or vsock:<cid>:<port>")
	}
	return map[string]string{"type": "unix", "path": s}, nil
}

// tapDevice is an open tap QEMU inherits, so the VMM itself needs no network
// privilege. fd and vhostFD are the descriptor numbers QEMU sees; vhostFD is
// zero without vhost-net.
type tapDevice struct {
	mac         string
	fd, vhostFD int
}

// vsockDevice is a vhost-vsock descriptor QEMU inherits with its context id
// already reserved.
type vsockDevice struct {
	cid uint32
	fd  int
}

// diskFiles are the files a guest boots from and writes to, open, as the
// descriptor numbers QEMU sees: the firmware (TDX) or IGVM file (SEV-SNP),
// the image's root disk, the launch disk and the scratch disk. QEMU is given
// no path to any of them, so it needs no right to enter the directories they
// are in. scratch is zero for a guest without one, and images for a guest
// with no image store.
type diskFiles struct {
	firmware, root, opkey, scratch, images int
}

// QEMU's fd sets, which a drive names as /dev/fdset/<n>. QEMU duplicates the
// descriptor in the set and opens nothing.
const (
	rootSet    = 1
	scratchSet = 2
	opkeySet   = 3
	imagesSet  = 4
)

// fdPath names an open descriptor as a path, for the QEMU options that take
// only a path. Opening it checks the file's own permissions and no
// directory's, so the file must be readable by the VMM's user.
func fdPath(fd int) string { return "/proc/self/fd/" + strconv.Itoa(fd) }

// sandbox is QEMU's own seccomp filter at its strictest: no obsolete system
// call, no change of user or group, no new process, no change of scheduling.
// Installing it sets no_new_privs.
const sandbox = "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"

func (c *Config) validate() error {
	switch c.Platform {
	case "tdx", "snp":
	default:
		return fmt.Errorf("--platform must be tdx or snp")
	}
	for name, path := range map[string]string{"--qemu": c.QEMU, "--image-dir": c.ImageDir, "--launch-dir": c.LaunchDir, "--work-dir": c.WorkDir} {
		if path == "" {
			return fmt.Errorf("%s is required", name)
		}
		// QEMU splits option values on commas.
		if strings.Contains(path, ",") {
			return fmt.Errorf("%s %q contains a comma, which QEMU would read as an option separator", name, path)
		}
	}
	if c.QuoteSocket != "" {
		if _, err := quoteSocketAddress(c.QuoteSocket); err != nil {
			return err
		}
	}
	if c.VCPUs < 1 || c.VCPUs > 256 {
		return fmt.Errorf("--vcpus must be 1..256")
	}
	if c.MemoryMiB < 512 {
		return fmt.Errorf("--memory must be at least 512M")
	}
	// The firmware, the kernel it loads and the guest's bounce buffer all
	// live below 4 GiB: the guest image does not boot with 256M there.
	if c.LowMemoryMiB != 0 && (c.LowMemoryMiB < minLowMemoryMiB || c.LowMemoryMiB > c.MemoryMiB) {
		return fmt.Errorf("--low-memory must be 0, or between %dM and --memory", minLowMemoryMiB)
	}
	if c.ScratchMiB < 0 {
		return fmt.Errorf("--scratch must not be negative")
	}
	switch c.Network {
	case NetworkTap:
		if c.Interface == "" {
			return fmt.Errorf("--interface is required with --network tap")
		}
	case NetworkUser:
		if len(c.Forwards) == 0 {
			return fmt.Errorf("--port is required with --network user")
		}
		for _, forward := range c.Forwards {
			if err := forward.validate(); err != nil {
				return fmt.Errorf("--port: %w", err)
			}
		}
	case NetworkFD:
		// 0-2 are this process's own standard streams.
		if c.TapFD < 3 || (c.VhostFD != -1 && (c.VhostFD < 3 || c.VhostFD == c.TapFD)) {
			return fmt.Errorf("--tap-fd and --vhost-fd must be distinct inherited descriptors, 3 or greater")
		}
		if c.Guest.Address == "" {
			return fmt.Errorf("--guest-address is required with --network fd")
		}
		if err := (&session.HostConfig{Network: &c.Guest}).Validate(); err != nil {
			return fmt.Errorf("--guest-*: %w", err)
		}
		// QEMU reads the value as an option: only a parsed address is rendered.
		mac, err := net.ParseMAC(c.MAC)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
			return fmt.Errorf("--guest-mac must be a unicast Ethernet address")
		}
		c.MAC = mac.String()
	default:
		return fmt.Errorf("--network must be %s, %s or %s", NetworkTap, NetworkUser, NetworkFD)
	}
	// 0-2 are reserved and 0xffffffff is VMADDR_CID_ANY.
	if c.VsockCID != 0 && (c.VsockCID < 3 || c.VsockCID == 0xffffffff) {
		return fmt.Errorf("--vsock-cid must be 3 or greater")
	}
	if c.VsockAuto && c.VsockCID != 0 {
		return fmt.Errorf("--vsock-cid is either a number or auto")
	}
	if c.Name == "" || strings.ContainsAny(c.Name, ",= ") {
		return fmt.Errorf("--name must be set and contain no comma, equals sign or space")
	}
	return nil
}

// minLowMemoryMiB is the least memory below 4 GiB the launcher will ask for.
const minLowMemoryMiB = 384

// bareBoard turns off the devices a q35 board has by default and a session
// guest has no use for: the SATA controller, the SMBus, the keyboard
// controller, the HPET, USB and the VMware port. Each is a device its host
// emulates for the guest to probe: time at every boot, and code on both
// sides that nothing needs.
const bareBoard = "sata=off,smbus=off,i8042=off,hpet=off,usb=off,vmport=off"

// machine is the -machine value: the q35 chipset stripped to what a guest
// uses, with what the platform adds, and the memory split if one is set.
func (c *Config) machine(platform string) string {
	machine := "q35,confidential-guest-support=tee0," + platform + "kernel-irqchip=split," + bareBoard
	if c.LowMemoryMiB != 0 {
		machine += fmt.Sprintf(",max-ram-below-4g=%dM", c.LowMemoryMiB)
	}
	return machine
}

// QEMUArgs builds the complete argument vector. The launch public key is
// needed on SEV-SNP only, where the launcher commits its digest as HOST_DATA;
// on TDX the measured initrd binds it from inside the guest.
func (c *Config) QEMUArgs(launchPubPEM []byte) ([]string, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	args := []string{
		"-name", "guest=" + c.Name + ",debug-threads=off",
		"-nodefaults", "-no-user-config", "-nographic",
		// A guest that resets has lost its instance key and its measurements'
		// history. Exit instead: whatever replaces it is attested afresh.
		"-no-reboot",
		"-accel", "kvm",
		"-smp", strconv.Itoa(c.VCPUs),
		"-m", strconv.Itoa(c.MemoryMiB) + "M",
		"-monitor", "none", "-serial", "none",
		"-sandbox", sandbox,
	}
	if c.disks == nil {
		return nil, errors.New("the guest's disks are not open")
	}
	switch c.Platform {
	case "tdx":
		object := map[string]any{"qom-type": "tdx-guest", "id": "tee0"}
		if c.QuoteSocket != "" {
			address, err := quoteSocketAddress(c.QuoteSocket)
			if err != nil {
				return nil, err
			}
			object["quote-generation-socket"] = address
		}
		encoded, err := json.Marshal(object)
		if err != nil {
			return nil, err
		}
		args = append(args,
			// A named CPU model is refused for TDX; the TD sees what the module allows.
			"-cpu", "host",
			"-machine", c.machine(""),
			"-object", string(encoded),
			"-bios", fdPath(c.disks.firmware),
		)
	case "snp":
		if len(launchPubPEM) == 0 {
			return nil, errors.New("SEV-SNP launch needs the launch public key to commit as HOST_DATA")
		}
		// HOST_DATA = SHA-256 of the exact pubkey bytes, the SNP counterpart
		// of the RTMR[3] seed. The guest's initrd refuses to boot on a mismatch.
		hostData := sha256.Sum256(launchPubPEM)
		args = append(args,
			"-cpu", "EPYC-Genoa",
			"-machine", c.machine("igvm-cfg=igvm0,memory-backend=ram0,"),
			"-object", "igvm-cfg,id=igvm0,file="+fdPath(c.disks.firmware),
			"-object", fmt.Sprintf("memory-backend-memfd,id=ram0,size=%dM,share=true", c.MemoryMiB),
			"-object", "sev-snp-guest,id=tee0,cbitpos=51,reduced-phys-bits=1,host-data="+base64.StdEncoding.EncodeToString(hostData[:]),
		)
	}
	// Device order fixes guest names: the initrd expects the root on vda.
	args = append(args,
		"-add-fd", fmt.Sprintf("fd=%d,set=%d", c.disks.root, rootSet),
		"-drive", fmt.Sprintf("file=/dev/fdset/%d,format=raw,if=none,id=root0,readonly=on", rootSet),
		"-device", "virtio-blk-pci,drive=root0,bootindex=0",
	)
	if c.ScratchMiB > 0 {
		if c.disks.scratch == 0 {
			return nil, errors.New("the scratch disk is not open")
		}
		args = append(args,
			"-add-fd", fmt.Sprintf("fd=%d,set=%d", c.disks.scratch, scratchSet),
			// QEMU takes a descriptor from a set only if its access mode and
			// O_DIRECT are the ones it would open with. auto-read-only would
			// have it open read-only first, which the one descriptor is not.
			"-drive", fmt.Sprintf("file=/dev/fdset/%d,format=raw,if=none,id=scratch0,cache=none,discard=unmap,auto-read-only=off", scratchSet),
			"-device", "virtio-blk-pci,drive=scratch0,serial="+scratchSerial,
		)
	}
	args = append(args,
		"-add-fd", fmt.Sprintf("fd=%d,set=%d", c.disks.opkey, opkeySet),
		"-drive", fmt.Sprintf("file=/dev/fdset/%d,format=raw,if=none,id=opkey0,readonly=on", opkeySet),
		"-device", "virtio-blk-pci,drive=opkey0",
	)
	if c.ImageStore != "" {
		if c.disks.images == 0 {
			return nil, errors.New("the image store is not open")
		}
		// After the disks the guest boots from, so their names stay put. The
		// guest finds this one by its serial.
		args = append(args,
			"-add-fd", fmt.Sprintf("fd=%d,set=%d", c.disks.images, imagesSet),
			"-drive", fmt.Sprintf("file=/dev/fdset/%d,format=raw,if=none,id=images0,readonly=on", imagesSet),
			"-device", "virtio-blk-pci,drive=images0,serial="+session.ImageStoreSerial,
		)
	}
	switch c.Network {
	case NetworkTap, NetworkFD:
		if c.tap == nil {
			return nil, errors.New("tap network is not set up")
		}
		netdev := fmt.Sprintf("tap,id=net0,fd=%d", c.tap.fd)
		if c.tap.vhostFD != 0 {
			netdev += fmt.Sprintf(",vhost=on,vhostfd=%d", c.tap.vhostFD)
		}
		args = append(args,
			"-netdev", netdev,
			// romfile= keeps the firmware from adding a network boot option,
			// which would change the measured boot path.
			"-device", "virtio-net-pci,netdev=net0,mac="+c.tap.mac+",romfile=",
		)
	case NetworkUser:
		netdev := "user,id=net0," + userNetdev
		for _, forward := range c.Forwards {
			netdev += fmt.Sprintf(",hostfwd=tcp:%s:%d-:%d", forward.Address, forward.Host, forward.Guest)
		}
		args = append(args, "-netdev", netdev, "-device", "virtio-net-pci,netdev=net0,romfile=")
	}
	switch {
	case c.vsock != nil:
		args = append(args, "-device", fmt.Sprintf("vhost-vsock-pci,guest-cid=%d,vhostfd=%d", c.vsock.cid, c.vsock.fd))
	case c.VsockAuto:
		return nil, errors.New("no vsock context id is reserved")
	case c.VsockCID != 0:
		args = append(args, "-device", fmt.Sprintf("vhost-vsock-pci,guest-cid=%d", c.VsockCID))
	}
	if c.Console {
		args = append(args,
			"-chardev", "stdio,id=con0,signal=off",
			"-device", "virtio-serial-pci",
			"-device", "virtconsole,chardev=con0",
		)
	}
	return args, nil
}
