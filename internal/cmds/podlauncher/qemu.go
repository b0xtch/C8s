package podlauncher

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
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
	// NetworkTap hands the pod's own interface to the guest: same address,
	// same MAC, traffic redirected at L2. Needs NET_ADMIN in the pod.
	NetworkTap = "tap"
	// NetworkUser is QEMU's user-mode stack with forwarded TCP ports. It needs
	// no privilege and is slower; it exists for bring-up.
	NetworkUser = "user"
)

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
	WorkDir    string
	Name       string
	VCPUs      int
	MemoryMiB  int
	ScratchMiB int
	Network    string
	// Interface is the pod interface a tap guest takes over.
	Interface string
	// Forwards are the guest TCP ports published in user mode.
	Forwards []Forward
	// QuoteSocket is the host quoting service's unix socket (TDX). QEMU needs
	// it to answer the guest's GetQuote; without it only the vsock path works.
	QuoteSocket string
	// VsockCID gives the guest a vsock device with this context id, which the
	// guest's quote path prefers. Zero attaches none.
	VsockCID uint32
	// Console attaches a virtio console wired to this process's stdout. A
	// locked image never gets one: the device is one more thing the host can
	// reach, and a console getty would answer on it.
	Console bool
	// tap is filled in by network setup.
	tap *tapDevice
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

// tapDevice is a tap the launcher opened. QEMU inherits it as descriptor 3,
// and vhost-net as descriptor 4, so the VMM itself needs no network privilege.
type tapDevice struct {
	mac   string
	vhost bool
}

const (
	tapFDNumber   = 3
	vhostFDNumber = 4
)

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
	if c.QuoteSocket != "" && (strings.Contains(c.QuoteSocket, ",") || !filepath.IsAbs(c.QuoteSocket)) {
		return fmt.Errorf("--quote-socket must be an absolute path with no comma")
	}
	if c.VCPUs < 1 || c.VCPUs > 256 {
		return fmt.Errorf("--vcpus must be 1..256")
	}
	if c.MemoryMiB < 512 {
		return fmt.Errorf("--memory must be at least 512M")
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
	default:
		return fmt.Errorf("--network must be %s or %s", NetworkTap, NetworkUser)
	}
	// 0-2 are reserved and 0xffffffff is VMADDR_CID_ANY.
	if c.VsockCID != 0 && (c.VsockCID < 3 || c.VsockCID == 0xffffffff) {
		return fmt.Errorf("--vsock-cid must be 3 or greater")
	}
	if c.Name == "" || strings.ContainsAny(c.Name, ",= ") {
		return fmt.Errorf("--name must be set and contain no comma, equals sign or space")
	}
	return nil
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
		// history. Exit instead, so the pod restarts and is attested afresh.
		"-no-reboot",
		"-accel", "kvm",
		"-smp", strconv.Itoa(c.VCPUs),
		"-m", strconv.Itoa(c.MemoryMiB) + "M",
		"-monitor", "none", "-serial", "none",
	}
	switch c.Platform {
	case "tdx":
		object := map[string]any{"qom-type": "tdx-guest", "id": "tee0"}
		if c.QuoteSocket != "" {
			object["quote-generation-socket"] = map[string]string{"type": "unix", "path": c.QuoteSocket}
		}
		encoded, err := json.Marshal(object)
		if err != nil {
			return nil, err
		}
		args = append(args,
			// A named CPU model is refused for TDX; the TD sees what the module allows.
			"-cpu", "host",
			"-machine", "q35,confidential-guest-support=tee0,kernel-irqchip=split",
			"-object", string(encoded),
			"-bios", filepath.Join(c.ImageDir, tdxFirmwareFile),
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
			"-machine", "q35,confidential-guest-support=tee0,igvm-cfg=igvm0,memory-backend=ram0,kernel-irqchip=split",
			"-object", "igvm-cfg,id=igvm0,file="+filepath.Join(c.ImageDir, fmt.Sprintf("guest-smp%d.igvm", c.VCPUs)),
			"-object", fmt.Sprintf("memory-backend-memfd,id=ram0,size=%dM,share=true", c.MemoryMiB),
			"-object", "sev-snp-guest,id=tee0,cbitpos=51,reduced-phys-bits=1,host-data="+base64.StdEncoding.EncodeToString(hostData[:]),
		)
	}
	// Device order fixes guest names: the initrd expects the root on vda.
	args = append(args,
		"-drive", "file="+filepath.Join(c.ImageDir, diskFile)+",format=raw,if=none,id=root0,readonly=on",
		"-device", "virtio-blk-pci,drive=root0,bootindex=0",
	)
	if c.ScratchMiB > 0 {
		args = append(args,
			"-drive", "file="+filepath.Join(c.WorkDir, scratchFile)+",format=raw,if=none,id=scratch0,cache=none,discard=unmap",
			"-device", "virtio-blk-pci,drive=scratch0,serial="+scratchSerial,
		)
	}
	args = append(args,
		"-drive", "file="+filepath.Join(c.WorkDir, opkeyISO)+",format=raw,if=none,id=opkey0,readonly=on",
		"-device", "virtio-blk-pci,drive=opkey0",
	)
	switch c.Network {
	case NetworkTap:
		if c.tap == nil {
			return nil, errors.New("tap network is not set up")
		}
		netdev := fmt.Sprintf("tap,id=net0,fd=%d", tapFDNumber)
		if c.tap.vhost {
			netdev += fmt.Sprintf(",vhost=on,vhostfd=%d", vhostFDNumber)
		}
		args = append(args,
			"-netdev", netdev,
			// romfile= keeps the firmware from adding a network boot option,
			// which would change the measured boot path.
			"-device", "virtio-net-pci,netdev=net0,mac="+c.tap.mac+",romfile=",
		)
	case NetworkUser:
		netdev := "user,id=net0"
		for _, forward := range c.Forwards {
			netdev += fmt.Sprintf(",hostfwd=tcp:%s:%d-:%d", forward.Address, forward.Host, forward.Guest)
		}
		args = append(args, "-netdev", netdev, "-device", "virtio-net-pci,netdev=net0,romfile=")
	}
	if c.VsockCID != 0 {
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
