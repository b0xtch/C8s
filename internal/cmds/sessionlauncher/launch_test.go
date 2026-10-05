package sessionlauncher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

func baseConfig() Config {
	return Config{
		Platform: "tdx", QEMU: "/usr/bin/qemu-system-x86_64", ImageDir: "/images/session", LaunchDir: "/launch",
		WorkDir: "/work", Name: "sbx-1", VCPUs: 2, MemoryMiB: 2048, ScratchMiB: 8192,
		Network: NetworkUser, Forwards: []Forward{{Host: 8443, Guest: 8443}}, QuoteSocket: "/run/tdx-qgs/qgs.socket", VsockCID: 7,
		disks: &diskFiles{firmware: 3, root: 4, opkey: 5, scratch: 6},
	}
}

func TestQEMUArgsTDX(t *testing.T) {
	cfg := baseConfig()
	args, err := cfg.QEMUArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"-name", "guest=sbx-1,debug-threads=off",
		"-nodefaults", "-no-user-config", "-nographic", "-no-reboot",
		"-accel", "kvm", "-smp", "2", "-m", "2048M", "-monitor", "none", "-serial", "none",
		"-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
		"-cpu", "host",
		"-machine", "q35,confidential-guest-support=tee0,kernel-irqchip=split,sata=off,smbus=off,i8042=off,hpet=off,usb=off,vmport=off",
		"-object", `{"id":"tee0","qom-type":"tdx-guest","quote-generation-socket":{"path":"/run/tdx-qgs/qgs.socket","type":"unix"}}`,
		"-bios", "/proc/self/fd/3",
		"-add-fd", "fd=4,set=1",
		"-drive", "file=/dev/fdset/1,format=raw,if=none,id=root0,readonly=on",
		"-device", "virtio-blk-pci,drive=root0,bootindex=0,disable-legacy=on",
		"-add-fd", "fd=6,set=2",
		"-drive", "file=/dev/fdset/2,format=raw,if=none,id=scratch0,cache=none,discard=unmap,auto-read-only=off",
		"-device", "virtio-blk-pci,drive=scratch0,serial=confai-scratch,disable-legacy=on",
		"-add-fd", "fd=5,set=3",
		"-drive", "file=/dev/fdset/3,format=raw,if=none,id=opkey0,readonly=on",
		"-device", "virtio-blk-pci,drive=opkey0,disable-legacy=on",
		"-netdev", "user,id=net0,net=10.0.2.0/24,host=10.0.2.2,dns=10.0.2.3,dhcpstart=10.0.2.15,hostfwd=tcp::8443-:8443",
		"-device", "virtio-net-pci,netdev=net0,romfile=,disable-legacy=on",
		"-device", "vhost-vsock-pci,guest-cid=7,disable-legacy=on",
	}
	if strings.Join(args, "\n") != strings.Join(want, "\n") {
		t.Fatalf("argv differs:\n got: %q\nwant: %q", args, want)
	}
	// A console is attached only on request: it is host-reachable surface.
	if strings.Contains(strings.Join(args, " "), "virtconsole") {
		t.Fatal("a guest got a console nobody asked for")
	}
	// So is an image store: read-only, after the disks the guest boots from,
	// under the serial the guest looks for.
	if strings.Contains(strings.Join(args, " "), "images0") {
		t.Fatal("a guest got an image store nobody asked for")
	}
	stored := baseConfig()
	stored.ImageStore, stored.disks.images = "/var/lib/c8s/images.store", 7
	got := strings.Join(mustArgs(t, &stored, nil), "\n")
	// The network and the vsock device are the last six arguments.
	withStore := strings.Join(want[:len(want)-6], "\n") + "\n" + strings.Join([]string{
		"-add-fd", "fd=7,set=4",
		"-drive", "file=/dev/fdset/4,format=raw,if=none,id=images0,readonly=on",
		"-device", "virtio-blk-pci,drive=images0,serial=c8s-images,disable-legacy=on",
	}, "\n") + "\n" + strings.Join(want[len(want)-6:], "\n")
	if got != withStore {
		t.Fatalf("argv with an image store differs:\n got: %q\nwant: %q", got, withStore)
	}
	if strings.Contains(got, stored.ImageStore) {
		t.Fatal("argv names the image store's path")
	}
	stored.disks.images = 0
	if _, err := stored.QEMUArgs(nil); err == nil {
		t.Fatal("built arguments for an image store that is not open")
	}
	cfg.Console = true
	if args := strings.Join(mustArgs(t, &cfg, nil), " "); !strings.HasSuffix(args, "-chardev stdio,id=con0,signal=off -device virtio-serial-pci,disable-legacy=on -device virtconsole,chardev=con0") {
		t.Fatalf("console arguments missing:\n%s", args)
	}
}

// The memory split is the machine's, on either platform, and is left to the
// machine unless it is asked for.
func TestQEMUArgsLowMemory(t *testing.T) {
	for platform, machine := range map[string]string{
		"tdx": "-machine q35,confidential-guest-support=tee0,kernel-irqchip=split,sata=off,smbus=off,i8042=off,hpet=off,usb=off,vmport=off",
		"snp": "-machine q35,confidential-guest-support=tee0,igvm-cfg=igvm0,memory-backend=ram0,kernel-irqchip=split,sata=off,smbus=off,i8042=off,hpet=off,usb=off,vmport=off",
	} {
		cfg := baseConfig()
		cfg.Platform = platform
		pub := []byte("-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----\n")
		if args := strings.Join(mustArgs(t, &cfg, pub), " "); !strings.Contains(args, machine+" ") || strings.Contains(args, "max-ram-below-4g") {
			t.Fatalf("%s without a split:\n%s", platform, args)
		}
		cfg.LowMemoryMiB = 512
		if args := strings.Join(mustArgs(t, &cfg, pub), " "); !strings.Contains(args, machine+",max-ram-below-4g=512M ") || !strings.Contains(args, "-m 2048M") {
			t.Fatalf("%s with 512M below 4 GiB:\n%s", platform, args)
		}
	}
}

// QEMU is handed every file open. Its arguments name no path of the image or
// of the work directory, so a VMM that can enter neither still boots.
func TestQEMUArgsNameNoFile(t *testing.T) {
	for _, platform := range []string{"tdx", "snp"} {
		cfg := baseConfig()
		cfg.Platform, cfg.QuoteSocket = platform, ""
		args := strings.Join(mustArgs(t, &cfg, []byte("key")), " ")
		for _, path := range []string{cfg.ImageDir, cfg.WorkDir} {
			if strings.Contains(args, path) {
				t.Errorf("%s: argv names a path under %s:\n%s", platform, path, args)
			}
		}
	}
	cfg := baseConfig()
	cfg.disks = nil
	if _, err := cfg.QEMUArgs(nil); err == nil {
		t.Error("built arguments before the guest's files were open")
	}
	cfg = baseConfig()
	cfg.disks.scratch = 0
	if _, err := cfg.QEMUArgs(nil); err == nil {
		t.Error("built arguments for a scratch disk that is not open")
	}
	cfg.ScratchMiB = 0
	if args := strings.Join(mustArgs(t, &cfg, nil), " "); strings.Contains(args, "scratch0") {
		t.Errorf("a guest with no scratch disk got one:\n%s", args)
	}
}

func TestParseConfinement(t *testing.T) {
	for in, want := range map[string]Confinement{"64055": {64055, 64055}, "64055:991": {64055, 991}} {
		if got, err := ParseConfinement(in); err != nil || *got != want {
			t.Errorf("%q = %+v, %v; want %+v", in, got, err, want)
		}
	}
	// Root is what the VMM is confined from, and 2^32-1 leaves an id as it is.
	for _, bad := range []string{"", "0", "0:991", "64055:0", "qemu", "64055:kvm", "-1", "4294967295", "64055:4294967295", "4294967296", "1:2:3"} {
		if got, err := ParseConfinement(bad); err == nil {
			t.Errorf("%q accepted as %+v", bad, got)
		}
	}
}

func TestQEMUArgsTap(t *testing.T) {
	cfg := baseConfig()
	cfg.Network, cfg.Interface, cfg.Forwards = NetworkTap, "eth0", nil
	if _, err := cfg.QEMUArgs(nil); err == nil {
		t.Fatal("built tap arguments before the tap was set up")
	}
	cfg.tap = &tapDevice{mac: "02:42:ac:11:00:02", fd: 3, vhostFD: 4}
	args := strings.Join(mustArgs(t, &cfg, nil), " ")
	for _, want := range []string{
		"-netdev tap,id=net0,fd=3,vhost=on,vhostfd=4",
		"-device virtio-net-pci,netdev=net0,mac=02:42:ac:11:00:02,romfile=,disable-legacy=on",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("argv lacks %q:\n%s", want, args)
		}
	}
	cfg.tap.vhostFD = 0
	if args := strings.Join(mustArgs(t, &cfg, nil), " "); strings.Contains(args, "vhost=on") || !strings.Contains(args, "-netdev tap,id=net0,fd=3 ") {
		t.Fatalf("argv without vhost-net is wrong:\n%s", args)
	}
}

func fdConfig() Config {
	cfg := baseConfig()
	cfg.Network, cfg.Forwards, cfg.VsockCID = NetworkFD, nil, 0
	cfg.TapFD, cfg.VhostFD = 3, -1
	cfg.Guest = session.HostNetwork{Address: "169.254.17.2/30", Gateway: "169.254.17.1", DNS: []string{"169.254.17.1"}, MTU: 1500}
	cfg.MAC = "02:A8:1E:00:00:02"
	cfg.disks = &diskFiles{firmware: 6, root: 7, opkey: 8, scratch: 9}
	return cfg
}

// An fd guest's descriptors are numbered by the order QEMU inherits them in,
// whatever numbers the launcher itself was handed.
func TestQEMUArgsInheritedDevices(t *testing.T) {
	cfg := fdConfig()
	if _, err := cfg.QEMUArgs(nil); err == nil {
		t.Fatal("built fd arguments before the tap was wrapped")
	}
	cfg.tap = &tapDevice{mac: "02:a8:1e:00:00:02", fd: 3, vhostFD: 4}
	cfg.VsockAuto = true
	if _, err := cfg.QEMUArgs(nil); err == nil {
		t.Fatal("built arguments for an automatic context id that was never reserved")
	}
	cfg.vsock = &vsockDevice{cid: 70000, fd: 5}
	args := strings.Join(mustArgs(t, &cfg, nil), " ")
	for _, want := range []string{
		"-netdev tap,id=net0,fd=3,vhost=on,vhostfd=4",
		"-device virtio-net-pci,netdev=net0,mac=02:a8:1e:00:00:02,romfile=,disable-legacy=on",
		"-device vhost-vsock-pci,guest-cid=70000,vhostfd=5,disable-legacy=on",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("argv lacks %q:\n%s", want, args)
		}
	}
}

func TestFDNetworkValidation(t *testing.T) {
	cfg := fdConfig()
	if err := cfg.validate(); err != nil {
		t.Fatalf("control: %v", err)
	}
	if cfg.MAC != "02:a8:1e:00:00:02" {
		t.Fatalf("MAC rendered as %q, want its canonical form", cfg.MAC)
	}
	for name, mutate := range map[string]func(*Config){
		"standard stream as tap": func(c *Config) { c.TapFD = 2 },
		"one descriptor twice":   func(c *Config) { c.VhostFD = 3 },
		"negative vhost":         func(c *Config) { c.VhostFD = -2 },
		"no address":             func(c *Config) { c.Guest.Address = "" },
		"address without prefix": func(c *Config) { c.Guest.Address = "169.254.17.2" },
		"gateway off the link":   func(c *Config) { c.Guest.Gateway = "10.0.0.1" },
		"resolver with a zone":   func(c *Config) { c.Guest.DNS = []string{"fe80::1%eth0"} },
		"tiny MTU":               func(c *Config) { c.Guest.MTU = 100 },
		"no MAC":                 func(c *Config) { c.MAC = "" },
		"MAC with an option":     func(c *Config) { c.MAC = "02:a8:1e:00:00:02,romfile=x" },
		"multicast MAC":          func(c *Config) { c.MAC = "01:00:5e:00:00:01" },
		"long MAC":               func(c *Config) { c.MAC = "02:a8:1e:00:00:02:00:01" },
		"id and auto":            func(c *Config) { c.VsockAuto, c.VsockCID = true, 7 },
	} {
		cfg := fdConfig()
		mutate(&cfg)
		if err := cfg.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseVsock(t *testing.T) {
	for in, want := range map[string]struct {
		cid  uint32
		auto bool
	}{"0": {0, false}, "4243": {4243, false}, "auto": {0, true}} {
		if cid, auto, err := parseVsock(in); err != nil || cid != want.cid || auto != want.auto {
			t.Errorf("%q = %d, %v, %v", in, cid, auto, err)
		}
	}
	for _, bad := range []string{"", "AUTO", "-1", "4294967296", "7,vhostfd=0"} {
		if _, _, err := parseVsock(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// The kernel refuses an id another guest holds. The launcher moves on to
// another one, and stops at any other refusal.
func TestPickCID(t *testing.T) {
	taken := 0
	cid, err := pickCID(func(cid uint64) error {
		if cid < 1<<16 || cid >= 1<<31 {
			t.Fatalf("tried context id %d, outside the range left for automatic ids", cid)
		}
		if taken++; taken < 5 {
			return syscall.EADDRINUSE
		}
		return nil
	})
	if err != nil || cid < 1<<16 || taken != 5 {
		t.Fatalf("cid %d after %d attempts: %v", cid, taken, err)
	}
	if _, err := pickCID(func(uint64) error { return syscall.EADDRINUSE }); err == nil {
		t.Fatal("reported an id although every one was taken")
	}
	calls := 0
	if _, err := pickCID(func(uint64) error { calls++; return syscall.EPERM }); err == nil || calls != 1 {
		t.Fatalf("a refusal that no other id would fix was retried %d times: %v", calls, err)
	}
}

func TestQuoteSocketForms(t *testing.T) {
	cfg := baseConfig()
	cfg.QuoteSocket = "vsock:2:4050"
	if args := strings.Join(mustArgs(t, &cfg, nil), " "); !strings.Contains(args, `"quote-generation-socket":{"cid":"2","port":"4050","type":"vsock"}`) {
		t.Fatalf("vsock quoting service not rendered:\n%s", args)
	}
	for _, bad := range []string{"vsock:2", "vsock:two:4050", "vsock:2:0", "vsock:2:port", "vsock::4050", "unix:/run/qgs.socket", "qgs.socket"} {
		cfg.QuoteSocket = bad
		if err := cfg.validate(); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseForward(t *testing.T) {
	for spec, want := range map[string]Forward{
		"8443":                 {Host: 8443, Guest: 8443},
		"18443:8443":           {Host: 18443, Guest: 8443},
		"127.0.0.1:18443:8443": {Address: "127.0.0.1", Host: 18443, Guest: 8443},
	} {
		if got, err := ParseForward(spec); err != nil || got != want {
			t.Errorf("%s = %+v, %v; want %+v", spec, got, err, want)
		}
	}
	// A comma or an IPv6 address would change what QEMU reads from hostfwd=.
	for _, spec := range []string{"", "0", "70000", "a:8443", "8443:b", "::1:18443:8443", "127.0.0.1,x:1:2", "localhost:1:2", "1:2:3:4"} {
		if got, err := ParseForward(spec); err == nil {
			t.Errorf("%q accepted as %+v", spec, got)
		}
	}
	cfg := baseConfig()
	cfg.Forwards = []Forward{{Address: "127.0.0.1", Host: 18443, Guest: 8443}}
	if args := strings.Join(mustArgs(t, &cfg, nil), " "); !strings.Contains(args, "-netdev user,id=net0,"+userNetdev+",hostfwd=tcp:127.0.0.1:18443-:8443 ") {
		t.Fatalf("forward not rendered:\n%s", args)
	}
}

func mustArgs(t *testing.T, cfg *Config, pub []byte) []string {
	t.Helper()
	args, err := cfg.QEMUArgs(pub)
	if err != nil {
		t.Fatal(err)
	}
	return args
}

// SEV-SNP is designed for and has never run on hardware. This pins the launch
// shape the node image's own SNP lane uses, with HOST_DATA committing the
// launch key.
func TestQEMUArgsSNPCommitsLaunchKey(t *testing.T) {
	cfg := baseConfig()
	cfg.Platform, cfg.VCPUs, cfg.QuoteSocket, cfg.VsockCID = "snp", 4, "", 0
	if _, err := cfg.QEMUArgs(nil); err == nil {
		t.Fatal("an SNP guest was launched without committing a launch key")
	}
	pub := []byte("-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----\n")
	args := strings.Join(mustArgs(t, &cfg, pub), " ")
	digest := sha256.Sum256(pub)
	for _, want := range []string{
		"-object igvm-cfg,id=igvm0,file=/proc/self/fd/3",
		"-object memory-backend-memfd,id=ram0,size=2048M,share=true",
		"host-data=" + base64.StdEncoding.EncodeToString(digest[:]),
		"-machine q35,confidential-guest-support=tee0,igvm-cfg=igvm0,memory-backend=ram0,kernel-irqchip=split,sata=off,smbus=off,i8042=off,hpet=off,usb=off,vmport=off",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("argv lacks %q:\n%s", want, args)
		}
	}
	if strings.Contains(args, "-bios") {
		t.Fatal("an IGVM launch must not also pass firmware")
	}
}

func TestConfigValidate(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"platform":            func(c *Config) { c.Platform = "sgx" },
		"comma in image dir":  func(c *Config) { c.ImageDir = "/images/a,readonly=off" },
		"comma in work dir":   func(c *Config) { c.WorkDir = "/work,x" },
		"relative qgs socket": func(c *Config) { c.QuoteSocket = "qgs.socket" },
		"comma in qgs socket": func(c *Config) { c.QuoteSocket = "/run/a,b" },
		"no vcpus":            func(c *Config) { c.VCPUs = 0 },
		"tiny memory":         func(c *Config) { c.MemoryMiB = 64 },
		"low memory too low":  func(c *Config) { c.LowMemoryMiB = 383 },
		"low memory negative": func(c *Config) { c.LowMemoryMiB = -512 },
		"low memory over all": func(c *Config) { c.LowMemoryMiB = 2049 },
		"negative scratch":    func(c *Config) { c.ScratchMiB = -1 },
		"unknown network":     func(c *Config) { c.Network = "bridge" },
		"tap without iface":   func(c *Config) { c.Network, c.Interface = NetworkTap, "" },
		"user without ports":  func(c *Config) { c.Forwards = nil },
		"bad port":            func(c *Config) { c.Forwards = []Forward{{Host: 70000, Guest: 8443}} },
		"reserved vsock cid":  func(c *Config) { c.VsockCID = 2 },
		"no device, no vsock": func(c *Config) { c.Network, c.VsockCID, c.VsockAuto = NetworkNone, 0, false },
		"no device, bad port": func(c *Config) {
			c.Network, c.VsockAuto, c.Forwards = NetworkNone, true, []Forward{{Host: 8443, Guest: 0}}
		},
		"name with comma": func(c *Config) { c.Name = "a,b" },
		"empty name":      func(c *Config) { c.Name = "" },
	} {
		cfg := baseConfig()
		mutate(&cfg)
		if err := cfg.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	cfg := baseConfig()
	if err := cfg.validate(); err != nil {
		t.Fatalf("control: %v", err)
	}
	// From the least that boots to all of it.
	for _, low := range []int{384, 512, 2048} {
		cfg.LowMemoryMiB = low
		if err := cfg.validate(); err != nil {
			t.Fatalf("%dM below 4 GiB: %v", low, err)
		}
	}
}

// A guest with no network device is given none: no back end, no card. Its
// socket to the host is its only road, so the mode needs one, and the ports
// it publishes are the launcher's to carry, of which QEMU is told nothing.
func TestQEMUArgsNoNetworkDevice(t *testing.T) {
	cfg := baseConfig()
	cfg.Network, cfg.VsockCID = NetworkNone, 7
	cfg.Forwards = []Forward{{Address: "127.0.0.1", Host: 18543, Guest: 8443}}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	args := strings.Join(mustArgs(t, &cfg, nil), " ")
	for _, absent := range []string{"-netdev", "virtio-net", "hostfwd", "18543", "-nic"} {
		if strings.Contains(args, absent) {
			t.Fatalf("a guest with no network device was given %q:\n%s", absent, args)
		}
	}
	if !strings.Contains(args, "vhost-vsock-pci,guest-cid=7") {
		t.Fatalf("a guest with no network device has no socket to its host:\n%s", args)
	}
	// With no port to publish it is a guest nobody reaches, which is its
	// launcher's caller's business.
	cfg.Forwards, cfg.VsockCID, cfg.VsockAuto = nil, 0, true
	if err := cfg.validate(); err != nil {
		t.Fatalf("a guest with no network device and no published port: %v", err)
	}
}

// fakeQEMU stands in for the VMM: it records its arguments, reads the disks it
// was handed open, and then behaves as told.
func fakeQEMU(t *testing.T, behaviour string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	record := filepath.Join(dir, "record")
	if err := os.Mkdir(record, 0o755); err != nil {
		t.Fatal(err)
	}
	// A confined VMM is another user: it has to reach the script, and to
	// write what it saw.
	for d, mode := range map[string]os.FileMode{filepath.Dir(dir): 0o755, dir: 0o755, record: 0o777} {
		if err := os.Chmod(d, mode); err != nil {
			t.Fatal(err)
		}
	}
	script := `#!/bin/sh
record="` + record + `"
printf '%s\n' "$@" > "$record/args"
prev=
for a in "$@"; do
  if [ "$prev" = -add-fd ]; then
    fd=${a#fd=}; fd=${fd%%,*}
    case "${a##*set=}" in
      2) wc -c <&$fd | tr -d ' ' > "$record/scratch-size" ;;
      3) cat <&$fd > "$record/opkey.iso" ;;
      4) cat <&$fd > "$record/images"
         # A program and no builtin: a shell keeps what a builtin failed to
         # write and prints it later, somewhere else. And dd, because the
         # echo of uutils coreutils exits 0 when its write fails.
         if dd if=/dev/zero bs=1 count=1 >&$fd 2>/dev/null; then echo writable; else echo read-only; fi > "$record/images-mode" ;;
    esac
  fi
  prev=$a
done
for n in 3 4 5 6 7 8 9; do
  # true and not ":": dash ends the script when a special builtin's
  # redirection fails.
  if { true <&$n; } 2>/dev/null; then echo open; else echo closed; fi > "$record/fd$n"
done
` + behaviour + "\n"
	path := filepath.Join(dir, "qemu")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, record
}

func launchConfig(t *testing.T, qemu string) Config {
	t.Helper()
	td := sessiontest.NewTD()
	bundle := filepath.Join(t.TempDir(), "bundle")
	if err := session.NewBundle(session.BundleOptions{Dir: bundle, ManifestPath: td.WriteManifest(t), Pool: "agents", Class: "s-4x16"}); err != nil {
		t.Fatal(err)
	}
	image := t.TempDir()
	for _, name := range []string{diskFile, tdxFirmwareFile} {
		if err := os.WriteFile(filepath.Join(image, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return Config{
		Platform: "tdx", QEMU: qemu, ImageDir: image, LaunchDir: filepath.Join(bundle, session.OpkeyDir),
		WorkDir: filepath.Join(t.TempDir(), "work"), Name: "sbx-1", VCPUs: 1, MemoryMiB: 1024, ScratchMiB: 64,
		Network: NetworkUser, Forwards: []Forward{{Host: 8443, Guest: 8443}},
	}
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestRunBuildsTheLaunchDiskAndStopsCleanly(t *testing.T) {
	qemu, record := fakeQEMU(t, "exec sleep 30")
	cfg := launchConfig(t, qemu)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, quiet) }()

	waitFor(t, filepath.Join(record, "fd9"), done)
	size, _ := os.ReadFile(filepath.Join(record, "scratch-size"))
	if strings.TrimSpace(string(size)) != "67108864" {
		t.Fatalf("scratch disk is %s bytes, want 64 MiB", bytes.TrimSpace(size))
	}
	args, _ := os.ReadFile(filepath.Join(record, "args"))
	for _, path := range []string{cfg.ImageDir, cfg.WorkDir} {
		if strings.Contains(string(args), path) {
			t.Fatalf("QEMU was given a path under %s:\n%s", path, args)
		}
	}
	// The firmware, the root disk, the launch disk and the scratch disk.
	for name, want := range map[string]string{"fd3": "open", "fd4": "open", "fd5": "open", "fd6": "open", "fd7": "closed"} {
		if got, _ := os.ReadFile(filepath.Join(record, name)); strings.TrimSpace(string(got)) != want {
			t.Errorf("QEMU saw %s %s, want %s", name, bytes.TrimSpace(got), want)
		}
	}
	if bsdtar, err := exec.LookPath("bsdtar"); err == nil {
		iso := filepath.Join(record, "opkey.iso")
		for _, name := range []string{session.PubkeyFile, session.DocumentFile, session.SignatureFile} {
			want, err := os.ReadFile(filepath.Join(cfg.LaunchDir, name))
			if err != nil {
				t.Fatal(err)
			}
			got, err := exec.Command(bsdtar, "-xOf", iso, name).Output()
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("%s on the launch disk differs from the bundle (%v)", name, err)
			}
		}
		host, err := exec.Command(bsdtar, "-xOf", iso, session.HostConfigFile).Output()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := session.ParseHostConfig(host); err != nil {
			t.Fatalf("host.json on the launch disk does not parse: %v (%s)", err, host)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a requested stop is not an error: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	for _, name := range []string{scratchFile, opkeyISO} {
		if _, err := os.Stat(filepath.Join(cfg.WorkDir, name)); err == nil {
			t.Fatalf("%s was left behind", name)
		}
	}
}

// An fd guest gets the caller's descriptors as 3 and 4, in that order, ahead
// of its four files, and is told the caller's address. The launcher opens no
// device of its own.
func TestRunPassesInheritedDescriptorsAndTheStatedNetwork(t *testing.T) {
	qemu, record := fakeQEMU(t, "exec sleep 30")
	cfg := launchConfig(t, qemu)
	tap, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer tap.Close()
	vhost, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer vhost.Close()
	cfg.Network, cfg.Forwards = NetworkFD, nil
	// Run closes what it wraps, so hand it duplicates.
	cfg.TapFD, cfg.VhostFD = dupFD(t, tap), dupFD(t, vhost)
	cfg.Guest = session.HostNetwork{Address: "169.254.17.2/30", Gateway: "169.254.17.1", DNS: []string{"169.254.17.1"}, MTU: 1500}
	cfg.MAC = "02:a8:1e:00:00:02"

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, quiet) }()
	waitFor(t, filepath.Join(record, "fd9"), done)
	for name, want := range map[string]string{"fd3": "open", "fd4": "open", "fd8": "open", "fd9": "closed"} {
		if got, _ := os.ReadFile(filepath.Join(record, name)); strings.TrimSpace(string(got)) != want {
			t.Errorf("QEMU saw %s %s, want %s", name, bytes.TrimSpace(got), want)
		}
	}
	args, _ := os.ReadFile(filepath.Join(record, "args"))
	if !strings.Contains(string(args), "tap,id=net0,fd=3,vhost=on,vhostfd=4\n") || !strings.Contains(string(args), "mac=02:a8:1e:00:00:02,") {
		t.Errorf("QEMU was not given the inherited tap:\n%s", args)
	}
	if bsdtar, err := exec.LookPath("bsdtar"); err == nil {
		host, err := exec.Command(bsdtar, "-xOf", filepath.Join(record, "opkey.iso"), session.HostConfigFile).Output()
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := session.ParseHostConfig(host)
		if err != nil || parsed.Network == nil {
			t.Fatalf("host.json on the launch disk: %v (%s)", err, host)
		}
		if n := parsed.Network; n.Address != "169.254.17.2/30" || n.Gateway != "169.254.17.1" || len(n.DNS) != 1 || n.DNS[0] != "169.254.17.1" || n.MTU != 1500 {
			t.Fatalf("the guest was told %+v", *n)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a requested stop is not an error: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	cfg = launchConfig(t, qemu)
	cfg.Network, cfg.Forwards, cfg.TapFD, cfg.VhostFD = NetworkFD, nil, 1<<20, -1
	cfg.Guest, cfg.MAC = session.HostNetwork{Address: "169.254.17.2/30"}, "02:a8:1e:00:00:02"
	if err := Run(context.Background(), cfg, quiet); err == nil || !strings.Contains(err.Error(), "not open") {
		t.Fatalf("a descriptor nobody passed was accepted: %v", err)
	}
}

func dupFD(t *testing.T, f *os.File) int {
	t.Helper()
	fd, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	return fd
}

// waitFor waits for the fake QEMU to write path. done is where Run's result
// goes: a Run that returned will never start it.
func waitFor(t *testing.T, path string, done <-chan error) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("Run returned before %s appeared: %v", filepath.Base(path), err)
		default:
		}
	}
	t.Fatalf("%s never appeared", path)
}

// A guest launched with an image store is handed the file open for reading:
// what one guest reads, no guest can change for the next.
func TestRunHandsTheImageStoreToTheGuestReadOnly(t *testing.T) {
	qemu, record := fakeQEMU(t, "exec sleep 30")
	cfg := launchConfig(t, qemu)
	cfg.ImageStore = filepath.Join(t.TempDir(), "images.store")
	if err := os.WriteFile(cfg.ImageStore, []byte("a store"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, quiet) }()
	waitFor(t, filepath.Join(record, "fd9"), done)

	if got, _ := os.ReadFile(filepath.Join(record, "images")); string(got) != "a store" {
		t.Fatalf("the guest's image store reads %q", got)
	}
	if mode, _ := os.ReadFile(filepath.Join(record, "images-mode")); strings.TrimSpace(string(mode)) != "read-only" {
		t.Fatalf("the guest's image store is %s", bytes.TrimSpace(mode))
	}
	if after, _ := os.ReadFile(cfg.ImageStore); string(after) != "a store" {
		t.Fatalf("the store now holds %q", after)
	}
	args, _ := os.ReadFile(filepath.Join(record, "args"))
	if !strings.Contains(string(args), "serial=c8s-images") || strings.Contains(string(args), cfg.ImageStore) {
		t.Fatalf("QEMU's arguments for the store:\n%s", args)
	}
	// One more file than a guest without a store: firmware, root, launch
	// disk, image store and scratch disk.
	for name, want := range map[string]string{"fd7": "open", "fd8": "closed"} {
		if got, _ := os.ReadFile(filepath.Join(record, name)); strings.TrimSpace(string(got)) != want {
			t.Errorf("QEMU saw %s %s, want %s", name, bytes.TrimSpace(got), want)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return after its context ended")
	}
}

func TestRunReportsAGuestThatExits(t *testing.T) {
	for name, behaviour := range map[string]string{"clean exit": "exit 0", "crash": "exit 1"} {
		t.Run(name, func(t *testing.T) {
			qemu, _ := fakeQEMU(t, behaviour)
			if err := Run(context.Background(), launchConfig(t, qemu), quiet); err == nil {
				t.Fatal("a guest that exited on its own was reported as success")
			}
		})
	}
}

func TestRunRefusesBeforeStartingQEMU(t *testing.T) {
	for name, mutate := range map[string]func(t *testing.T, cfg *Config){
		"tampered launch document": func(t *testing.T, cfg *Config) {
			path := filepath.Join(cfg.LaunchDir, session.DocumentFile)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, bytes.Replace(data, []byte("pool: agents"), []byte("pool: others"), 1), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"missing firmware": func(t *testing.T, cfg *Config) {
			if err := os.Remove(filepath.Join(cfg.ImageDir, tdxFirmwareFile)); err != nil {
				t.Fatal(err)
			}
		},
		"document for the other platform": func(t *testing.T, cfg *Config) { cfg.Platform = "snp" },
		"an image store that is not there": func(t *testing.T, cfg *Config) {
			cfg.ImageStore = filepath.Join(t.TempDir(), "absent.store")
		},
		"an image store that is a directory": func(t *testing.T, cfg *Config) { cfg.ImageStore = t.TempDir() },
	} {
		t.Run(name, func(t *testing.T) {
			qemu, record := fakeQEMU(t, "exit 0")
			cfg := launchConfig(t, qemu)
			mutate(t, &cfg)
			if err := Run(context.Background(), cfg, quiet); err == nil {
				t.Fatal("launched")
			}
			if _, err := os.Stat(filepath.Join(record, "args")); err == nil {
				t.Fatal("QEMU was started for a launch that should have been refused")
			}
		})
	}
}

// A user-mode guest has no DHCP client. What the launcher tells it is what
// the launcher tells QEMU, and it is a request the guest's loader accepts.
func TestUserNetworkMatchesQEMU(t *testing.T) {
	n := userNetwork()
	if err := (&session.HostConfig{Network: n}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"host=" + n.Gateway, "dns=" + n.DNS[0], "dhcpstart=" + strings.TrimSuffix(n.Address, "/24"), "net=10.0.2.0/24"} {
		if !strings.Contains(userNetdev, want) {
			t.Errorf("QEMU is told %q, which lacks %q", userNetdev, want)
		}
	}
}
