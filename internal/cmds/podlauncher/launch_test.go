package podlauncher

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
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/podcvmtest"
	"github.com/confidential-dot-ai/c8s/pkg/podcvm"
)

func baseConfig() Config {
	return Config{
		Platform: "tdx", QEMU: "/usr/bin/qemu-system-x86_64", ImageDir: "/images/pod", LaunchDir: "/launch",
		WorkDir: "/work", Name: "sbx-1", VCPUs: 2, MemoryMiB: 2048, ScratchMiB: 8192,
		Network: NetworkUser, Ports: []int{8443}, QuoteSocket: "/run/tdx-qgs/qgs.socket", VsockCID: 7,
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
		"-cpu", "host",
		"-machine", "q35,confidential-guest-support=tee0,kernel-irqchip=split",
		"-object", `{"id":"tee0","qom-type":"tdx-guest","quote-generation-socket":{"path":"/run/tdx-qgs/qgs.socket","type":"unix"}}`,
		"-bios", "/images/pod/OVMF.tdx.fd",
		"-drive", "file=/images/pod/disk.raw,format=raw,if=none,id=root0,readonly=on",
		"-device", "virtio-blk-pci,drive=root0,bootindex=0",
		"-drive", "file=/work/scratch.raw,format=raw,if=none,id=scratch0,cache=none,discard=unmap",
		"-device", "virtio-blk-pci,drive=scratch0,serial=confai-scratch",
		"-drive", "file=/work/opkey.iso,format=raw,if=none,id=opkey0,readonly=on",
		"-device", "virtio-blk-pci,drive=opkey0",
		"-netdev", "user,id=net0,hostfwd=tcp::8443-:8443",
		"-device", "virtio-net-pci,netdev=net0,romfile=",
		"-device", "vhost-vsock-pci,guest-cid=7",
	}
	if strings.Join(args, "\n") != strings.Join(want, "\n") {
		t.Fatalf("argv differs:\n got: %q\nwant: %q", args, want)
	}
	// A console is attached only on request: it is host-reachable surface.
	if strings.Contains(strings.Join(args, " "), "virtconsole") {
		t.Fatal("a guest got a console nobody asked for")
	}
	cfg.Console = true
	if args := strings.Join(mustArgs(t, &cfg, nil), " "); !strings.HasSuffix(args, "-chardev stdio,id=con0,signal=off -device virtio-serial-pci -device virtconsole,chardev=con0") {
		t.Fatalf("console arguments missing:\n%s", args)
	}
}

func TestQEMUArgsTap(t *testing.T) {
	cfg := baseConfig()
	cfg.Network, cfg.Interface, cfg.Ports = NetworkTap, "eth0", nil
	if _, err := cfg.QEMUArgs(nil); err == nil {
		t.Fatal("built tap arguments before the tap was set up")
	}
	cfg.tap = &tapDevice{mac: "02:42:ac:11:00:02", vhost: true}
	args := strings.Join(mustArgs(t, &cfg, nil), " ")
	for _, want := range []string{
		"-netdev tap,id=net0,fd=3,vhost=on,vhostfd=4",
		"-device virtio-net-pci,netdev=net0,mac=02:42:ac:11:00:02,romfile=",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("argv lacks %q:\n%s", want, args)
		}
	}
	cfg.tap.vhost = false
	if args := strings.Join(mustArgs(t, &cfg, nil), " "); strings.Contains(args, "vhost=on") || !strings.Contains(args, "-netdev tap,id=net0,fd=3 ") {
		t.Fatalf("argv without vhost-net is wrong:\n%s", args)
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
		"-object igvm-cfg,id=igvm0,file=/images/pod/guest-smp4.igvm",
		"-object memory-backend-memfd,id=ram0,size=2048M,share=true",
		"host-data=" + base64.StdEncoding.EncodeToString(digest[:]),
		"-machine q35,confidential-guest-support=tee0,igvm-cfg=igvm0,memory-backend=ram0,kernel-irqchip=split",
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
		"negative scratch":    func(c *Config) { c.ScratchMiB = -1 },
		"unknown network":     func(c *Config) { c.Network = "bridge" },
		"tap without iface":   func(c *Config) { c.Network, c.Interface = NetworkTap, "" },
		"user without ports":  func(c *Config) { c.Ports = nil },
		"bad port":            func(c *Config) { c.Ports = []int{70000} },
		"reserved vsock cid":  func(c *Config) { c.VsockCID = 2 },
		"name with comma":     func(c *Config) { c.Name = "a,b" },
		"empty name":          func(c *Config) { c.Name = "" },
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
}

// fakeQEMU stands in for the VMM: it records its arguments, copies the launch
// disk it was handed, and then behaves as told.
func fakeQEMU(t *testing.T, behaviour string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	record := filepath.Join(dir, "record")
	if err := os.Mkdir(record, 0o755); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
printf '%s\n' "$@" > "` + record + `/args"
for a in "$@"; do
  case "$a" in file=*opkey.iso,*) f=${a#file=}; cp "${f%%,*}" "` + record + `/opkey.iso" ;; esac
  case "$a" in file=*scratch.raw,*) f=${a#file=}; wc -c < "${f%%,*}" > "` + record + `/scratch-size" ;; esac
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
	td := podcvmtest.NewTD()
	bundle := filepath.Join(t.TempDir(), "bundle")
	if err := podcvm.NewBundle(podcvm.BundleOptions{Dir: bundle, ManifestPath: td.WriteManifest(t), Tenant: "acme", Sandbox: "sbx-1"}); err != nil {
		t.Fatal(err)
	}
	image := t.TempDir()
	for _, name := range []string{diskFile, tdxFirmwareFile} {
		if err := os.WriteFile(filepath.Join(image, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return Config{
		Platform: "tdx", QEMU: qemu, ImageDir: image, LaunchDir: filepath.Join(bundle, podcvm.OpkeyDir),
		WorkDir: filepath.Join(t.TempDir(), "work"), Name: "sbx-1", VCPUs: 1, MemoryMiB: 1024, ScratchMiB: 64,
		Network: NetworkUser, Ports: []int{8443},
	}
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestRunBuildsTheLaunchDiskAndStopsCleanly(t *testing.T) {
	qemu, record := fakeQEMU(t, "exec sleep 30")
	cfg := launchConfig(t, qemu)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, quiet) }()

	waitFor(t, filepath.Join(record, "scratch-size"))
	size, _ := os.ReadFile(filepath.Join(record, "scratch-size"))
	if strings.TrimSpace(string(size)) != "67108864" {
		t.Fatalf("scratch disk is %s bytes, want 64 MiB", bytes.TrimSpace(size))
	}
	if bsdtar, err := exec.LookPath("bsdtar"); err == nil {
		iso := filepath.Join(record, "opkey.iso")
		for _, name := range []string{podcvm.PubkeyFile, podcvm.DocumentFile, podcvm.SignatureFile} {
			want, err := os.ReadFile(filepath.Join(cfg.LaunchDir, name))
			if err != nil {
				t.Fatal(err)
			}
			got, err := exec.Command(bsdtar, "-xOf", iso, name).Output()
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("%s on the launch disk differs from the bundle (%v)", name, err)
			}
		}
		host, err := exec.Command(bsdtar, "-xOf", iso, podcvm.HostConfigFile).Output()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := podcvm.ParseHostConfig(host); err != nil {
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

func waitFor(t *testing.T, path string) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			return
		}
	}
	t.Fatalf("%s never appeared", path)
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
			path := filepath.Join(cfg.LaunchDir, podcvm.DocumentFile)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, bytes.Replace(data, []byte("tenant: acme"), []byte("tenant: evil"), 1), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"missing firmware": func(t *testing.T, cfg *Config) {
			if err := os.Remove(filepath.Join(cfg.ImageDir, tdxFirmwareFile)); err != nil {
				t.Fatal(err)
			}
		},
		"document for the other platform": func(t *testing.T, cfg *Config) { cfg.Platform = "snp" },
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
