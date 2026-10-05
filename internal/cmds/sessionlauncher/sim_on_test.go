//go:build c8s_simtee

package sessionlauncher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/c8s/internal/simtee"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// simulated turns cfg into a guest whose TEE is simulated: an authority's
// directory whose documents somebody serves, and a manifest that names the
// image's two files and the registers a TD booted from them holds.
func simulated(t *testing.T, cfg *Config) (registers [3][48]byte) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "authority")
	if _, err := simtee.NewDirectory(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, simtee.VendorFile), []byte("127.0.0.1:9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.sim.Dir = dir
	for i := range registers {
		registers[i] = sha512.Sum384([]byte{byte(i)})
	}
	writeManifest(t, cfg, registers, nil)
	return registers
}

// writeManifest writes the image's manifest, with the digests of the files
// as they are unless digests names another for one.
func writeManifest(t *testing.T, cfg *Config, registers [3][48]byte, digests map[string]string) {
	t.Helper()
	digest := func(name string) string {
		if other, ok := digests[name]; ok {
			return other
		}
		data, err := os.ReadFile(filepath.Join(cfg.ImageDir, name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:])
	}
	manifest := fmt.Sprintf(`{"version": 3,
  "outputs": {"disk_image": {"path": "disk.raw", "sha256": %q}},
  "tdx": {"mrtd": "%x", "rtmr1": "%x", "rtmr2": "%x", "firmware": {"path": "OVMF.tdx.fd", "sha256": %q}}}`,
		digest(diskFile), registers[0], registers[1], registers[2], digest(tdxFirmwareFile))
	if err := os.WriteFile(filepath.Join(cfg.ImageDir, manifestFile), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A simulated guest is the machine a TD of its class is, with nothing that
// guards it: the same board, CPU, firmware and devices, no TDX object, and
// no quoting service to reach.
func TestSimulatedGuestIsTheSameMachineWithNoTEE(t *testing.T) {
	guarded := baseConfig()
	want, err := guarded.QEMUArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	plain := baseConfig()
	plain.sim.Dir = "/authority"
	got, err := plain.QEMUArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	var expect []string
	for i := 0; i < len(want); i++ {
		switch {
		case want[i] == "-object" && strings.Contains(want[i+1], "tdx-guest"):
			i++
		case want[i] == "-machine":
			expect = append(expect, "-machine", strings.Replace(want[i+1], "confidential-guest-support=tee0,", "", 1))
			i++
		default:
			expect = append(expect, want[i])
		}
	}
	if strings.Join(got, "\n") != strings.Join(expect, "\n") {
		t.Fatalf("a simulated guest's machine:\n got: %q\nwant: %q", got, expect)
	}
	for _, word := range []string{"tdx-guest", "confidential-guest-support", "tee0", "qgs", "sev-snp-guest"} {
		if strings.Contains(strings.Join(got, " "), word) {
			t.Errorf("a simulated guest was given %q", word)
		}
	}
	if len(got) != len(want)-2 {
		t.Fatalf("a simulated guest has %d arguments and a TD %d: only the TDX object goes", len(got), len(want))
	}
}

// The launcher of a simulated guest stands where the TDX module would: it
// holds the two files it hands the VMM to the digests the manifest names,
// declares that manifest's registers, and hands the guest the quoting
// enclave of the authority's platform. The guest's quotes then verify under
// that authority's root and carry those registers.
func TestRunDeclaresTheRegistersOfTheImageItBoots(t *testing.T) {
	bsdtar, err := exec.LookPath("bsdtar")
	if err != nil {
		t.Skip("no bsdtar to read the launch disk with")
	}
	qemu, record := fakeQEMU(t, "exec sleep 30")
	cfg := launchConfig(t, qemu)
	registers := simulated(t, &cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, quiet) }()
	waitFor(t, filepath.Join(record, "fd9"), done)
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("a requested stop: %v", err)
		}
	}()

	args, _ := os.ReadFile(filepath.Join(record, "args"))
	if strings.Contains(string(args), "tdx-guest") || strings.Contains(string(args), "confidential-guest-support") {
		t.Fatalf("the VMM was asked for a TEE:\n%s", args)
	}
	data, err := exec.Command(bsdtar, "-xOf", filepath.Join(record, "opkey.iso"), simtee.HardwareFile).Output()
	if err != nil {
		t.Fatalf("no %s on the launch disk: %v", simtee.HardwareFile, err)
	}
	hardware, err := simtee.ParseHardware(data)
	if err != nil {
		t.Fatal(err)
	}
	machine, err := hardware.Boot()
	if err != nil {
		t.Fatal(err)
	}
	if machine.MRTD != registers[0] || machine.RTMR[1] != registers[1] || machine.RTMR[2] != registers[2] {
		t.Fatal("the guest's registers are not the ones the image's manifest names")
	}
	shape := sha512.Sum384([]byte("c8s simulated TEE: machine\x00" + cfg.sim.machine(&cfg)))
	if machine.RTMR[0] != shape {
		t.Fatal("RTMR[0] is not the digest of the machine the launcher built")
	}
	root, err := simtee.LoadRoot(cfg.sim.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if !machine.Root.Equal(root) {
		t.Fatal("the guest's authority is not the directory's")
	}
	var reportData [64]byte
	copy(reportData[:], "a guest's key")
	raw, err := machine.Quote([48]byte{3}, reportData)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := abi.QuoteToProto(raw)
	if err != nil {
		t.Fatal(err)
	}
	body := parsed.(*pb.QuoteV4).GetTdQuoteBody()
	if !bytes.Equal(body.GetMrTd(), registers[0][:]) || !bytes.Equal(body.GetRtmrs()[2], registers[2][:]) ||
		!bytes.Equal(body.GetRtmrs()[3], append([]byte{3}, make([]byte, 47)...)) || !bytes.Equal(body.GetReportData(), reportData[:]) {
		t.Fatal("the guest's quote does not carry its registers and its report data")
	}
	// The other launch files are as on any guest's volume.
	for _, name := range []string{session.PubkeyFile, session.DocumentFile, session.SignatureFile, session.HostConfigFile} {
		if _, err := exec.Command(bsdtar, "-xOf", filepath.Join(record, "opkey.iso"), name).Output(); err != nil {
			t.Errorf("%s is not on the launch disk: %v", name, err)
		}
	}
}

// A launcher declares no registers for files they were not computed from,
// under no authority it cannot read, and for no platform but TDX. It starts
// no VMM then.
func TestSimulatedLaunchRefusesBeforeStartingQEMU(t *testing.T) {
	other := strings.Repeat("ab", sha256.Size)
	for name, c := range map[string]struct {
		change func(t *testing.T, cfg *Config, registers [3][48]byte)
		want   string
	}{
		"another firmware than the manifest's": {func(t *testing.T, cfg *Config, registers [3][48]byte) {
			writeManifest(t, cfg, registers, map[string]string{tdxFirmwareFile: other})
		}, "OVMF.tdx.fd is "},
		"another disk than the manifest's": {func(t *testing.T, cfg *Config, registers [3][48]byte) {
			writeManifest(t, cfg, registers, map[string]string{diskFile: other})
		}, "disk.raw is "},
		"a disk changed after its manifest was written": {func(t *testing.T, cfg *Config, _ [3][48]byte) {
			if err := os.WriteFile(filepath.Join(cfg.ImageDir, diskFile), []byte("y"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "the registers it names are another image's"},
		"a manifest that names no digest of the disk": {func(t *testing.T, cfg *Config, registers [3][48]byte) {
			writeManifest(t, cfg, registers, map[string]string{diskFile: ""})
		}, "names no digest of disk.raw"},
		"a manifest that names no digest of the firmware": {func(t *testing.T, cfg *Config, registers [3][48]byte) {
			writeManifest(t, cfg, registers, map[string]string{tdxFirmwareFile: "abcd"})
		}, "names no digest of OVMF.tdx.fd"},
		"no manifest": {func(t *testing.T, cfg *Config, _ [3][48]byte) {
			if err := os.Remove(filepath.Join(cfg.ImageDir, manifestFile)); err != nil {
				t.Fatal(err)
			}
		}, manifestFile},
		"a manifest that is none": {func(t *testing.T, cfg *Config, _ [3][48]byte) {
			if err := os.WriteFile(filepath.Join(cfg.ImageDir, manifestFile), []byte("{"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, manifestFile},
		"a manifest with a register that is none": {func(t *testing.T, cfg *Config, _ [3][48]byte) {
			path := filepath.Join(cfg.ImageDir, manifestFile)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var manifest map[string]any
			if err := json.Unmarshal(data, &manifest); err != nil {
				t.Fatal(err)
			}
			manifest["tdx"].(map[string]any)["rtmr2"] = "00"
			if data, err = json.Marshal(manifest); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatal(err)
			}
		}, "names no MRTD, RTMR[1] and RTMR[2]"},
		"an authority nobody serves the documents of": {func(t *testing.T, cfg *Config, _ [3][48]byte) {
			if err := os.Remove(filepath.Join(cfg.sim.Dir, simtee.VendorFile)); err != nil {
				t.Fatal(err)
			}
		}, "nobody serves its documents"},
		"a directory that holds no authority": {func(t *testing.T, cfg *Config, _ [3][48]byte) {
			cfg.sim.Dir = t.TempDir()
		}, "simulated authority"},
	} {
		t.Run(name, func(t *testing.T) {
			qemu, record := fakeQEMU(t, "exit 0")
			cfg := launchConfig(t, qemu)
			registers := simulated(t, &cfg)
			c.change(t, &cfg, registers)
			err := Run(context.Background(), cfg, quiet)
			if err == nil || !strings.Contains(err.Error(), "simulated TEE: ") || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("launched, or refused for another reason: %v", err)
			}
			if _, err := os.Stat(filepath.Join(record, "args")); err == nil {
				t.Fatal("the VMM was started for a guest whose registers could not be declared")
			}
		})
	}
	// SEV-SNP has no simulation: nothing declares its launch digest.
	var s simulation
	s.Dir = t.TempDir()
	if err := s.open(&Config{Platform: "snp"}); err == nil || !strings.Contains(err.Error(), "for tdx alone") {
		t.Fatalf("a TEE was simulated for SEV-SNP: %v", err)
	}
}

// RTMR[0] tells two shapes apart and nothing else: two guests of one shape
// are one machine, whatever their names, addresses and context ids.
func TestSimulatedMachineIsTheShape(t *testing.T) {
	var s simulation
	base := baseConfig()
	one := s.machine(&base)
	same := baseConfig()
	same.Name, same.VsockCID, same.MAC, same.WorkDir, same.QuoteSocket = "sbx-2", 9, "02:00:00:00:00:02", "/elsewhere", ""
	if got := s.machine(&same); got != one {
		t.Fatalf("two guests of one shape are two machines: %q and %q", one, got)
	}
	for name, change := range map[string]func(c *Config){
		"vcpus":              func(c *Config) { c.VCPUs++ },
		"memory":             func(c *Config) { c.MemoryMiB += 1024 },
		"the memory's split": func(c *Config) { c.LowMemoryMiB = 512 },
		"no scratch disk":    func(c *Config) { c.ScratchMiB = 0 },
		"no network device":  func(c *Config) { c.Network = NetworkNone },
		"no vsock device":    func(c *Config) { c.VsockCID = 0 },
		"an image store":     func(c *Config) { c.ImageStore = "/images.store" },
		"a console":          func(c *Config) { c.Console = true },
	} {
		other := baseConfig()
		change(&other)
		if s.machine(&other) == one {
			t.Errorf("%s: the machine is described as the same one", name)
		}
	}
}

// Every road a simulated replica's launcher carries leads to whoever serves
// the simulated authority's documents, and its host's copies of them are
// kept apart from the vendor's. With the option unset the build is any
// other: the vendor's service, and the vendor's documents.
func TestSimulationLeadsToTheSimulatedVendorAlone(t *testing.T) {
	services, err := session.VendorServices("tdx")
	if err != nil {
		t.Fatal(err)
	}
	var off simulation
	if off.on() || off.vendor(services[0]) != services[0] || off.stockDir("/stock") != "/stock" {
		t.Fatal("a launcher that was asked for no simulation is not as any other")
	}
	if files, err := off.declare(&Config{}, nil, nil); err != nil || files != nil {
		t.Fatalf("a launcher that was asked for no simulation declared %v (%v)", files, err)
	}
	if err := off.open(&Config{Platform: "snp"}); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Platform: "tdx", ImageDir: t.TempDir()}
	for _, name := range []string{diskFile, tdxFirmwareFile} {
		if err := os.WriteFile(filepath.Join(cfg.ImageDir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	simulated(t, &cfg)
	if err := cfg.sim.open(&cfg); err != nil {
		t.Fatal(err)
	}
	for _, service := range services {
		if got := cfg.sim.vendor(service); got != "127.0.0.1:9" {
			t.Errorf("the road named for %s leads to %s", service, got)
		}
	}
	if got := cfg.sim.stockDir("/stock"); got != "/stock/simulated" {
		t.Errorf("the simulated authority's documents are kept in %s", got)
	}
	if got := cfg.sim.stockDir(""); got != "" {
		t.Errorf("a launcher that keeps no documents keeps the simulated ones in %s", got)
	}
}

// The option is the only way to a simulation, and says what it is.
func TestSimulatedTEEFlagSaysWhatItIs(t *testing.T) {
	flag := newRunCmd().Flags().Lookup("simulated-tee")
	if flag == nil {
		t.Fatal("a build made for the simulation has no --simulated-tee")
	}
	if flag.DefValue != "" || !strings.Contains(flag.Usage, "DEVELOPMENT ONLY") || !strings.Contains(flag.Usage, "protects nothing") {
		t.Fatalf("--simulated-tee: default %q, usage %q", flag.DefValue, flag.Usage)
	}
	var s simulation
	set := pflag.NewFlagSet("launcher", pflag.ContinueOnError)
	s.flags(set)
	if err := set.Parse([]string{"--simulated-tee", "/authority"}); err != nil || !s.on() || s.Dir != "/authority" {
		t.Fatalf("--simulated-tee /authority: %v, on %v", err, s.on())
	}
}
