//go:build c8s_simtee

package sessionlauncher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/c8s/internal/simtee"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// simulation is a TEE the launcher simulates in software for its guest: the
// second baseline of docs/session-performance.md. With --simulated-tee the
// guest boots the image's firmware and disk with no TEE at all, and its
// launcher stands where a TDX module would: it declares the registers the
// image's manifest names, and hands the guest its platform's quoting
// enclave. Such a guest is protected from nobody. Only a build made with the
// c8s_simtee tag has this.
type simulation struct {
	// Dir is the simulated authority's directory ('c8s session simtee new').
	Dir string
	// authority is what Dir holds, and vendorAddress where its documents are
	// served.
	authority     *simtee.Directory
	vendorAddress string
}

// open reads the authority, before the launcher makes any road that leads
// to whoever serves its documents.
func (s *simulation) open(cfg *Config) (err error) {
	if !s.on() {
		return nil
	}
	if cfg.Platform != "tdx" {
		return fmt.Errorf("a TEE is simulated for tdx alone, and the guest's platform is %s", cfg.Platform)
	}
	if s.authority, err = simtee.LoadDirectory(s.Dir); err != nil {
		return err
	}
	s.vendorAddress, err = simtee.LoadVendor(s.Dir)
	return err
}

func (s *simulation) flags(f *pflag.FlagSet) {
	f.StringVar(&s.Dir, "simulated-tee", "",
		"DEVELOPMENT ONLY, and protects nothing: boot the guest with no TEE and simulate one in software, under the simulated authority in this directory ('c8s session simtee new'). The image must be one built for it. The launcher declares the registers its manifest names, where a TDX module would measure them")
}

func (s *simulation) on() bool { return s.Dir != "" }

// vendor is where a guest's road to one of the vendor's services leads: to
// whoever serves the simulated authority's documents, whichever service the
// road is named for.
func (s *simulation) vendor(service string) string {
	if !s.on() {
		return service
	}
	return s.vendorAddress
}

// fetcher asks whoever stands for the vendor for the documents a guest's
// host answers it with.
func (s *simulation) fetcher() func(context.Context, session.CollateralPlatform) ([]session.CollateralDocument, error) {
	if !s.on() {
		return session.FetchCollateral
	}
	vendor := simtee.NewRemote(s.vendorAddress, nil)
	return func(ctx context.Context, p session.CollateralPlatform) ([]session.CollateralDocument, error) {
		return session.FetchSimulatedCollateral(ctx, vendor, p)
	}
}

// stockDir keeps a simulated authority's documents apart from the vendor's:
// they have the same addresses.
func (s *simulation) stockDir(dir string) string {
	if !s.on() || dir == "" {
		return dir
	}
	return filepath.Join(dir, "simulated")
}

// imageManifest is what a launcher reads of an image's manifest: the
// registers a TD booted from the image holds, and the digests of the two
// files the registers were computed from.
type imageManifest struct {
	Outputs struct {
		DiskImage struct {
			SHA256 string `json:"sha256"`
		} `json:"disk_image"`
	} `json:"outputs"`
	TDX struct {
		MRTD     string `json:"mrtd"`
		RTMR1    string `json:"rtmr1"`
		RTMR2    string `json:"rtmr2"`
		Firmware struct {
			SHA256 string `json:"sha256"`
		} `json:"firmware"`
	} `json:"tdx"`
}

// maxManifest bounds an image's manifest.
const maxManifest = 1 << 20

// declare is what a simulated guest's launcher does where a TDX module would
// measure: it holds the firmware and the disk it hands the VMM to the
// digests the image's manifest names, and then declares the registers that
// manifest names for them. A run cannot report one image and boot another.
// The registers are declared and not measured: nothing in the guest's
// evidence shows what it booted.
func (s *simulation) declare(cfg *Config, firmware, disk *os.File) ([]ISOFile, error) {
	if !s.on() {
		return nil, nil
	}
	if s.authority == nil {
		return nil, errors.New("the simulated authority is not open")
	}
	data, err := session.ReadBounded(filepath.Join(cfg.ImageDir, manifestFile), maxManifest)
	if err != nil {
		return nil, err
	}
	var manifest imageManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("%s: %w", manifestFile, err)
	}
	for _, file := range []struct {
		name string
		f    *os.File
		want string
	}{{tdxFirmwareFile, firmware, manifest.TDX.Firmware.SHA256}, {diskFile, disk, manifest.Outputs.DiskImage.SHA256}} {
		if len(file.want) != 2*sha256.Size {
			return nil, fmt.Errorf("%s names no digest of %s", manifestFile, file.name)
		}
		got, err := digestOf(file.f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file.name, err)
		}
		if got != file.want {
			return nil, fmt.Errorf("%s is %s and %s names %s: the registers it names are another image's", file.name, got, manifestFile, file.want)
		}
	}
	var registers [3][48]byte
	for i, value := range []string{manifest.TDX.MRTD, manifest.TDX.RTMR1, manifest.TDX.RTMR2} {
		raw, err := hex.DecodeString(value)
		if err != nil || len(raw) != len(registers[i]) {
			return nil, fmt.Errorf("%s names no MRTD, RTMR[1] and RTMR[2] of 48 bytes each", manifestFile)
		}
		copy(registers[i][:], raw)
	}
	hardware, err := s.authority.NewHardware(registers[0], registers[1], registers[2], s.machine(cfg))
	if err != nil {
		return nil, err
	}
	encoded, err := hardware.Encode()
	if err != nil {
		return nil, err
	}
	if len(encoded) > simtee.MaxHardwareBytes {
		return nil, errors.New("the simulated hardware is more than a guest reads")
	}
	return []ISOFile{{Name: simtee.HardwareFile, Data: encoded}}, nil
}

// digestOf is the SHA-256 of an open file, read beside its offset: the VMM
// inherits the descriptor.
func digestOf(f *os.File) (string, error) {
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, info.Size())); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// machine describes the machine the launcher builds, for RTMR[0]: what a
// TD's firmware would measure of it. Two shapes are two machines, and two
// guests of one shape are one, whatever their names and addresses.
func (s *simulation) machine(cfg *Config) string {
	return fmt.Sprintf("vcpus=%d memory=%dM low=%dM scratch=%t network=%s vsock=%t images=%t console=%t",
		cfg.VCPUs, cfg.MemoryMiB, cfg.LowMemoryMiB, cfg.ScratchMiB > 0, networkDevice(cfg.Network),
		cfg.vsock != nil || cfg.VsockCID != 0, cfg.ImageStore != "", cfg.Console)
}

// networkDevice is the device a network mode gives the guest.
func networkDevice(mode string) string {
	if mode == NetworkNone {
		return "none"
	}
	return "virtio-net"
}
