package podlauncher

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/podcvm"
)

// opkeyLabel is the volume label the measured initrd looks for.
const opkeyLabel = "opkeydata"

// shutdownGrace is how long QEMU gets after SIGTERM. Guest state is ephemeral
// by construction, so there is nothing to flush.
const shutdownGrace = 10 * time.Second

// Run boots one guest and blocks until it exits or ctx ends. A guest that
// exits on its own is an error: the pod should restart and be attested afresh.
func Run(ctx context.Context, cfg Config, log *slog.Logger) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	pub, err := podcvm.ReadBounded(filepath.Join(cfg.LaunchDir, podcvm.PubkeyFile), 8192)
	if err != nil {
		return err
	}
	launch, err := podcvm.ReadBounded(filepath.Join(cfg.LaunchDir, podcvm.DocumentFile), podcvm.MaxDocumentSize)
	if err != nil {
		return err
	}
	signature, err := podcvm.ReadBounded(filepath.Join(cfg.LaunchDir, podcvm.SignatureFile), 4096)
	if err != nil {
		return err
	}
	// The guest is the one that enforces this. Checking here only turns a
	// bundle that could never boot into an immediate, legible failure.
	doc, err := podcvm.VerifySigned(pub, launch, string(signature))
	if err != nil {
		return fmt.Errorf("launch bundle in %s: %w", cfg.LaunchDir, err)
	}
	if doc.Image.Platform != cfg.Platform {
		return fmt.Errorf("launch document is for %s, launcher was asked for %s", doc.Image.Platform, cfg.Platform)
	}
	for _, name := range imageFiles(&cfg) {
		if _, err := os.Stat(filepath.Join(cfg.ImageDir, name)); err != nil {
			return fmt.Errorf("guest image: %w", err)
		}
	}
	if err := os.MkdirAll(cfg.WorkDir, 0o700); err != nil {
		return err
	}

	host := podcvm.HostConfig{}
	var inherited []*os.File
	if cfg.Network == NetworkTap {
		if host.Network, inherited, err = setupTap(&cfg); err != nil {
			return fmt.Errorf("tap network: %w", err)
		}
		defer func() {
			for _, f := range inherited {
				f.Close()
			}
		}()
	}
	hostJSON, err := json.Marshal(host)
	if err != nil {
		return err
	}
	iso, err := BuildISO(opkeyLabel, []ISOFile{
		{Name: podcvm.PubkeyFile, Data: pub},
		{Name: podcvm.DocumentFile, Data: launch},
		{Name: podcvm.SignatureFile, Data: signature},
		{Name: podcvm.HostConfigFile, Data: hostJSON},
	})
	if err != nil {
		return err
	}
	if err := fileutil.WriteAtomic(filepath.Join(cfg.WorkDir, opkeyISO), iso, 0o600); err != nil {
		return fmt.Errorf("write launch disk: %w", err)
	}
	if cfg.ScratchMiB > 0 {
		if err := createSparse(filepath.Join(cfg.WorkDir, scratchFile), int64(cfg.ScratchMiB)<<20); err != nil {
			return fmt.Errorf("create scratch disk: %w", err)
		}
	}
	args, err := cfg.QEMUArgs(pub)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, cfg.QEMU, args...)
	cmd.Stdin = nil
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.ExtraFiles = inherited
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = shutdownGrace
	log.Info("starting guest", "platform", cfg.Platform, "sandbox", doc.Sandbox, "tenant", doc.Tenant,
		"launch_digest", podcvm.LaunchDigest(launch), "vcpus", cfg.VCPUs, "memory_mib", cfg.MemoryMiB, "network", cfg.Network)
	started := time.Now()
	err = cmd.Run()
	// The scratch disk held only ciphertext under a key that died with the
	// guest; removing it just returns the space.
	_ = os.Remove(filepath.Join(cfg.WorkDir, scratchFile))
	_ = os.Remove(filepath.Join(cfg.WorkDir, opkeyISO))
	uptime := time.Since(started).Round(time.Millisecond).String()
	if ctx.Err() != nil {
		log.Info("guest stopped", "uptime", uptime)
		return nil
	}
	if err != nil {
		return fmt.Errorf("guest exited after %s: %w", uptime, err)
	}
	return fmt.Errorf("guest exited on its own after %s", uptime)
}

// imageFiles lists what the platform boots from.
func imageFiles(cfg *Config) []string {
	if cfg.Platform == "tdx" {
		return []string{diskFile, tdxFirmwareFile}
	}
	return []string{diskFile, fmt.Sprintf("guest-smp%d.igvm", cfg.VCPUs)}
}

// createSparse makes a fresh file of size bytes that occupies no blocks until
// the guest writes to it.
func createSparse(path string, size int64) error {
	_ = os.Remove(path)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := f.Truncate(size); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
