package podlauncher

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/pkg/podcvm"
)

// NewCmd returns `c8s pod-launcher`, the host side of a pod CVM. It is the
// pod's one container: it boots the guest and stays until the guest is gone.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pod-launcher",
		Short: "Boot a pod CVM from a launch bundle (host side, untrusted)",
	}
	cmd.AddCommand(newRunCmd())
	return cmd
}

func newRunCmd() *cobra.Command {
	var cfg Config
	var memory, scratch string
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Boot one guest and wait for it",
		Long: `Boot the measured pod guest image as a confidential VM inside this pod's
cgroup and network namespace, with the launch bundle attached as its
opkeydata volume. The command returns when the guest exits or on SIGTERM.

Nothing here is trusted: the guest authenticates the launch bundle against
the key the hardware binds, and a verifier checks the guest. A launcher that
misbehaves produces a guest that will not boot or will not verify.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var err error
			if cfg.MemoryMiB, err = parseMiB(memory); err != nil {
				return fmt.Errorf("--memory: %w", err)
			}
			if cfg.ScratchMiB, err = parseMiB(scratch); err != nil {
				return fmt.Errorf("--scratch: %w", err)
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT)
			defer stop()
			return Run(ctx, cfg, slog.New(slog.NewJSONHandler(os.Stderr, nil)))
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.Platform, "platform", "", "TEE to launch on: tdx or snp (required)")
	f.StringVar(&cfg.QEMU, "qemu", "qemu-system-x86_64", "QEMU binary")
	f.StringVar(&cfg.ImageDir, "image-dir", "", "pod guest image directory (disk.raw, firmware, manifest.json)")
	f.StringVar(&cfg.LaunchDir, "launch-dir", "", "launch bundle's opkeydata directory")
	f.StringVar(&cfg.WorkDir, "work-dir", "", "directory for this guest's launch disk and scratch disk")
	f.StringVar(&cfg.Name, "name", "pod-cvm", "guest name, shown in the process list")
	f.IntVar(&cfg.VCPUs, "vcpus", 1, "guest vCPUs")
	f.StringVar(&memory, "memory", "1G", "guest memory, e.g. 2G or 1536M")
	f.StringVar(&scratch, "scratch", "8G", "encrypted scratch disk size; 0 leaves writable state on a 2G RAM tmpfs")
	f.StringVar(&cfg.Network, "network", NetworkTap, "tap: the guest takes over this pod's interface; user: QEMU user-mode stack with forwarded ports")
	f.StringVar(&cfg.Interface, "interface", "eth0", "pod interface the guest takes over (--network tap)")
	f.IntSliceVar(&cfg.Ports, "port", []int{podcvm.AgentPort}, "TCP port forwarded to the guest (--network user)")
	f.StringVar(&cfg.QuoteSocket, "quote-socket", "", "host quoting service unix socket (TDX)")
	f.Uint32Var(&cfg.VsockCID, "vsock-cid", 0, "guest vsock context id, for the fast quote path; 0 attaches no vsock device")
	f.BoolVar(&cfg.Console, "console", false, "attach a guest console to this process's output (dev images; a locked image prints nothing)")
	for _, name := range []string{"platform", "image-dir", "launch-dir", "work-dir"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

// parseMiB reads a size with an M or G suffix as mebibytes.
func parseMiB(s string) (int, error) {
	if s == "0" {
		return 0, nil
	}
	mult := 0
	switch {
	case strings.HasSuffix(s, "G"):
		mult = 1024
	case strings.HasSuffix(s, "M"):
		mult = 1
	default:
		return 0, fmt.Errorf("%q needs an M or G suffix", s)
	}
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || n <= 0 || n > 1<<20 {
		return 0, fmt.Errorf("%q is not a size", s)
	}
	return n * mult, nil
}
