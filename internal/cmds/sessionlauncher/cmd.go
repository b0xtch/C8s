package sessionlauncher

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// NewCmd returns `c8s session-launcher`, the host side of one guest: it boots
// the guest and stays until the guest is gone.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session-launcher",
		Short: "Boot one session guest from a launch bundle (host side, untrusted)",
	}
	cmd.AddCommand(newRunCmd())
	return cmd
}

func newRunCmd() *cobra.Command {
	var cfg Config
	var memory, lowMemory, scratch, vsock, confine string
	var ports []string
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Boot one guest and wait for it",
		Long: `Boot the measured session guest image as a confidential VM in this
process's cgroup and network namespace, with the launch bundle attached as
its opkeydata volume. The command returns when the guest exits or on SIGTERM.

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
			if cfg.LowMemoryMiB, err = parseMiB(lowMemory); err != nil {
				return fmt.Errorf("--low-memory: %w", err)
			}
			if cfg.ScratchMiB, err = parseMiB(scratch); err != nil {
				return fmt.Errorf("--scratch: %w", err)
			}
			for _, spec := range ports {
				forward, err := ParseForward(spec)
				if err != nil {
					return fmt.Errorf("--port: %w", err)
				}
				cfg.Forwards = append(cfg.Forwards, forward)
			}
			if cfg.VsockCID, cfg.VsockAuto, err = parseVsock(vsock); err != nil {
				return fmt.Errorf("--vsock-cid: %w", err)
			}
			if confine != "" {
				if cfg.Confine, err = ParseConfinement(confine); err != nil {
					return fmt.Errorf("--confine: %w", err)
				}
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT)
			defer stop()
			return Run(ctx, cfg, slog.New(slog.NewJSONHandler(os.Stderr, nil)))
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.Platform, "platform", "", "TEE to launch on: tdx or snp (required)")
	f.StringVar(&cfg.QEMU, "qemu", "qemu-system-x86_64", "QEMU binary")
	f.StringVar(&cfg.ImageDir, "image-dir", "", "session guest image directory (disk.raw, firmware, manifest.json)")
	f.StringVar(&cfg.LaunchDir, "launch-dir", "", "launch bundle's opkeydata directory")
	f.StringVar(&cfg.WorkDir, "work-dir", "", "directory for this guest's launch disk and scratch disk")
	f.StringVar(&cfg.Name, "name", "c8s-session", "guest name, shown in the process list")
	f.IntVar(&cfg.VCPUs, "vcpus", 1, "guest vCPUs")
	f.StringVar(&memory, "memory", "1G", "guest memory, e.g. 2G or 1536M")
	f.StringVar(&lowMemory, "low-memory", "0", "how much of the guest's memory sits below 4 GiB, e.g. 512M; the rest sits above, where a confidential guest's firmware accepts none of it before the kernel runs, so a guest whose kernel accepts memory as it uses it starts with this much. 0 leaves the machine's own split. It changes RTMR[0]")
	f.StringVar(&scratch, "scratch", "8G", "encrypted scratch disk size; 0 leaves writable state on a 2G RAM tmpfs")
	f.StringVar(&cfg.Network, "network", NetworkTap, "tap: the guest takes over an interface of this network namespace, as a pod's launcher hands its guest the pod's own; user: QEMU user-mode stack with forwarded ports; fd: a tap the caller opened, with the address the caller states")
	f.StringVar(&cfg.Interface, "interface", "eth0", "interface the guest takes over (--network tap)")
	f.StringArrayVar(&ports, "port", []string{strconv.Itoa(session.AgentPort)},
		"guest TCP port to publish (--network user): [address:]host:guest, or one port for both")
	f.IntVar(&cfg.TapFD, "tap-fd", 3, "inherited descriptor of the guest's tap (--network fd)")
	f.IntVar(&cfg.VhostFD, "vhost-fd", -1, "inherited descriptor of vhost-net for that tap (--network fd); -1 for none")
	f.StringVar(&cfg.Guest.Address, "guest-address", "", "address the guest configures, in CIDR form (--network fd)")
	f.StringVar(&cfg.Guest.Gateway, "guest-gateway", "", "the guest's default gateway (--network fd)")
	f.StringArrayVar(&cfg.Guest.DNS, "guest-dns", nil, "a resolver for the guest, up to three (--network fd)")
	f.IntVar(&cfg.Guest.MTU, "guest-mtu", 0, "the guest's link MTU (--network fd); 0 leaves the default")
	f.StringVar(&cfg.MAC, "guest-mac", "", "Ethernet address of the guest's interface (--network fd)")
	f.StringVar(&cfg.QuoteSocket, "quote-socket", "", "host quoting service (TDX): a unix socket path, or vsock:<cid>:<port>")
	f.StringVar(&vsock, "vsock-cid", "0", "guest vsock context id, for the fast quote path: a number, auto for one no other guest on the host holds, or 0 for no vsock device")
	f.BoolVar(&cfg.Collateral, "collateral", true, "answer the guest's asks for Intel's collateral for its platform; the guest passes it on to its verifiers so that they need not ask Intel (TDX with --vsock-cid). A verifier checks Intel's signatures and dates on it either way")
	f.StringVar(&cfg.CollateralCache, "collateral-cache", "", "directory the launchers of this host keep Intel's collateral in, so that a guest is answered with what another guest's launcher fetched; empty has this launcher fetch for itself")
	f.BoolVar(&cfg.AvoidFirstCPU, "avoid-first-cpu", true, "keep the VMM off the first online CPU of each package (TDX): when a host frees any guest's key it writes the package's caches back on that CPU, in an interrupt handler, and whatever runs there waits")
	f.BoolVar(&cfg.Console, "console", false, "attach a guest console to this process's output (dev images; a locked image prints nothing)")
	f.StringVar(&cfg.ImageStore, "image-store", "", "a store of public images, written by 'c8s session image-store', that the guest takes sandbox images from before it asks a registry; read-only, and shared by every guest launched with it")
	f.StringVar(&confine, "confine", "", "run QEMU as this numeric uid[:gid], with no capability and in process, IPC, host name and (except --network user) network namespaces of its own; needs CAP_SETUID, CAP_SETGID, CAP_SYS_ADMIN and CAP_KILL here")
	for _, name := range []string{"platform", "image-dir", "launch-dir", "work-dir"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

// parseVsock reads --vsock-cid: a context id, or auto.
func parseVsock(s string) (cid uint32, auto bool, err error) {
	if s == "auto" {
		return 0, true, nil
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, false, fmt.Errorf("%q is neither a context id nor auto", s)
	}
	return uint32(n), false, nil
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
