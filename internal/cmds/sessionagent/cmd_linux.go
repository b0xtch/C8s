//go:build linux

package sessionagent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"slices"
	"strconv"
	"strings"

	containerdlog "github.com/containerd/log"
	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/imagestore"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// Paths baked into the session guest image. The units that pass them are on the
// verity root, so they are part of what the image measurement covers.
const (
	defaultPubkeyPath    = "/etc/confai/operator-pubkey"
	defaultLaunchDir     = "/run/c8s-session/launch"
	defaultNetworkDir    = "/run/systemd/network"
	defaultCredentialDir = "/run/c8s/credentials"
	defaultSandboxUser   = "sandbox"
	// /var is a writable overlay on the encrypted scratch volume.
	defaultStateDir   = "/var/lib/c8s-session"
	defaultRuntimeDir = "/run/c8s-session/runtime"
	// defaultPidsMax leaves the guest's own services and the agent their
	// tasks whatever the sandbox does.
	defaultPidsMax = 4096
	// clockSourcePath names the clocksource the kernel settled on.
	clockSourcePath = "/sys/devices/system/clocksource/clocksource0/current_clocksource"
)

// Bounds on one sandbox image. The scratch volume is the real limit; these
// stop a registry's answer long before a full disk would.
var (
	sandboxPullLimits   = imagestore.PullLimits{Layers: 256, BlobBytes: 8 << 30, TotalBytes: 16 << 30}
	sandboxUnpackLimits = imagestore.UnpackLimits{Entries: 4 << 20, Bytes: 32 << 30}
)

// NewCmd returns `c8s session-agent`, the in-guest half of a session guest. It runs only
// from the guest image's units.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session-agent",
		Short: "The measured in-guest agent of a session guest",
	}
	cmd.AddCommand(newLoadCmd(), newRunCmd(), newHoldCmd())
	return cmd
}

// newHoldCmd is what the agent runs itself as, in the new namespaces it makes
// for a sandbox, until it holds them. Nothing else calls it.
func newHoldCmd() *cobra.Command {
	return &cobra.Command{
		Use:    holdCommand,
		Short:  "Do nothing until standard input ends: the agent runs this in new namespaces to take hold of them",
		Hidden: true,
		Args:   cobra.NoArgs, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error { return Hold(cmd.InOrStdin()) },
	}
}

func newLoadCmd() *cobra.Command {
	cfg := LoadConfig{}
	cmd := &cobra.Command{
		Use:   "load",
		Short: "Copy this boot's launch files off the opkeydata volume and render the host's network request",
		Args:  cobra.NoArgs, SilenceUsage: true,
		RunE: func(*cobra.Command, []string) error { return Load(cfg) },
	}
	cmd.Flags().StringVar(&cfg.LaunchDir, "launch-dir", defaultLaunchDir, "where launch.yaml and its signature are staged for the agent")
	cmd.Flags().StringVar(&cfg.NetworkDir, "network-dir", defaultNetworkDir, "systemd-networkd runtime configuration directory")
	return cmd
}

func newRunCmd() *cobra.Command {
	var cfg Config
	var listen, sandboxUser string
	var plainHTTP []string
	var acceptReserve int
	var acceptRest bool
	var guard RulesetGuard
	image := ImageRunnerConfig{Pull: sandboxPullLimits, Unpack: sandboxUnpackLimits}
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Authenticate and measure the launch document, then serve the attested agent API",
		Args:  cobra.NoArgs, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg.Logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
			// Such an agent would refuse every document it is handed, and say
			// so only then. It is an image built wrong, and says so now.
			if image.Crun == "" && !cfg.Bare {
				return errors.New("this guest can run a tenant's code nowhere: its image names no container runtime (--crun), and its agent is not a dev image's (--bare)")
			}
			cfg.Memory = NewMemory(acceptReserve, acceptRest, cfg.Logger)
			// For the key service a launch document may pin. The guest has no
			// road to the vendor: its host hands it the vendor's documents.
			cfg.Engine = session.NewEngine(session.EngineOptions{})
			tee, err := OpenTEE(cfg.Platform)
			if err != nil {
				return err
			}
			cfg.TEE = tee
			if guard.Expected != "" {
				// The filter keeps the sandbox off the guest's ports, which
				// protects the guest's services only while they listen nowhere else.
				listeners := ListenerGuard{Proc: "/proc"}
				cfg.Guard = func(ctx context.Context) error {
					if err := guard.Check(ctx); err != nil {
						return err
					}
					return listeners.Check(ctx)
				}
			}
			// Unreadable reads as none, which a document with a bind deadline
			// refuses.
			cfg.ClockSource = func() string {
				source, err := os.ReadFile(clockSourcePath)
				if err != nil {
					return ""
				}
				return strings.TrimSpace(string(source))
			}
			uid, gid, home, err := lookupUser(sandboxUser)
			if err != nil {
				return err
			}
			cgroup, err := DelegatedCgroup()
			if err != nil {
				return err
			}
			if cgroup == "" {
				cfg.Logger.Warn("no delegated cgroup: commands are contained by process group only")
			}
			bare, err := NewProcessRunner(RunnerConfig{UID: uid, GID: gid, Home: home, CredentialDir: cfg.CredentialDir, CgroupParent: cgroup})
			if err != nil {
				return err
			}
			cfg.Runner = bare
			// An image without a container runtime keeps the bare runner, which
			// refuses a launch document that names a sandbox image. Nothing in
			// such a guest has a use for a user namespace.
			if image.Crun == "" {
				if err := closeUserNamespaces(); err != nil {
					return err
				}
			}
			if image.Crun != "" {
				// The registry client logs through its own global logger, in
				// another format. Its failures come back as errors anyway.
				_ = containerdlog.SetLevel("error")
				image.CredentialDir, image.CgroupParent, image.Logger = cfg.CredentialDir, cgroup, cfg.Logger
				image.PlainHTTP = func(host string) bool { return slices.Contains(plainHTTP, host) }
				image.Images = OpenImageStore("/sys/block", "/dev", cfg.Logger)
				runner, err := NewImageRunner(image, bare)
				if err != nil {
					return err
				}
				defer runner.Close()
				cfg.Runner = runner
			}
			return Run(cmd.Context(), cfg, listen)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.Platform, "platform", "", "TEE this image was built for: tdx or snp (required)")
	f.StringVar(&listen, "listen", fmt.Sprintf(":%d", session.AgentPort), "RA-TLS bind address")
	f.StringVar(&cfg.PubkeyPath, "pubkey", defaultPubkeyPath, "launch public key staged by the measured initrd")
	f.StringVar(&cfg.LaunchDir, "launch-dir", defaultLaunchDir, "directory holding launch.yaml and launch.yaml.sig")
	f.StringVar(&cfg.CredentialDir, "credential-dir", defaultCredentialDir, "RAM-backed directory for released credentials")
	f.StringVar(&sandboxUser, "sandbox-user", defaultSandboxUser, "unprivileged user commands run as when the bind names no sandbox image")
	f.BoolVar(&cfg.Bare, "bare", false, "take a bind that names no sandbox image, and run its commands on the guest's own file system as --sandbox-user: a dev image's mode, for tests. Without it such a document is refused")
	f.StringVar(&guard.Expected, "packet-filter", "", "nft JSON listing of the image's packet filter; the agent ends the guest if another is in force")
	f.StringVar(&guard.Nft, "nft", "/usr/sbin/nft", "nft binary, for --packet-filter")
	f.StringVar(&image.Crun, "crun", "", "crun binary; set by guest images that can run a sandbox image")
	f.StringVar(&image.StateDir, "sandbox-state-dir", defaultStateDir, "directory on the encrypted scratch volume for the sandbox image")
	f.StringVar(&image.RunDir, "sandbox-runtime-dir", defaultRuntimeDir, "RAM-backed directory for the container runtime's state")
	f.Int64Var(&image.PidsLimit, "sandbox-pids-max", defaultPidsMax, "task limit of the sandbox and its commands together")
	f.IntVar(&acceptReserve, "accept-reserve", 0, "megabytes of accepted free memory a guest holds while it waits for a sandbox, on a kernel that accepts memory on request (vm.accept_memory_mb); a pool guest says it is ready once it holds them")
	f.BoolVar(&acceptRest, "accept-rest", false, "once a sandbox runs, accept the rest of the guest's memory in the background, so that the sandbox finds it accepted. Without it a sandbox accepts what it grows into, and the guest stays as small as its use")
	f.StringSliceVar(&plainHTTP, "sandbox-plain-http", nil, "registries (host:port) reached without TLS, for a dev image's local registry; an image is verified by its digest either way")
	_ = cmd.MarkFlagRequired("platform")
	return cmd
}

// lookupUser resolves the unprivileged sandbox account. Running tenant
// commands as root would hand them the agent's keys, so root is refused.
func lookupUser(name string) (uid, gid int, home string, err error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, "", fmt.Errorf("sandbox user: %w", err)
	}
	if uid, err = strconv.Atoi(u.Uid); err != nil {
		return 0, 0, "", err
	}
	if gid, err = strconv.Atoi(u.Gid); err != nil {
		return 0, 0, "", err
	}
	if uid == 0 || gid == 0 {
		return 0, 0, "", errors.New("the sandbox user must not be root")
	}
	return uid, gid, u.HomeDir, nil
}
