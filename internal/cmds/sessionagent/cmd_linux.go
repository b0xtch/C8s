//go:build linux

package sessionagent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/user"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	containerdlog "github.com/containerd/log"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/guestend"
	"github.com/confidential-dot-ai/c8s/internal/imagestore"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// Paths baked into the session guest image. The units that pass them are on the
// verity root, so they are part of what the image measurement covers.
const (
	defaultPubkeyPath    = "/etc/confai/operator-pubkey"
	defaultLaunchDir     = guestend.LaunchDir
	defaultResolvConf    = "/run/c8s-session/resolv.conf"
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
	// consolesPath lists the consoles the kernel registered.
	consolesPath = "/proc/consoles"
	// pciDevicesPath lists the functions on the guest's PCI bus.
	pciDevicesPath = "/sys/bus/pci/devices"
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
	cmd.AddCommand(newLoadCmd(), newRunCmd(), newHoldCmd(), newKeysCmd())
	return cmd
}

// keysCommand is what the agent's executable is run as to be the guest's key
// helper.
const keysCommand = "one-time-keys"

// newKeysCmd is the key helper: the process that holds the private halves of
// the guest's one-time keys, started by the agent at its own start. Nothing
// else calls it.
func newKeysCmd() *cobra.Command {
	return &cobra.Command{
		Use:    keysCommand,
		Short:  "Hold the guest's one-time keys for the agent that started this: sign one receipt, open one sealed message, and exit",
		Hidden: true,
		Args:   cobra.NoArgs, SilenceUsage: true,
		RunE: func(*cobra.Command, []string) error { return RunKeyHelper() },
	}
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
	var allowConsole, noNetwork bool
	cmd := &cobra.Command{
		Use:   "load",
		Short: "Copy this boot's launch files off the opkeydata volume and apply the host's network request",
		Args:  cobra.NoArgs, SilenceUsage: true,
		RunE: func(*cobra.Command, []string) error {
			// The first thing the guest does with what its host built: before
			// it reads a file the host handed it or sets an address the host
			// asked for, the machine is one a guest of its class is given.
			if err := (DeviceGuard{Devices: pciDevicesPath, Console: allowConsole, NoNetwork: noNetwork}).Check(); err != nil {
				return err
			}
			// A guest of a class without a network has no interface to set,
			// whatever its host asks for.
			if noNetwork {
				cfg.ResolvConf = ""
			} else {
				cfg.Network = applyNetwork
			}
			cfg.More = hardwareFiles()
			return Load(cfg)
		},
	}
	cmd.Flags().StringVar(&cfg.LaunchDir, "launch-dir", defaultLaunchDir, "where launch.yaml and its signature are staged for the agent")
	cmd.Flags().StringVar(&cfg.ResolvConf, "resolv-conf", defaultResolvConf, "where the host's resolvers are written; the image's /etc/resolv.conf links to it")
	cmd.Flags().BoolVar(&allowConsole, "allow-console", false, "take a virtio console among the guest's devices (dev images)")
	cmd.Flags().BoolVar(&noNetwork, "no-network", false, "this image's class has no network device: take none among the guest's devices, and set no interface (the key service's image)")
	return cmd
}

func newRunCmd() *cobra.Command {
	var cfg Config
	var listen, sandboxUser string
	var plainHTTP []string
	var acceptReserve, processors int
	var acceptRest bool
	var guard RulesetGuard
	var schemas SchemaGuard
	var allowConsole bool
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
			if image.Crun != "" && image.SandboxInit == "" {
				return errors.New("this guest's image names a container runtime (--crun) and not the program its containers start with (--sandbox-init)")
			}
			// A guest makes keys for its one bind that must be gone before
			// anything of a tenant runs: where they were kept, and whatever
			// signing or decrypting with them left behind.
			if !erasesTemporaries {
				return errors.New("this guest's program was built without the runtime's secret mode (GOEXPERIMENT=runtimesecret): it cannot erase what its one-time keys leave in memory")
			}
			// The keys are gone with the helper that held them because the
			// kernel zeroes every page it frees. Its build and its measured
			// command line decide that, and its own log says what they came to.
			said, err := kernelOnFreedMemory()
			if err != nil {
				return fmt.Errorf("erasing the one-time keys rests on a kernel that zeroes what it frees: %w", err)
			}
			if !zeroesFreedMemory(said) {
				return fmt.Errorf("this guest's kernel says %q: erasing the one-time keys rests on a kernel that zeroes what it frees", said)
			}
			cfg.Logger.Info("the kernel zeroes the memory it frees", "kernel", said)
			if processors < 0 {
				return errors.New("--processors is a number of processors, or 0 for all of the guest's")
			}
			if processors > 0 {
				runtime.GOMAXPROCS(processors)
				if err := keepTo(processors); err != nil {
					return err
				}
			}
			// The guest's one-time keys live in a process of their own, which
			// this one starts now and reaps before anything of a tenant runs.
			cfg.KeyHelper = []string{ownExecutable, "session-agent", keysCommand}
			cfg.Memory = NewMemory(acceptReserve, acceptRest, cfg.Logger)
			// For the key service a launch document may pin. The guest has no
			// road to the vendor: it asks its host for the vendor's documents.
			if cfg.Engine, err = GuestEngine(); err != nil {
				return err
			}
			dials, err := readHostDials(cfg.LaunchDir)
			if err != nil {
				return err
			}
			cfg.KeyServiceDial, cfg.CollateralDial = dials.KeyService, dials.Collateral
			if cfg.TEE, err = OpenTEE(cfg.Platform); err != nil {
				return err
			}
			// Before the guest serves, everything. The schemas on the
			// measured root are the ones this agent keeps to, or this is not
			// the image that was published.
			checks := []guestCheck{{"schemas", func(context.Context) error { return schemas.Check() }}}
			if !allowConsole {
				consoles := ConsoleGuard{Consoles: consolesPath}
				checks = append(checks, guestCheck{"consoles", func(context.Context) error { return consoles.Check() }})
			}
			// The machine is the one a session guest is given, device by
			// device, or the guest ends before it stages anything.
			devices := DeviceGuard{Devices: pciDevicesPath, Console: allowConsole}
			checks = append(checks, guestCheck{"devices", func(context.Context) error { return devices.Check() }})
			// Before a sandbox starts, what can have changed since. The
			// schemas are on a root no write reaches, and the kernel takes no
			// console, no device and no code after it has booted: its image
			// is built without hot plug and without modules.
			var atBind []guestCheck
			if guard.Expected != "" {
				// The filter keeps the sandbox off the guest's ports, which
				// protects the guest's services only while they listen nowhere else.
				listeners := ListenerGuard{Proc: "/proc", TCP: func(family int) ([]int, error) {
					ports, err := tcpListeners(family)
					// A kernel without an address family has no socket of it.
					if family == unix.AF_INET6 && errors.Is(err, unix.ENOENT) {
						return nil, fs.ErrNotExist
					}
					return ports, err
				}}
				// Listed before the guest serves, and from then on held to
				// the kernel's count of its changes.
				filter := &RulesetWatch{Guard: guard, Generation: rulesetGeneration}
				atBind = []guestCheck{{"filter", filter.Check}, {"listeners", listeners.Check}}
				checks = append(checks, atBind...)
			}
			cfg.Guard = func(ctx context.Context) error { return runChecks(ctx, nil, checks) }
			cfg.BindGuard = func(ctx context.Context) error { return runChecks(ctx, cfg.Logger, atBind) }
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
	f.StringVar(&cfg.PhaseFile, "phase-file", guestend.PhaseFile, "file the agent writes its phase to as it changes, for the guest's init to read once the agent has ended; empty writes none")
	f.StringVar(&cfg.CredentialDir, "credential-dir", defaultCredentialDir, "RAM-backed directory for released credentials")
	f.StringVar(&sandboxUser, "sandbox-user", defaultSandboxUser, "unprivileged user commands run as when the bind names no sandbox image")
	f.BoolVar(&cfg.Bare, "bare", false, "take a bind that names no sandbox image, and run its commands on the guest's own file system as --sandbox-user: a dev image's mode, for tests. Without it such a document is refused")
	f.StringVar(&guard.Expected, "packet-filter", "", "nft JSON listing of the image's packet filter; the agent ends the guest if another is in force")
	f.StringVar(&guard.Nft, "nft", "/usr/sbin/nft", "nft binary, for --packet-filter")
	f.StringVar(&schemas.Disclosure, "disclosure-schema", "", "the image's disclosure schema, on its measured root; the agent ends the guest if it is not the one the agent keeps to")
	f.StringVar(&schemas.Bind, "bind-schema", "", "the image's bind schema, on its measured root; the agent ends the guest if it is not the one the agent takes binds by")
	f.BoolVar(&allowConsole, "allow-console", false, "serve in a guest whose kernel has a console its host can read: a dev image's mode. Without it the agent ends such a guest")
	f.StringVar(&image.Crun, "crun", "", "crun binary; set by guest images that can run a sandbox image")
	f.StringVar(&image.SandboxInit, "sandbox-init", "", "the program a sandbox's container runs until its session's bind names the sandbox's process (c8s-sandbox-init); set with --crun")
	f.StringVar(&image.StateDir, "sandbox-state-dir", defaultStateDir, "directory on the encrypted scratch volume for the sandbox image")
	f.StringVar(&image.RunDir, "sandbox-runtime-dir", defaultRuntimeDir, "RAM-backed directory for the container runtime's state")
	f.Int64Var(&image.PidsLimit, "sandbox-pids-max", defaultPidsMax, "task limit of the sandbox and its commands together")
	f.IntVar(&processors, "processors", 0, "how many of the guest's processors the agent keeps to, the first ones, with the runtime it starts containers with (0: all of them). The session's own code has every one either way: fewer for the agent means fewer of them woken for its work")
	f.IntVar(&acceptReserve, "accept-reserve", 0, "megabytes of accepted free memory a guest holds while it waits for a sandbox, on a kernel that accepts memory on request (vm.accept_memory_mb); a pool guest says it is ready once it holds them")
	f.BoolVar(&acceptRest, "accept-rest", false, "once a sandbox runs, accept the rest of the guest's memory in the background, so that the sandbox finds it accepted. Without it a sandbox accepts what it grows into, and the guest stays as small as its use")
	f.StringSliceVar(&plainHTTP, "sandbox-plain-http", nil, "registries (host:port) reached without TLS, for a dev image's local registry; an image is verified by its digest either way")
	_ = cmd.MarkFlagRequired("platform")
	return cmd
}

// guestCheck is one thing a guest checks of itself.
type guestCheck struct {
	name  string
	check func(context.Context) error
}

// runChecks runs checks in order and stops at the first that fails. With a
// log it says how long each took.
func runChecks(ctx context.Context, log *slog.Logger, checks []guestCheck) error {
	took := make([]any, 0, 2*len(checks))
	for _, c := range checks {
		began := time.Now()
		if err := c.check(ctx); err != nil {
			return err
		}
		took = append(took, c.name+"_us", time.Since(began).Microseconds())
	}
	if log != nil && len(took) > 0 {
		log.Info("checked before a sandbox", took...)
	}
	return nil
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
