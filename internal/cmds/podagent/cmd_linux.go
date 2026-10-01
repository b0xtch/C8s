//go:build linux

package podagent

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/pkg/podcvm"
)

// Paths baked into the pod guest image. The units that pass them are on the
// verity root, so they are part of what the image measurement covers.
const (
	defaultPubkeyPath    = "/etc/confai/operator-pubkey"
	defaultLaunchDir     = "/run/c8s-pod/launch"
	defaultNetworkDir    = "/run/systemd/network"
	defaultCredentialDir = "/run/c8s/credentials"
	defaultWorkloadUser  = "workload"
)

// NewCmd returns `c8s pod-agent`, the in-guest half of a pod CVM. It runs only
// from the guest image's units.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pod-agent",
		Short: "The measured in-guest agent of a pod CVM",
	}
	cmd.AddCommand(newLoadCmd(), newRunCmd())
	return cmd
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
	var listen, workloadUser string
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Authenticate and measure the launch document, then serve the attested agent API",
		Args:  cobra.NoArgs, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg.Logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
			tee, err := OpenTEE(cfg.Platform)
			if err != nil {
				return err
			}
			cfg.TEE = tee
			uid, gid, home, err := lookupUser(workloadUser)
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
			runner, err := NewProcessRunner(RunnerConfig{UID: uid, GID: gid, Home: home, CredentialDir: cfg.CredentialDir, CgroupParent: cgroup})
			if err != nil {
				return err
			}
			cfg.Runner = runner
			return Run(cmd.Context(), cfg, listen)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.Platform, "platform", "", "TEE this image was built for: tdx or snp (required)")
	f.StringVar(&listen, "listen", fmt.Sprintf(":%d", podcvm.AgentPort), "RA-TLS bind address")
	f.StringVar(&cfg.PubkeyPath, "pubkey", defaultPubkeyPath, "launch public key staged by the measured initrd")
	f.StringVar(&cfg.LaunchDir, "launch-dir", defaultLaunchDir, "directory holding launch.yaml and launch.yaml.sig")
	f.StringVar(&cfg.CredentialDir, "credential-dir", defaultCredentialDir, "RAM-backed directory for released credentials")
	f.StringVar(&workloadUser, "workload-user", defaultWorkloadUser, "unprivileged user commands run as")
	_ = cmd.MarkFlagRequired("platform")
	return cmd
}

// lookupUser resolves the unprivileged workload account. Running tenant
// commands as root would hand them the agent's keys, so root is refused.
func lookupUser(name string) (uid, gid int, home string, err error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, "", fmt.Errorf("workload user: %w", err)
	}
	if uid, err = strconv.Atoi(u.Uid); err != nil {
		return 0, 0, "", err
	}
	if gid, err = strconv.Atoi(u.Gid); err != nil {
		return 0, 0, "", err
	}
	if uid == 0 || gid == 0 {
		return 0, 0, "", errors.New("the workload user must not be root")
	}
	return uid, gid, u.HomeDir, nil
}
