// Package sessiondaemon is `c8s session-daemon`: the host's side of the
// session API.
package sessiondaemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/sessiond"
)

// NewCmd returns `c8s session-daemon`.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session-daemon",
		Short: "Keep pools of session TDs on this host and serve the session API (host side, untrusted)",
	}
	cmd.AddCommand(newRunCmd(), newDrainCmd())
	return cmd
}

func newRunCmd() *cobra.Command {
	var config, profile string
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the daemon",
		Long: `Keep each configured pool at its depth of ready TDs and serve the session
API over them: Claim, Bind, Connect, GetEvidence and Destroy.

Nothing here is trusted. The daemon relays evidence it does not judge and
carries bytes it cannot read, and a caller acts on what it verified itself.
The TDs outlive the daemon: one started later takes them over from the state
directory, and 'c8s session-daemon drain' ends them.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
			cfg, err := sessiond.LoadConfig(config)
			if err != nil {
				return err
			}
			runner, err := sessiond.NewQEMURunner(cfg, log)
			if err != nil {
				return err
			}
			ln, err := net.Listen("tcp", cfg.Listen)
			if err != nil {
				return err
			}
			defer ln.Close()
			if profile != "" {
				defer profileOnSignals(profile, log)()
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT)
			defer stop()
			d := sessiond.New(cfg, runner, log)
			log.Info("serving the session API", "address", ln.Addr().String(), "host", cfg.Host, "pools", len(cfg.Pools), "capacity", cfg.Capacity)
			errs := make(chan error, 2)
			go func() { errs <- d.Run(ctx) }()
			go func() { errs <- d.Serve(ctx, ln) }()
			// Either one ending ends the other.
			err = <-errs
			stop()
			if other := <-errs; err == nil {
				err = other
			}
			return err
		},
	}
	cmd.Flags().StringVar(&config, "config", "", "the daemon's configuration file")
	cmd.Flags().StringVar(&profile, "cpu-profile", "", "for a trial: write the daemon's CPU profile over each stretch from a SIGUSR1 to the SIGUSR2 that follows, to this path with .0, .1 and so on after it (go tool pprof)")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

func newDrainCmd() *cobra.Command {
	var config string
	var wait time.Duration
	cmd := &cobra.Command{
		Use:   "drain",
		Short: "End every TD of a stopped daemon",
		Long: `End every TD the state directory records, bound or not, and wait for
their memory to return to the host. For a host that leaves service: run it
with the daemon stopped, or the daemon boots the pools again.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
			cfg, err := sessiond.LoadConfig(config)
			if err != nil {
				return err
			}
			runner, err := sessiond.NewQEMURunner(cfg, log)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), wait)
			defer cancel()
			ended, err := sessiond.New(cfg, runner, log).Drain(ctx)
			fmt.Fprintf(cmd.OutOrStdout(), "ended %d TDs\n", ended)
			return err
		},
	}
	cmd.Flags().StringVar(&config, "config", "", "the daemon's configuration file")
	cmd.Flags().DurationVar(&wait, "wait", 5*time.Minute, "how long to wait for the TDs to be gone")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}
