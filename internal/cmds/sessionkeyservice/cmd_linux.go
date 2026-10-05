// Package sessionkeyservice is `c8s session-key-service`: the measured
// service of a key service guest (docs/session-key-service.md).
package sessionkeyservice

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

	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
	"github.com/confidential-dot-ai/c8s/internal/keyservice"
	"github.com/confidential-dot-ai/c8s/internal/vsock"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	api "github.com/confidential-dot-ai/c8s/pkg/session/keyservice"
)

// Paths baked into the key service's guest image, which is the session guest
// image with this service on its verity root.
const (
	defaultPubkeyPath = "/etc/confai/operator-pubkey"
	defaultLaunchDir  = "/run/c8s-session/launch"
	pciDevicesPath    = "/sys/bus/pci/devices"
	// The vendor's documents, kept between judgments. RAM-backed: nothing of
	// a replica is read back from a disk.
	defaultCollateralDir = "/run/c8s-key-service/collateral"
)

// NewCmd returns `c8s session-key-service`. It runs only from the key service
// image's unit.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session-key-service",
		Short: "The measured service of a key service guest",
	}
	cmd.AddCommand(newRunCmd())
	return cmd
}

// hostOnly takes connections from the guest's host alone: the launcher that
// carries every connection of a replica.
type hostOnly struct{ net.Listener }

func (l hostOnly) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if peer, ok := conn.(*vsock.Conn); ok && peer.Peer() == vsock.HostCID {
			return conn, nil
		}
		_ = conn.Close()
	}
}

// accepted bounds the connections that wait for the replica to take them.
const accepted = 128

func newRunCmd() *cobra.Command {
	var platform, pubkey, launchDir, collateral string
	var port uint32
	var allowConsole bool
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Authenticate and measure the launch document, then serve the key service",
		Long: `Authenticate this boot's launch document under the key the hardware binds,
measure it, and serve one replica of the session key service over RA-TLS: it
verifies the guests of the pools the document lists and releases a tenant's
stored credentials to a guest that tenant's authority has bound.

Everything the replica holds is in this process's memory. A replica that
stops has forgotten it all, and the unit that runs it powers the guest off.`,
		Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
			// What a replica logs names tenants and sessions. Its kernel
			// writes to no console its host could read, or it does not serve.
			if !allowConsole {
				if err := (sessionagent.ConsoleGuard{Consoles: "/proc/consoles"}).Check(); err != nil {
					return err
				}
			}
			// The load step checked the guest's devices before it read a
			// file of the host's. A replica checks them again before it
			// serves, as a session guest's agent does. Its class has no
			// network device: every connection of a replica is one its
			// launcher carries over the guest's socket to the host.
			if err := (sessionagent.DeviceGuard{Devices: pciDevicesPath, Console: allowConsole, NoNetwork: true}).Check(); err != nil {
				return err
			}
			// Its road to the vendor's service, for the documents it judges
			// guests by. The TLS session on it ends at the vendor.
			vendor, err := sessionagent.VendorDial(launchDir)
			if err != nil {
				return err
			}
			tee, err := sessionagent.OpenTEE(platform)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT)
			defer stop()
			measured, err := sessionagent.MeasureDocument(ctx, tee, platform, pubkey, launchDir,
				func(pub, launch []byte, signature string) (session.Image, *session.Machine, error) {
					doc, err := api.VerifySigned(pub, launch, signature)
					if err != nil {
						return session.Image{}, nil, err
					}
					return doc.Image, doc.Machine, nil
				})
			if err != nil {
				return fmt.Errorf("stage launch document: %w", err)
			}
			engine, err := sessionagent.ReplicaEngine(session.EngineOptions{CollateralCacheDir: collateral, Dial: vendor})
			if err != nil {
				return err
			}
			warm, cancel := context.WithTimeout(ctx, time.Minute)
			service, err := keyservice.New(warm, keyservice.Config{
				Launch: measured.Launch, Signature: measured.Signature, LaunchKey: measured.LaunchKey,
				TEE:    tee,
				Engine: engine,
				Logger: log,
			})
			cancel()
			if err != nil {
				return err
			}
			ln, err := vsock.Listen(port, accepted)
			if err != nil {
				return fmt.Errorf("listen on vsock port %d: %w", port, err)
			}
			log.Info("key service serving", "vsock_port", port)
			return service.Serve(ctx, hostOnly{ln})
		},
	}
	f := cmd.Flags()
	f.StringVar(&platform, "platform", "", "TEE this image was built for: tdx or snp (required)")
	f.Uint32Var(&port, "vsock-port", api.Port, "port of the guest's socket to its host that the replica serves RA-TLS on: its launcher publishes it")
	f.StringVar(&pubkey, "pubkey", defaultPubkeyPath, "launch public key staged by the measured initrd")
	f.StringVar(&launchDir, "launch-dir", defaultLaunchDir, "directory holding launch.yaml and launch.yaml.sig")
	f.StringVar(&collateral, "collateral-cache", defaultCollateralDir, "RAM-backed directory that keeps the vendor's documents between judgments")
	f.BoolVar(&allowConsole, "allow-console", false, "serve in a guest whose kernel has a console its host can read: a dev image's mode")
	_ = cmd.MarkFlagRequired("platform")
	return cmd
}
