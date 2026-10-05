//go:build c8s_simtee

package sessioncli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/internal/simtee"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// simulatedTrust has a command judge evidence under a simulated authority
// in place of the vendor: the second baseline of
// docs/session-performance.md, in a build made with the c8s_simtee tag. A
// guest that passes such a command runs in no TEE.
type simulatedTrust struct {
	// dir is the simulated authority's directory.
	dir string
}

func (s *simulatedTrust) flags(f *pflag.FlagSet) {
	f.StringVar(&s.dir, "simulated-tee", "",
		"DEVELOPMENT ONLY, and proves nothing: judge evidence under the simulated authority in this directory ('c8s session simtee new') in place of Intel's root, never beside it, and ask whoever serves that authority's documents ('c8s session simtee vendor') in place of Intel's service. A guest that passes runs in no TEE")
}

// engine is the engine of a command that was asked to judge under a
// simulated authority, or nil for one that was not.
func (s *simulatedTrust) engine(opts session.EngineOptions) session.Engine {
	if s.dir == "" {
		return nil
	}
	engine, err := simulatedEngine(s.dir, opts)
	if err != nil {
		return noEngine{err}
	}
	return engine
}

// unproven is what a verdict under a simulated authority leaves unproven:
// everything a TEE would have proved. A command says so with every verdict
// it prints.
func (s *simulatedTrust) unproven() []string {
	if s.dir == "" {
		return nil
	}
	return []string{"anything about the guest's hardware: its TEE is simulated in software (--simulated-tee). Its registers are what its launcher declared, and whoever reads the authority's directory makes any quote"}
}

// simulatedEngine judges under the authority in dir and asks whoever serves
// its documents.
func simulatedEngine(dir string, opts session.EngineOptions) (session.Engine, error) {
	root, err := simtee.LoadRoot(dir)
	if err != nil {
		return nil, err
	}
	address, err := simtee.LoadVendor(dir)
	if err != nil {
		return nil, err
	}
	return session.NewSimulatedEngine(opts, root, simtee.NewRemote(address, nil))
}

// noEngine is the engine of a command whose simulated authority could not be
// read: it judges nothing, and says why.
type noEngine struct{ err error }

func (e noEngine) VerifyEvidence(context.Context, teetypes.AttestationEvidence, []byte) (*teetypes.VerificationResult, error) {
	return nil, fmt.Errorf("--simulated-tee: %w", e.err)
}

// simulationCmds are the commands that make and serve a simulated authority.
func simulationCmds() []*cobra.Command {
	cmd := &cobra.Command{
		Use:   "simtee",
		Short: "DEVELOPMENT ONLY: make and serve the authority of a TEE simulated in software",
		Long: `A build made with the c8s_simtee tag can run session guests with no TEE and
simulate one in software: quotes in Intel's format under a development
authority, signed inside the guest, and that authority's documents in place
of Intel's. It exists to measure what the hardware adds
(docs/session-performance.md) and protects nothing: whoever reads the
authority's directory makes any quote and any document.

'new' makes the authority. 'vendor' serves its documents, where every
launcher and verifier that is given the directory (--simulated-tee) asks for
them.`,
	}
	cmd.AddCommand(newSimulatedAuthorityCmd(), newSimulatedVendorCmd())
	return []*cobra.Command{cmd}
}

func newSimulatedAuthorityCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Make a simulated authority, one platform under it and that platform's quoting enclave",
		Args:  cobra.NoArgs, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := simtee.NewDirectory(out, time.Now())
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s holds a simulated authority (root %x) and the keys that make its quotes and its documents: it protects nothing\n",
				out, dir.Authority.Root.Cert.SubjectKeyId)
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "directory to make, which must not exist (required)")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

func newSimulatedVendorCmd() *cobra.Command {
	var dir, listen string
	cmd := &cobra.Command{
		Use:   "vendor",
		Short: "Serve a simulated authority's documents until stopped",
		Long: `Serve the four documents a quote under the simulated authority is judged
against: the TCB info, the quoting enclave's identity and the two revocation
lists, each signed when it is first asked for and again an hour later, as
Intel's service signs its own. The platform is always UpToDate and nothing is
ever revoked.

The address is written to the directory, where launchers and verifiers find
it, and removed when the command ends.`,
		Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			authority, err := simtee.LoadDirectory(dir)
			if err != nil {
				return err
			}
			ln, err := net.Listen("tcp", listen)
			if err != nil {
				return err
			}
			defer ln.Close()
			address := filepath.Join(dir, simtee.VendorFile)
			if err := fileutil.WriteAtomic(address, []byte(ln.Addr().String()+"\n"), 0o644); err != nil {
				return err
			}
			defer os.Remove(address)
			fmt.Fprintf(cmd.OutOrStdout(), "serving the simulated authority's documents on %s\n", ln.Addr())
			server := &http.Server{
				Handler:           simtee.Handler(simtee.NewVendor(authority.Authority, time.Now)),
				ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second,
				IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10,
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT)
			defer stop()
			ended := context.AfterFunc(ctx, func() {
				closing, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = server.Shutdown(closing)
			})
			defer ended()
			if err := server.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "the simulated authority's directory (required)")
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:0", "address to serve on: launchers and verifiers of this host reach it, and nobody else has a use for it")
	_ = cmd.MarkFlagRequired("dir")
	return cmd
}
