package sessioncli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/keyservice"
)

// keyServiceCmd returns `c8s session key-service`: what an operator boots a
// key service with, and what an owner tells one.
func keyServiceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key-service",
		Short: "Launch a session key service, and store a tenant's credentials in one",
		Long: `A key service holds what a session needs when its owner is not there: a
tenant's stored credentials, released to a guest only once that tenant's
authority has bound it. It runs in a confidential VM of its own, and a guest
or an owner sends it nothing before its evidence has been held to a pin.
See docs/session-key-service.md.`,
	}
	launch := &cobra.Command{Use: "launch-config", Short: "Create a key service's signed launch bundle"}
	launch.AddCommand(newKeyServiceBundleCmd())
	tenant := &cobra.Command{Use: "tenant", Short: "Register a tenant with a key service"}
	tenant.AddCommand(newTenantRegisterCmd())
	credential := &cobra.Command{Use: "credential", Short: "Store a tenant's credentials in a key service"}
	credential.AddCommand(newStoredCredentialPutCmd())
	cmd.AddCommand(launch, newKeyServicePinCmd(), tenant, credential)
	return cmd
}

// acceptedTCBFlag is the flag by which a document's author names the Intel
// TCB statuses it accepts besides UpToDate.
func acceptedTCBFlag(f *pflag.FlagSet, statuses *[]string, of string) {
	f.StringSliceVar(statuses, "accept-tcb-status", nil,
		"an Intel TCB status, besides UpToDate, that "+of+" may have, such as OutOfDate or SWHardeningNeeded; repeat for more. Whoever verifies the document sees the list. Revoked is never accepted")
}

// sortedOnce is a flag's list as a document carries it.
func sortedOnce(statuses []string) []string {
	out := slices.Clone(statuses)
	slices.Sort(out)
	return slices.Compact(out)
}

func newKeyServiceBundleCmd() *cobra.Command {
	var opts keyservice.BundleOptions
	var pools, acceptTCB []string
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Write and sign a key service's launch document",
		Long: `Write a launch bundle for a key service: its policy, which names its own
image and the pools of session guests it serves, signed with a launch key.
The key service measures the document at boot, so whoever verifies it knows
which guests it releases to.

  <out>/launch.key              the launch private key (only when generated here)
  <out>/opkeydata/pubkey        attach these three as the guest's
  <out>/opkeydata/launch.yaml   opkeydata volume, as for a session guest
  <out>/opkeydata/launch.yaml.sig`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			for _, spec := range pools {
				manifest, key, ok := strings.Cut(spec, ":")
				if !ok || manifest == "" || key == "" {
					return fmt.Errorf("--pool %q must be <image manifest>:<launch public key>", spec)
				}
				opts.Pools = append(opts.Pools, keyservice.PoolOptions{ManifestPath: manifest, LaunchKeyPath: key, AcceptTCBStatus: sortedOnce(acceptTCB)})
			}
			if err := keyservice.NewBundle(opts); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s: a key service for %d pools\n", opts.Dir, len(opts.Pools))
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.Dir, "out", "", "bundle directory to create (must not exist)")
	f.StringVar(&opts.ManifestPath, "image-manifest", "", "manifest.json published with the key service's guest image")
	f.StringVar(&opts.KeyPath, "key", "", "existing launch private key to sign with (default: generate <out>/launch.key)")
	f.StringArrayVar(&pools, "pool", nil, "a pool the key service serves, as <manifest.json of its guest image>:<its launch public key PEM> (repeatable)")
	acceptedTCBFlag(f, &acceptTCB, "the platform of a guest of these pools")
	for _, name := range []string{"out", "image-manifest", "pool"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

func newKeyServicePinCmd() *cobra.Command {
	var bundle, url, out string
	var acceptTCB []string
	cmd := &cobra.Command{
		Use:   "pin",
		Short: "Write the pin of a key service: where it is reached and what it must be",
		Long: `Write what a pool's launch document, an owner's bind and every command
here hold a key service to: its address, its image and the launch key its
launch document is signed with. The file is public.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pin, err := keyservice.Pin(bundle, url)
			if err != nil {
				return err
			}
			pin.AcceptTCBStatus = sortedOnce(acceptTCB)
			if err := pin.Validate(); err != nil {
				return err
			}
			data, err := json.MarshalIndent(pin, "", "  ")
			if err != nil {
				return err
			}
			if err := os.WriteFile(out, append(data, '\n'), 0o644); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", out)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&bundle, "bundle", "", "the key service's launch bundle directory")
	f.StringVar(&url, "url", "", "where the key service is reached, as https://host:port")
	f.StringVar(&out, "out", "", "file to write")
	acceptedTCBFlag(f, &acceptTCB, "the key service's platform")
	for _, name := range []string{"bundle", "url", "out"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

// tenantFlags are what a command that speaks for a tenant takes: the key
// service it speaks to, and the tenant's authority.
type tenantFlags struct {
	trust
	pin          string
	tenant       string
	authorityKey string
}

func (t *tenantFlags) register(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&t.pin, "key-service", "", "pin of the key service, as 'c8s session key-service pin' writes it")
	f.StringVar(&t.tenant, "tenant", "", "the tenant")
	f.StringVar(&t.authorityKey, "authority-key", "", "the tenant's authority private key, which signs the request")
	t.collateralFlags(f)
	f.DurationVar(&t.timeout, "timeout", 2*time.Minute, "overall deadline")
	for _, name := range []string{"key-service", "tenant", "authority-key"} {
		_ = cmd.MarkFlagRequired(name)
	}
}

// open returns a client of the pinned key service and the tenant's signer
// and public authority key.
func (t *tenantFlags) open() (*keyservice.Client, *operatorauth.Signer, []byte, error) {
	pin, err := session.LoadKeyServicePin(t.pin)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("--key-service: %w", err)
	}
	keyPEM, err := os.ReadFile(t.authorityKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("--authority-key: %w", err)
	}
	authority, err := certutil.ParseECPrivateKey(keyPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("--authority-key: %w", err)
	}
	public, err := session.PublicKeyPEM(&authority.PublicKey)
	if err != nil {
		return nil, nil, nil, err
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(keyPEM)
	if err != nil {
		return nil, nil, nil, err
	}
	client, err := keyservice.NewClient(keyservice.Options{Pin: pin, Engine: t.engine()})
	if err != nil {
		return nil, nil, nil, err
	}
	return client, signer, public, nil
}

// keyServiceExit sorts an error from a key service into the CI contract.
func keyServiceExit(err error) int {
	var refused *session.VerificationError
	switch {
	case err == nil:
		return ExitOK
	case errors.As(err, &refused):
		return ExitRefused
	default:
		return ExitUnavailable
	}
}

func newTenantRegisterCmd() *cobra.Command {
	var t tenantFlags
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a tenant's authority key with a key service",
		Long: `Hold the key service to its pin, then register the tenant's authority: the
key whose binds may take the tenant's stored credentials. The first
registration of a tenant is trust on first use, and the key service takes no
other key for that tenant afterwards.

Exit codes: 0 registered, 1 usage error, 2 the key service is not the one
pinned and was sent nothing, 3 it could not be reached or refused.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			os.Exit(runTenantRegister(cmd.Context(), &t, cmd.OutOrStdout(), cmd.ErrOrStderr()))
			return nil
		},
	}
	t.register(cmd)
	return cmd
}

func runTenantRegister(ctx context.Context, t *tenantFlags, stdout, stderr io.Writer) int {
	client, signer, public, err := t.open()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	if err := client.RegisterAuthority(ctx, t.tenant, public, signer); err != nil {
		fmt.Fprintf(stderr, "NOT REGISTERED: %v\n", err)
		return keyServiceExit(err)
	}
	fmt.Fprintf(stdout, "registered the authority of tenant %s\n", t.tenant)
	return ExitOK
}

func newStoredCredentialPutCmd() *cobra.Command {
	var t tenantFlags
	var fromFile string
	cmd := &cobra.Command{
		Use:   "put <name>",
		Short: "Store one credential of a tenant in a key service",
		Long: `Hold the key service to its pin, then store the value under the tenant's
authority. A session of the tenant whose bind declares the name with
--stored-credential finds it in its sandbox from the first moment, with its
owner nowhere near.

The value is read from standard input, or from --from-file, and leaves only
on a connection whose far end verified as the pinned key service.

Exit codes: 0 stored, 1 usage error, 2 the key service is not the one pinned
and was sent nothing, 3 it could not be reached or refused.`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			in := cmd.InOrStdin()
			if fromFile != "" {
				f, err := os.Open(fromFile)
				if err != nil {
					return err
				}
				defer f.Close()
				in = f
			}
			value, err := readutil.ReadAll(in, session.MaxCredentialBytes)
			if err != nil {
				return fmt.Errorf("read the credential: %w", err)
			}
			os.Exit(runStoredCredentialPut(cmd.Context(), &t, args[0], value, cmd.OutOrStdout(), cmd.ErrOrStderr()))
			return nil
		},
	}
	t.register(cmd)
	cmd.Flags().StringVar(&fromFile, "from-file", "", "read the value from this file instead of stdin")
	return cmd
}

func runStoredCredentialPut(ctx context.Context, t *tenantFlags, name string, value []byte, stdout, stderr io.Writer) int {
	if !session.ValidCredentialName(name) || len(value) == 0 {
		fmt.Fprintln(stderr, "a credential has a name of lowercase letters, digits, '.', '_' and '-', and a value")
		return ExitUsage
	}
	client, signer, _, err := t.open()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	if err := client.PutCredential(ctx, t.tenant, name, value, signer); err != nil {
		fmt.Fprintf(stderr, "NOT STORED: %v\n", err)
		return keyServiceExit(err)
	}
	fmt.Fprintf(stdout, "stored %d bytes as %s for tenant %s\n", len(value), name, t.tenant)
	return ExitOK
}
