// Package pod is the operator CLI for pod CVMs: write a sandbox's signed
// launch bundle, then verify the running guest, release credentials into it
// and run commands in it. Every command that talks to a guest goes through the
// trust gate in pkg/podcvm first.
package pod

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/podcvm"
)

// Exit codes are a CI contract, shared with `c8s verify` where they overlap.
const (
	ExitOK = 0
	// ExitUsage: bad flags or unreadable local inputs.
	ExitUsage = 1
	// ExitRefused: evidence was obtained and failed verification or policy.
	ExitRefused = 2
	// ExitUnavailable: no verdict; the guest could not be reached or answered
	// with an error.
	ExitUnavailable = 3

	// `c8s pod exec` exits with the remote command's own status, so its
	// failures to run anything at all sit above the range commands use.
	ExitExecUnavailable = 124
	ExitExecRefused     = 125
)

// NewCmd returns the `c8s pod` command group.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pod",
		Short: "Launch, verify and drive single-tenant pod CVMs",
		Long: `A pod CVM is one worker pod running as its own confidential VM for one
tenant. 'launch-config new' writes the signed launch bundle the guest boots
from. 'verify', 'credential put' and 'exec' talk to the running guest, and
each one first proves from hardware evidence that the guest is the pinned
image, launched for your key, running exactly your launch document.
See docs/pod-cvm.md.`,
	}
	launch := &cobra.Command{Use: "launch-config", Short: "Create a pod CVM's signed launch bundle"}
	launch.AddCommand(newBundleCmd())
	credential := &cobra.Command{Use: "credential", Short: "Release credentials into a verified pod CVM"}
	credential.AddCommand(newCredentialPutCmd())
	cmd.AddCommand(launch, newVerifyCmd(), credential, newExecCmd())
	return cmd
}

func newBundleCmd() *cobra.Command {
	var opts podcvm.BundleOptions
	var image, workingDir string
	var command, args, env, credentials, execKeys, credentialKeys []string
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Write and sign one sandbox's launch document",
		Long: `Write everything one pod CVM boots from:

  <out>/launch.key              launch private key (unless --key reuses one)
  <out>/opkeydata/pubkey        the public key the guest measures
  <out>/opkeydata/launch.yaml   the launch document
  <out>/opkeydata/launch.yaml.sig

Give the opkeydata directory to the pod launcher. The document carries no
secrets, so it can be shown to anyone who needs to verify the guest.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if image != "" {
				opts.Workload = &podcvm.Workload{Image: image, Command: command, Args: args, WorkingDir: workingDir}
				if len(env) > 0 {
					opts.Workload.Env = map[string]string{}
					for _, kv := range env {
						k, v, ok := strings.Cut(kv, "=")
						if !ok {
							return fmt.Errorf("--env %q must be NAME=value", kv)
						}
						opts.Workload.Env[k] = v
					}
				}
			} else if len(command)+len(args)+len(env) > 0 || workingDir != "" {
				return errors.New("--command, --arg, --env and --working-dir need --workload-image")
			}
			for _, spec := range credentials {
				name, limit, _ := strings.Cut(spec, ":")
				c := podcvm.Credential{Name: name}
				if limit != "" {
					n, err := strconv.Atoi(limit)
					if err != nil || n <= 0 {
						return fmt.Errorf("--credential %q: size must be a positive byte count", spec)
					}
					c.MaxBytes = n
				}
				opts.Credentials = append(opts.Credentials, c)
			}
			var err error
			if opts.ExecKeys, err = readKeys(execKeys); err != nil {
				return fmt.Errorf("--exec-key: %w", err)
			}
			if opts.CredentialKeys, err = readKeys(credentialKeys); err != nil {
				return fmt.Errorf("--credential-key: %w", err)
			}
			if err := podcvm.NewBundle(opts); err != nil {
				return err
			}
			bundle, err := podcvm.LoadBundle(opts.Dir)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote launch bundle %s for tenant %s sandbox %s\nlaunch document %s\n",
				opts.Dir, bundle.Document.Tenant, bundle.Document.Sandbox, podcvm.LaunchDigest(bundle.Launch))
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.Dir, "out", "", "bundle directory to create (must not exist)")
	f.StringVar(&opts.ManifestPath, "image-manifest", "", "manifest.json published with the pod guest image")
	f.IntVar(&opts.VCPUs, "vcpus", 0, "SNP only: the VM's vCPU count, selecting its launch digest")
	f.StringVar(&opts.KeyPath, "key", "", "existing launch private key to sign with (default: generate <out>/launch.key)")
	f.StringVar(&opts.Tenant, "tenant", "", "the one tenant this CVM belongs to")
	f.StringVar(&opts.Sandbox, "sandbox", "", "sandbox name, an RFC1123 label")
	f.StringVar(&image, "workload-image", "", "OCI image the guest pulls and runs, as name@sha256:<digest>")
	f.StringArrayVar(&command, "command", nil, "workload entrypoint override, one element per flag")
	f.StringArrayVar(&args, "arg", nil, "workload argument, one element per flag")
	f.StringArrayVar(&env, "env", nil, "workload environment NAME=value (not for secrets)")
	f.StringVar(&workingDir, "working-dir", "", "workload working directory")
	f.StringArrayVar(&credentials, "credential", nil, "credential NAME[:MAXBYTES] the workload may be handed after attestation")
	f.StringArrayVar(&execKeys, "exec-key", nil, "public key PEM file granted exec, in addition to the launch key")
	f.StringArrayVar(&credentialKeys, "credential-key", nil, "public key PEM file granted credential release, in addition to the launch key")
	f.BoolVar(&opts.NoLaunchKeyAccess, "no-launch-key-access", false, "grant the launch key itself no exec or credential access")
	for _, name := range []string{"out", "image-manifest", "tenant", "sandbox"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

func readKeys(paths []string) ([]string, error) {
	var out []string
	for _, path := range paths {
		data, err := podcvm.ReadBounded(path, 8192)
		if err != nil {
			return nil, err
		}
		out = append(out, string(data))
	}
	return out, nil
}

// trust is the flag set every guest-facing command shares.
type trust struct {
	url           string
	bundle        string
	manifest      string
	launchKey     string
	tenant        string
	sandbox       string
	key           string
	collateral    string
	allowStaged   bool
	timeout       time.Duration
	engineForTest podcvm.Engine
}

func (t *trust) register(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&t.url, "url", "", "the guest agent, https://<pod-ip>:8443")
	f.StringVar(&t.bundle, "bundle", "", "launch bundle directory: pins the exact launch document and supplies the launch key")
	f.StringVar(&t.manifest, "image-manifest", "", "manifest.json published with the pod guest image")
	f.StringVar(&t.launchKey, "launch-key", "", "launch public key PEM, when no --bundle is at hand (then --tenant and --sandbox are required)")
	f.StringVar(&t.tenant, "tenant", "", "tenant the guest must belong to")
	f.StringVar(&t.sandbox, "sandbox", "", "sandbox the guest must be")
	f.StringVar(&t.key, "key", "", "private key that signs requests (default <bundle>/launch.key)")
	f.StringVar(&t.collateral, "collateral", string(podcvm.CollateralRequired),
		"required: fetch Intel collateral and refuse any TCB status but UpToDate; skip: check the quote signature, the PCK chain and the quoting enclave identity only")
	f.DurationVar(&t.timeout, "timeout", 2*time.Minute, "overall deadline")
	for _, name := range []string{"url", "image-manifest"} {
		_ = cmd.MarkFlagRequired(name)
	}
}

// client turns the flags into a verifying client. Every failure here is a
// usage error: nothing has been sent yet.
func (t *trust) client() (*podcvm.Client, error) {
	identity, err := runtimemeasure.LoadImageManifest(t.manifest)
	if err != nil {
		return nil, fmt.Errorf("--image-manifest: %w", err)
	}
	policy := podcvm.Policy{Image: identity, Tenant: t.tenant, Sandbox: t.sandbox, AllowStaged: t.allowStaged}
	keyPath := t.key
	switch {
	case t.bundle != "" && t.launchKey != "":
		return nil, errors.New("--bundle and --launch-key are alternatives")
	case t.bundle != "":
		bundle, err := podcvm.LoadBundle(t.bundle)
		if err != nil {
			return nil, fmt.Errorf("--bundle: %w", err)
		}
		policy.LaunchKey, policy.Launch = bundle.LaunchKey, bundle.Launch
		if keyPath == "" {
			keyPath = filepath.Join(t.bundle, podcvm.BundleKeyFile)
		}
	case t.launchKey != "":
		if policy.LaunchKey, err = podcvm.ReadBounded(t.launchKey, 8192); err != nil {
			return nil, fmt.Errorf("--launch-key: %w", err)
		}
	default:
		return nil, errors.New("one of --bundle or --launch-key is required")
	}
	if keyPath == "" {
		return nil, errors.New("--key is required: the private key that signs requests")
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	if _, err := certutil.ParseECPrivateKey(keyPEM); err != nil {
		return nil, fmt.Errorf("signing key %s: %w", keyPath, err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	engine := t.engineForTest
	if engine == nil {
		if engine, err = podcvm.NewEngine(podcvm.Collateral(t.collateral)); err != nil {
			return nil, fmt.Errorf("--collateral: %w", err)
		}
	}
	return podcvm.NewClient(t.url, policy, engine, signer)
}

// exitCode sorts an error into the CI contract.
func exitCode(err error) int {
	var verdict *podcvm.VerificationError
	switch {
	case err == nil:
		return ExitOK
	case errors.As(err, &verdict):
		return ExitRefused
	default:
		return ExitUnavailable
	}
}

// verdict is the machine-readable result of `c8s pod verify`.
type verdict struct {
	Verified           bool     `json:"verified"`
	Error              string   `json:"error,omitempty"`
	Tenant             string   `json:"tenant,omitempty"`
	Sandbox            string   `json:"sandbox,omitempty"`
	Phase              string   `json:"phase,omitempty"`
	Platform           string   `json:"platform,omitempty"`
	LaunchDigest       string   `json:"launch_digest,omitempty"`
	Events             []string `json:"events,omitempty"`
	MRTD               string   `json:"mrtd,omitempty"`
	InstanceKeySHA256  string   `json:"instance_key_sha256,omitempty"`
	CollateralVerified bool     `json:"collateral_verified"`
	// NotProven lists what this verdict does not establish.
	NotProven []string `json:"not_proven,omitempty"`
}

func newVerifyCmd() *cobra.Command {
	var t trust
	var output string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a running pod CVM from hardware evidence",
		Long: `Fetch evidence for a fresh nonce and check, in process, that the guest
answering on this connection is the pinned image, was launched for the launch
key, measured exactly the expected launch document and workload, is not
debuggable, and holds the key this connection terminates on.

Exit codes: 0 verified, 1 usage error, 2 verification or policy failed,
3 the guest could not be reached.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if output != "text" && output != "json" {
				return errors.New("-o must be text or json")
			}
			os.Exit(runVerify(cmd.Context(), &t, output == "json", cmd.OutOrStdout(), cmd.ErrOrStderr()))
			return nil
		},
	}
	t.register(cmd)
	cmd.Flags().BoolVar(&t.allowStaged, "allow-staged", false, "accept a guest that has measured its launch document but not yet its workload")
	cmd.Flags().StringVarP(&output, "output", "o", "text", "text or json")
	return cmd
}

func runVerify(ctx context.Context, t *trust, asJSON bool, stdout, stderr io.Writer) int {
	client, err := t.client()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	att, err := client.Attest(ctx)
	v := verdict{Verified: err == nil}
	if err != nil {
		v.Error = err.Error()
	} else {
		v.Tenant, v.Sandbox = att.Document.Tenant, att.Document.Sandbox
		v.Phase, v.Platform = string(att.Phase), string(att.Result.Platform)
		v.LaunchDigest, v.Events = podcvm.LaunchDigest(att.Launch), att.Events
		v.MRTD = att.Result.Claims.LaunchDigest
		v.InstanceKeySHA256 = certutil.CertFingerprint(att.InstanceKey)
		v.CollateralVerified = att.Result.CollateralVerified
		if !att.Result.CollateralVerified {
			v.NotProven = append(v.NotProven, "platform TCB level, quoting enclave version and certificate revocation (collateral was not checked)")
		}
	}
	if asJSON {
		_ = json.NewEncoder(stdout).Encode(v)
	} else if err != nil {
		fmt.Fprintf(stderr, "NOT VERIFIED: %v\n", err)
	} else {
		fmt.Fprintf(stdout, "VERIFIED %s pod CVM\n  tenant        %s\n  sandbox       %s\n  phase         %s\n  launch doc    %s\n  events        %s\n  image (MRTD)  %s\n  instance key  sha256:%s\n",
			v.Platform, v.Tenant, v.Sandbox, v.Phase, v.LaunchDigest, strings.Join(v.Events, " "), v.MRTD, v.InstanceKeySHA256)
		for _, gap := range v.NotProven {
			fmt.Fprintf(stdout, "  NOT PROVEN    %s\n", gap)
		}
	}
	return exitCode(err)
}

func newCredentialPutCmd() *cobra.Command {
	var t trust
	var fromFile string
	cmd := &cobra.Command{
		Use:   "put <name>",
		Short: "Release one credential into a pod CVM, after attesting it",
		Long: `Attest the guest for a fresh nonce and, only if it verifies with its
workload admitted, send the value on a connection that terminates at the key
it attested. The value is read from stdin or --from-file and stored exactly
as read.

Exit codes: 0 released, 1 usage error, 2 verification or policy failed
(nothing was sent), 3 the guest could not be reached or refused the write.`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			var value []byte
			var err error
			if fromFile != "" {
				value, err = podcvm.ReadBounded(fromFile, podcvm.MaxCredentialBytes)
			} else {
				value, err = io.ReadAll(io.LimitReader(cmd.InOrStdin(), podcvm.MaxCredentialBytes+1))
			}
			if err != nil {
				return err
			}
			if len(value) == 0 || len(value) > podcvm.MaxCredentialBytes {
				return fmt.Errorf("credential value must be 1..%d bytes", podcvm.MaxCredentialBytes)
			}
			os.Exit(runCredentialPut(cmd.Context(), &t, args[0], value, cmd.OutOrStdout(), cmd.ErrOrStderr()))
			return nil
		},
	}
	t.register(cmd)
	cmd.Flags().StringVar(&fromFile, "from-file", "", "read the value from this file instead of stdin")
	return cmd
}

func runCredentialPut(ctx context.Context, t *trust, name string, value []byte, stdout, stderr io.Writer) int {
	client, err := t.client()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	att, err := client.PutCredential(ctx, name, value)
	if err != nil {
		fmt.Fprintf(stderr, "credential %s was not released: %v\n", name, err)
		return exitCode(err)
	}
	// The byte count confirms which value was sent; the value is never echoed.
	fmt.Fprintf(stdout, "released %d bytes as %s to tenant %s sandbox %s (launch document %s)\n",
		len(value), name, att.Document.Tenant, att.Document.Sandbox, podcvm.LaunchDigest(att.Launch))
	return ExitOK
}

func newExecCmd() *cobra.Command {
	var t trust
	var req podcvm.ExecRequest
	var seconds int
	var stdin bool
	cmd := &cobra.Command{
		Use:   "exec -- <command> [args...]",
		Short: "Run one command in a verified pod CVM",
		Long: `Attest the guest, then run one command in its workload context and print
what it wrote. The process exits with the command's own status.

Exit codes above the command's range: 124 the guest could not be reached or
could not run the command, 125 verification or policy failed (nothing was
sent), 1 usage error.`,
		Args:         cobra.MinimumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			req.Argv, req.TimeoutSeconds = args, seconds
			if stdin {
				data, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), podcvm.MaxExecStdin+1))
				if err != nil {
					return err
				}
				req.Stdin = data
			}
			os.Exit(runExec(cmd.Context(), &t, req, cmd.OutOrStdout(), cmd.ErrOrStderr()))
			return nil
		},
	}
	t.register(cmd)
	f := cmd.Flags()
	f.StringVar(&req.ID, "id", "", "idempotency id, 32 hex characters: a repeated id returns the first result (default: random)")
	f.StringVar(&req.Cwd, "cwd", "", "working directory in the guest")
	f.IntVar(&seconds, "exec-timeout", 0, fmt.Sprintf("seconds before the guest kills the command (default %d, max %d)", podcvm.DefaultExecLimit, podcvm.MaxExecTimeout))
	f.BoolVarP(&stdin, "stdin", "i", false, "send this process's stdin to the command")
	return cmd
}

func runExec(ctx context.Context, t *trust, req podcvm.ExecRequest, stdout, stderr io.Writer) int {
	client, err := t.client()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(ctx, t.timeout+time.Duration(req.TimeoutSeconds)*time.Second)
	defer cancel()
	resp, err := client.Exec(ctx, req)
	if err != nil {
		fmt.Fprintf(stderr, "command was not run: %v\n", err)
		if exitCode(err) == ExitRefused {
			return ExitExecRefused
		}
		return ExitExecUnavailable
	}
	_, _ = stdout.Write(resp.Stdout)
	_, _ = stderr.Write(resp.Stderr)
	if resp.StdoutTruncated || resp.StderrTruncated {
		fmt.Fprintf(stderr, "c8s: output was truncated at %d bytes per stream\n", podcvm.MaxExecOutput)
	}
	if resp.TimedOut {
		fmt.Fprintln(stderr, "c8s: the command was killed at its timeout")
	}
	return resp.ExitCode
}
