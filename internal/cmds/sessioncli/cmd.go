// Package sessioncli is the command line for confidential sessions: write a
// pool's signed launch bundle, bind one of its guests to a session, then
// verify the bound guest, release credentials into it and run commands in it.
// Every command that talks to a guest goes through the trust gate in
// pkg/session first.
package sessioncli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionschema"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/daemon"
	"github.com/confidential-dot-ai/c8s/pkg/session/keyservice"
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

	// `c8s session exec` exits with the remote command's own status, so its
	// failures to run anything at all sit above the range commands use.
	ExitExecUnavailable = 124
	ExitExecRefused     = 125
)

// NewCmd returns the `c8s session` command group.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Launch, bind, verify and drive confidential sessions",
		Long: `A confidential session runs in a confidential VM of its own. A pool's guests
boot from one signed launch document, which 'launch-config new' writes and
which names no tenant. 'start' takes a guest from a pool that a c8s daemon
keeps and makes it a session's, once, under its owner's authority. 'bind'
does the same to a guest reached by its address. 'verify', 'credential put'
and 'exec' talk to the bound guest, and each one first proves from hardware
evidence that the guest is the pinned image, launched for the pool's key,
bound by exactly that bind, and that it holds the key the connection ends
at. 'destroy' ends a session, and 'watch' shows an orchestrator the guests
of a host as they change.
See docs/sessions.md.`,
	}
	launch := &cobra.Command{Use: "launch-config", Short: "Create a pool's signed launch bundle"}
	launch.AddCommand(newBundleCmd(), newLaunchKeyCmd(), newMachineCmd())
	credential := &cobra.Command{Use: "credential", Short: "Release credentials into a verified guest"}
	credential.AddCommand(newCredentialPutCmd())
	cmd.AddCommand(launch, newStartCmd(), newBindCmd(), newVerifyCmd(), credential, newExecCmd(), newDestroyCmd(), newWatchCmd(), keyServiceCmd(), sessionschema.NewCmd())
	cmd.AddCommand(imageStoreCmds()...)
	return cmd
}

// sandboxFlags say what runs in a guest and who may drive it: what a bind
// decides.
type sandboxFlags struct {
	image, workingDir                                                              string
	command, args, env, egress, credentials, execKeys, credentialKeys, forwardKeys []string
	forwardPorts                                                                   []int
	// stored are the credentials the guest takes from its key service, and
	// keyService the file that pins that key service.
	stored     []string
	keyService string
}

// egressNone is the --egress value that allows the sandbox no destination.
const egressNone = "none"

func (w *sandboxFlags) register(f *pflag.FlagSet, besides string) {
	f.StringVar(&w.image, "sandbox-image", "", "OCI image the guest pulls and runs, as name@sha256:<digest>")
	f.StringArrayVar(&w.command, "command", nil, "sandbox entrypoint override, one element per flag")
	f.StringArrayVar(&w.args, "arg", nil, "sandbox argument, one element per flag")
	f.StringArrayVar(&w.env, "env", nil, "sandbox environment NAME=value (not for secrets)")
	f.StringVar(&w.workingDir, "working-dir", "", "sandbox working directory")
	f.StringArrayVar(&w.egress, "egress", nil, "destination the sandbox may connect to, as host:port, *.domain:port or address:port (repeatable); \"none\" allows none. Without it the sandbox may connect to any public destination. A private address is reached only if named here")
	f.StringArrayVar(&w.credentials, "credential", nil, "credential NAME[:MAXBYTES] the sandbox may be handed after attestation")
	f.StringArrayVar(&w.stored, "stored-credential", nil, "credential NAME[:MAXBYTES] the guest takes from the key service when it is bound: one the tenant stored there with 'c8s session key-service credential put' (needs --key-service)")
	f.StringVar(&w.keyService, "key-service", "", "pin of the key service the session trusts, as 'c8s session key-service pin' writes it")
	f.StringArrayVar(&w.execKeys, "exec-key", nil, "public key PEM file granted exec, in addition to "+besides)
	f.StringArrayVar(&w.credentialKeys, "credential-key", nil, "public key PEM file granted credential release, in addition to "+besides)
	f.IntSliceVar(&w.forwardPorts, "forward-port", nil, "TCP port of the sandbox, on its own loopback, that a holder of a forward key may open a stream to (repeatable). Without it nothing outside the guest connects to the sandbox")
	f.StringArrayVar(&w.forwardKeys, "forward-key", nil, "public key PEM file granted streams to the --forward-port ports, in addition to "+besides)
}

func (w *sandboxFlags) sandbox() (*session.Sandbox, error) {
	if w.image == "" {
		if len(w.command)+len(w.args)+len(w.env)+len(w.egress)+len(w.forwardPorts) > 0 || w.workingDir != "" {
			return nil, errors.New("--command, --arg, --env, --egress, --forward-port and --working-dir need --sandbox-image")
		}
		return nil, nil
	}
	sandbox := &session.Sandbox{Image: w.image, Command: w.command, Args: w.args, WorkingDir: w.workingDir}
	if len(w.env) > 0 {
		sandbox.Env = map[string]string{}
		for _, kv := range w.env {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return nil, fmt.Errorf("--env %q must be NAME=value", kv)
			}
			sandbox.Env[k] = v
		}
	}
	return sandbox, nil
}

// egressPolicy is the sandbox's allowlist, or nil when the flags set none.
func (w *sandboxFlags) egressPolicy() (*session.Egress, error) {
	switch {
	case len(w.egress) == 1 && w.egress[0] == egressNone:
		return &session.Egress{Allow: []string{}}, nil
	case slices.Contains(w.egress, egressNone):
		return nil, fmt.Errorf("--egress %s stands alone: it allows no destination", egressNone)
	case len(w.egress) > 0:
		return &session.Egress{Allow: w.egress}, nil
	}
	return nil, nil
}

// forward is the area that opens the --forward-port ports, or nil when the
// flags name none.
func (w *sandboxFlags) forward() *session.Forward {
	if len(w.forwardPorts) == 0 {
		return nil
	}
	// The bind lists them in one order. A port given twice stays twice, for
	// the bind's own check to refuse.
	return &session.Forward{Ports: slices.Sorted(slices.Values(w.forwardPorts))}
}

func (w *sandboxFlags) declared() ([]session.Credential, error) {
	var out []session.Credential
	for flag, specs := range map[string][]string{"--credential": w.credentials, "--stored-credential": w.stored} {
		for _, spec := range specs {
			name, limit, _ := strings.Cut(spec, ":")
			c := session.Credential{Name: name}
			if flag == "--stored-credential" {
				c.Source = session.SourceKeyService
			}
			if limit != "" {
				n, err := strconv.Atoi(limit)
				if err != nil || n <= 0 {
					return nil, fmt.Errorf("%s %q: size must be a positive byte count", flag, spec)
				}
				c.MaxBytes = n
			}
			out = append(out, c)
		}
	}
	// One order, whatever order the flags came in.
	slices.SortFunc(out, func(a, b session.Credential) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// pin is the key service the flags have the session trust, or nil.
func (w *sandboxFlags) pin() (*session.KeyService, error) {
	if w.keyService == "" {
		if len(w.stored) > 0 {
			return nil, errors.New("--stored-credential needs --key-service: the key service the session trusts")
		}
		return nil, nil
	}
	pin, err := session.LoadKeyServicePin(w.keyService)
	if err != nil {
		return nil, fmt.Errorf("--key-service: %w", err)
	}
	return pin, nil
}

// servedBy holds a pool to the key service the owner pins. A guest of a pool
// that pins another one would refuse the bind, so the pool's own pin, from
// the launch document the guest measured, is checked before anything is
// signed.
func servedBy(pin, pool *session.KeyService) error {
	if pin != nil && !pin.Equal(pool) {
		return &session.VerificationError{Err: errors.New("the pool's guests open their sessions with another key service than --key-service pins, or with none")}
	}
	return nil
}

// judgedMembers judges the replica of the pinned key service that answers,
// as for a release: on the vendor's documents as engine fetched them itself.
// The bind names it, and its guest then deals with that replica alone. Nil
// for a session that trusts no key service.
func judgedMembers(ctx context.Context, pin *session.KeyService, engine session.Engine) ([]string, error) {
	if pin == nil {
		return nil, nil
	}
	replicas, err := keyservice.NewMembers(keyservice.Options{Pin: pin, Engine: engine})
	if err != nil {
		return nil, err
	}
	defer replicas.Close()
	return replicas.Named(ctx)
}

func (w *sandboxFlags) keys() (access session.Access, err error) {
	if access.Exec, err = readKeys(w.execKeys); err != nil {
		return session.Access{}, fmt.Errorf("--exec-key: %w", err)
	}
	if access.Credentials, err = readKeys(w.credentialKeys); err != nil {
		return session.Access{}, fmt.Errorf("--credential-key: %w", err)
	}
	if access.Forward, err = readKeys(w.forwardKeys); err != nil {
		return session.Access{}, fmt.Errorf("--forward-key: %w", err)
	}
	return access, nil
}

// policy is what the flags have a bind decide, with a key made for this one
// session granted every area the bind opens. The authority signs binds and
// nothing else: that key drives the session.
func (w *sandboxFlags) policy() (policy session.BindPolicy, accessPEM []byte, err error) {
	if policy.Sandbox, err = w.sandbox(); err != nil {
		return policy, nil, err
	}
	if policy.Egress, err = w.egressPolicy(); err != nil {
		return policy, nil, err
	}
	if policy.Credentials, err = w.declared(); err != nil {
		return policy, nil, err
	}
	if policy.Access, err = w.keys(); err != nil {
		return policy, nil, err
	}
	policy.Forward = w.forward()
	access, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return policy, nil, fmt.Errorf("generate access key: %w", err)
	}
	if accessPEM, err = certutil.MarshalECKeyPEM(access); err != nil {
		return policy, nil, err
	}
	accessPub, err := session.PublicKeyPEM(&access.PublicKey)
	if err != nil {
		return policy, nil, err
	}
	policy.Access.Exec = append([]string{string(accessPub)}, policy.Access.Exec...)
	policy.Access.Credentials = append([]string{string(accessPub)}, policy.Access.Credentials...)
	// Streams only where the bind opens a port: a key with nothing to open is
	// not written into a document.
	if policy.Forward != nil {
		policy.Access.Forward = append([]string{string(accessPub)}, policy.Access.Forward...)
	}
	return policy, accessPEM, nil
}

// newLaunchKeyCmd returns `c8s session launch-config key`.
func newLaunchKeyCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Make a launch key ahead of its bundle",
		Long: `Write a new launch private key to --out and its public half to <out>.pub.
A pool whose launch document pins a key service needs its key first: the key
service's own launch document lists the pool's public key. Pass the private
key to 'launch-config new' with --key.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return err
			}
			private, err := certutil.MarshalECKeyPEM(key)
			if err != nil {
				return err
			}
			public, err := session.PublicKeyPEM(&key.PublicKey)
			if err != nil {
				return err
			}
			// Neither replaces a file that is there: a launch key is not
			// one to lose to a second run.
			for path, file := range map[string]struct {
				data []byte
				mode os.FileMode
			}{out: {private, 0o600}, out + ".pub": {public, 0o644}} {
				f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, file.mode)
				if err != nil {
					return err
				}
				_, err = f.Write(file.data)
				if closeErr := f.Close(); err == nil {
					err = closeErr
				}
				if err != nil {
					return err
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s and %s.pub\n", out, out)
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "file for the private key (must not exist)")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

func newBundleCmd() *cobra.Command {
	var opts session.BundleOptions
	var keyService string
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Write and sign a pool's launch document",
		Long: `Write everything a pool's guests boot from:

  <out>/launch.key              launch private key (unless --key reuses one)
  <out>/opkeydata/pubkey        the public key the guest measures
  <out>/opkeydata/launch.yaml   the launch document
  <out>/opkeydata/launch.yaml.sig

Give the opkeydata directory to whatever launches the pool's guests. The
document carries no secrets, so it can be shown to anyone who needs to verify
a guest. It names no tenant and grants no access, the launch key included:
each guest waits for one bind, see 'c8s session bind'.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if keyService != "" {
				pin, err := session.LoadKeyServicePin(keyService)
				if err != nil {
					return fmt.Errorf("--key-service: %w", err)
				}
				opts.KeyService = pin
			}
			if err := session.NewBundle(opts); err != nil {
				return err
			}
			bundle, err := session.LoadBundle(opts.Dir)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote launch bundle %s for pool %s, class %s\nlaunch document %s\n",
				opts.Dir, bundle.Document.Pool, bundle.Document.Class, session.DocumentDigest(bundle.Launch))
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.Dir, "out", "", "bundle directory to create (must not exist)")
	f.StringVar(&opts.ManifestPath, "image-manifest", "", "manifest.json published with the session guest image")
	f.IntVar(&opts.VCPUs, "vcpus", 0, "SNP only: the VM's vCPU count, selecting its launch digest")
	f.StringVar(&opts.KeyPath, "key", "", "existing launch private key to sign with (default: generate <out>/launch.key)")
	f.StringVar(&opts.Pool, "pool", "", "the pool's name, an RFC1123 label")
	f.StringVar(&opts.Class, "class", "", "the class of VM the pool's guests are launched in, an RFC1123 label")
	f.DurationVar(&opts.AgeLimit, "age-limit", time.Hour, "how long a guest waits for its bind, on its own clock, before it ends; 0 sets no bound")
	f.StringArrayVar(&opts.Machines, "machine", nil, "a machine the guest may be, as the value its RTMR[0] then holds (96 hex characters, as 'c8s session verify' prints it for a guest on that machine); repeatable. The guest's host can then launch it in no other shape. Without it the document pins no machine")
	f.StringArrayVar(&opts.Prestage, "prestage", nil, "a public image, name@sha256:<digest>, that a guest unpacks from its host's image store before anybody binds it, so that a bind which names it starts it at once (repeatable)")
	f.StringVar(&keyService, "key-service", "", "pin of the key service the pool's guests open their sessions with, as 'c8s session key-service pin' writes it. Without it a guest of the pool takes no credential from a key service")
	for _, name := range []string{"out", "image-manifest", "pool", "class"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

// noToken is the authorizer of a command that asks a guest only what it
// tells anyone.
type noToken struct{}

func (noToken) AuthorizationFor(string, string, string, []byte) (string, error) {
	return "", errors.New("this command holds no key to sign a request with")
}

func newMachineCmd() *cobra.Command {
	var m trust
	cmd := &cobra.Command{
		Use:   "machine",
		Short: "Print the machine a pool's guest runs on, for its launch document to list",
		Long: `Verify one guest that nobody has bound and print what its RTMR[0] holds: the
machine its host built it.

A launch document lists the machines its pool's guests may be ('launch-config
new --machine'), and a TD whose document lists none takes no bind. So a
pool's document is first written without --machine, one guest is launched
from it in the pool's class, this command reads the value from that guest's
evidence, and the document is written again with it.

The value comes from evidence that verified for the pinned image under the
pool's launch key. It is what one host declared to the firmware for one shape
of VM: compare it with a second host of the same build before it is
published as a class's reference value.

Exit codes: 0 printed, 1 usage error, 2 the guest is not what was pinned,
3 the guest could not be reached or judged.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			os.Exit(runMachine(cmd.Context(), &m, cmd.OutOrStdout(), cmd.ErrOrStderr()))
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&m.url, "url", "", "the guest's agent, as https://host:port")
	f.StringVar(&m.manifest, "image-manifest", "", "manifest.json published with the session guest image")
	f.StringVar(&m.launchKey, "launch-key", "", "the pool's public launch key, PEM")
	m.collateralFlags(f)
	f.DurationVar(&m.timeout, "timeout", 2*time.Minute, "overall deadline")
	for _, name := range []string{"url", "image-manifest", "launch-key"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

// runMachine verifies one unbound guest of a pool and prints its machine.
func runMachine(ctx context.Context, m *trust, stdout, stderr io.Writer) int {
	identity, err := runtimemeasure.LoadImageManifest(m.manifest)
	if err != nil {
		fmt.Fprintf(stderr, "--image-manifest: %v\n", err)
		return ExitUsage
	}
	launchKey, err := session.ReadBounded(m.launchKey, 8192)
	if err != nil {
		fmt.Fprintf(stderr, "--launch-key: %v\n", err)
		return ExitUsage
	}
	// A policy that names no authority accepts a guest nobody has bound, and
	// nothing else. This is the one command that takes the word of a guest
	// whose document lists no machine: it is how the value gets listed.
	policy := session.Policy{Image: identity, LaunchKey: launchKey, AllowReady: true, AllowNoMachine: true, AcceptTCBStatus: m.acceptedTCB()}
	client, err := session.NewClient(m.url, policy, m.engine(), noToken{}, m.road(stderr)...)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	ready, err := client.Ready(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "NOT VERIFIED: %v\n", err)
		return exitCode(err)
	}
	if len(ready.Machine) == 0 {
		fmt.Fprintln(stderr, "the guest's evidence holds no register for its machine: only a TD has one")
		return ExitRefused
	}
	fmt.Fprintln(stdout, hex.EncodeToString(ready.Machine))
	if ready.Document.Machine != nil {
		fmt.Fprintf(stderr, "the guest's launch document lists it among %d machines\n", len(ready.Document.Machine.RTMR0))
	}
	return ExitOK
}

func readKeys(paths []string) ([]string, error) {
	var out []string
	for _, path := range paths {
		data, err := session.ReadBounded(path, 8192)
		if err != nil {
			return nil, err
		}
		out = append(out, string(data))
	}
	return out, nil
}

// trust is the flag set every command that talks to a bound guest shares.
type trust struct {
	url       string
	binding   string
	authority string
	manifest  string
	launchKey string
	tenant    string
	session   string
	key       string
	// collateralCache is the directory Intel's collateral is kept in between
	// commands, or empty to fetch it every time.
	collateralCache string
	// freshCollateral refuses a kept document past the hour when Intel
	// cannot be asked for a new one.
	freshCollateral bool
	// ownCollateral takes Intel's documents from Intel's service alone, and
	// none the guest hands over.
	ownCollateral bool
	// timing prints how long each step took.
	timing bool
	// fresh asks the guest for a quote even when --binding holds a verdict
	// that would spare it.
	fresh bool
	// acceptTCB names Intel TCB statuses, besides UpToDate, that the guest's
	// platform may have.
	acceptTCB []string
	// kept is the verdict the binding held when the client was made.
	kept          *session.Verdict
	allowBound    bool
	timeout       time.Duration
	engineForTest session.Engine
	// daemon is how the guest's host is reached when the guest is, and td
	// the guest's TD there. A binding that 'start' wrote names both.
	daemon daemonFlags
	td     string
	// through is the daemon the client's connections run through, if any.
	through *daemon.Client
}

// close ends what client opened besides the client.
func (t *trust) close() {
	if t.through != nil {
		_ = t.through.Close()
	}
}

// collateralFlags are the flags every command that judges evidence takes.
func (t *trust) collateralFlags(f *pflag.FlagSet) {
	f.StringVar(&t.collateralCache, "collateral-cache", defaultCollateralCache(),
		"directory that keeps Intel's collateral between commands, for an hour; every document in it is verified again at each use. Empty fetches the collateral every time")
	f.BoolVar(&t.freshCollateral, "fresh-collateral-only", false,
		"when Intel's service cannot be reached, fail also where the command would go on, for a check that sends the guest nothing secret, with collateral older than an hour that Intel's own date still covers. Before anything is released or run it never goes on with such")
	f.BoolVar(&t.ownCollateral, "own-collateral-only", false,
		"take Intel's collateral from Intel's service alone, also for a check that sends the guest nothing secret. Without it such a check, when the command has none, asks the guest for the copies its host fetched, and takes each that Intel signed within two hours. Before anything is released or run the command fetches all of it itself")
	f.BoolVar(&t.timing, "timing", false, "print how long each step took, a line each, to standard error")
	f.StringSliceVar(&t.acceptTCB, "accept-tcb-status", nil,
		"an Intel TCB status, besides UpToDate, that the guest's platform, its TDX module or its quoting enclave may have, such as OutOfDate or SWHardeningNeeded; repeat for more. Without it each of the three must be UpToDate. Revoked is never accepted")
}

// acceptedTCB is --accept-tcb-status as a policy carries it: sorted, each
// status once.
func (t *trust) acceptedTCB() []string {
	accepted := slices.Clone(t.acceptTCB)
	slices.Sort(accepted)
	return slices.Compact(accepted)
}

// road is how the flags say to report on the way to the guest.
func (t *trust) road(stderr io.Writer) []session.ClientOption {
	if report := t.steps(stderr); report != nil {
		return []session.ClientOption{session.Timed(report)}
	}
	return nil
}

// steps prints each step a client takes, when --timing asks for it.
func (t *trust) steps(stderr io.Writer) session.Timing {
	if !t.timing {
		return nil
	}
	var mu sync.Mutex
	return func(step string, took time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(stderr, "timing\t%s\t%d us\n", step, took.Microseconds())
	}
}

func (t *trust) register(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&t.url, "url", "", "the guest agent, https://<address>:8443, for a guest reached by its address")
	t.daemon.register(f, false)
	f.StringVar(&t.td, "td", "", "the guest's TD at --daemon (default: the one --binding names)")
	f.StringVar(&t.binding, "binding", "", "binding directory written by 'c8s session start' or 'c8s session bind': pins the guest's launch document and bind, supplies the access key and, from 'start', says where the guest is reached")
	f.StringVar(&t.authority, "authority", "", "authority public key PEM the guest must be bound under (default: the one that signed --binding)")
	f.StringVar(&t.manifest, "image-manifest", "", "manifest.json published with the session guest image")
	f.StringVar(&t.launchKey, "launch-key", "", "the pool's launch public key PEM, when no --binding is at hand (then --authority, --tenant and --session are required)")
	f.StringVar(&t.tenant, "tenant", "", "tenant the guest must belong to")
	f.StringVar(&t.session, "session", "", "session the guest must be bound to")
	f.StringVar(&t.key, "key", "", "private key that signs requests (default <binding>/access.key)")
	f.BoolVar(&t.fresh, "fresh", false, "ask the guest for a fresh quote and judge it, where a verdict kept in --binding within the last hour would spare both")
	t.collateralFlags(f)
	f.DurationVar(&t.timeout, "timeout", 2*time.Minute, "overall deadline")
	_ = cmd.MarkFlagRequired("image-manifest")
}

// client turns the flags into a verifying client. Every failure here is a
// usage error: nothing has been sent yet.
func (t *trust) client(stderr io.Writer) (*session.Client, error) {
	identity, err := runtimemeasure.LoadImageManifest(t.manifest)
	if err != nil {
		return nil, fmt.Errorf("--image-manifest: %w", err)
	}
	policy := session.Policy{
		Image: identity, Tenant: t.tenant, Session: t.session, AllowBound: t.allowBound,
		AcceptTCBStatus: t.acceptedTCB(),
	}
	if t.authority != "" {
		if policy.Authority, err = session.ReadBounded(t.authority, 8192); err != nil {
			return nil, fmt.Errorf("--authority: %w", err)
		}
	}
	keyPath := t.key
	switch {
	case t.binding != "" && t.launchKey != "":
		return nil, errors.New("--binding and --launch-key are alternatives")
	case t.binding != "":
		binding, err := session.LoadBinding(t.binding)
		if err != nil {
			return nil, fmt.Errorf("--binding: %w", err)
		}
		if policy.Authority != nil && !binding.Bind.SignedBy(policy.Authority) {
			return nil, errors.New("--binding was signed by another authority than --authority")
		}
		pinned := binding.Policy(identity)
		pinned.Tenant, pinned.Session, pinned.AllowBound = t.tenant, t.session, t.allowBound
		pinned.AcceptTCBStatus = t.acceptedTCB()
		policy = pinned
		if keyPath == "" {
			keyPath = filepath.Join(t.binding, session.AccessKeyFile)
		}
	case t.launchKey != "":
		if policy.LaunchKey, err = session.ReadBounded(t.launchKey, 8192); err != nil {
			return nil, fmt.Errorf("--launch-key: %w", err)
		}
		if policy.Authority == nil {
			return nil, errors.New("--launch-key needs --authority: whose bind the guest must have taken")
		}
	default:
		return nil, errors.New("one of --binding or --launch-key is required")
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
	road := t.road(stderr)
	url, through, err := t.reach()
	if err != nil {
		return nil, err
	}
	if through != nil {
		road = append(road, through)
	}
	if t.binding != "" && !t.fresh {
		// A file that is no verdict is none: the command attests, and keeps
		// its own in the file's place.
		kept, err := session.LoadVerdict(t.binding)
		if err != nil {
			fmt.Fprintf(stderr, "the kept verdict is not used: %v\n", err)
		}
		t.kept = kept
		road = append(road, session.Kept(t.kept))
	}
	return session.NewClient(url, policy, t.engine(), signer, road...)
}

// keep leaves the client's verdict in the binding for the next command, when
// the client reached one this command did not start with. A verdict that did
// not hold, because the guest presented another key, is removed.
func (t *trust) keep(client *session.Client, stderr io.Writer) {
	if t.binding == "" {
		return
	}
	// The guest at this address is not the one the verdict is of.
	if client.AnotherKey() {
		_ = os.Remove(filepath.Join(t.binding, session.VerdictFile))
		return
	}
	v, ok := client.Verdict()
	if !ok || reflect.DeepEqual(v, t.kept) {
		return
	}
	if err := session.WriteVerdict(t.binding, v); err != nil {
		fmt.Fprintf(stderr, "the next command will attest the guest again: %v\n", err)
	}
}

func (t *trust) engine() session.Engine {
	if t.engineForTest != nil {
		return t.engineForTest
	}
	return session.NewEngine(session.EngineOptions{
		CollateralCacheDir: t.collateralCache, FreshCollateralOnly: t.freshCollateral, OwnCollateralOnly: t.ownCollateral,
	})
}

// defaultCollateralCache is under the user's cache directory, or nowhere on a
// system that has none.
func defaultCollateralCache() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "c8s", "collateral")
}

// exitCode sorts an error into the CI contract.
func exitCode(err error) int {
	var verdict *session.VerificationError
	switch {
	case err == nil:
		return ExitOK
	case errors.As(err, &verdict):
		return ExitRefused
	default:
		return ExitUnavailable
	}
}

// verdict is the machine-readable result of `c8s session verify`.
type verdict struct {
	Verified     bool   `json:"verified"`
	Error        string `json:"error,omitempty"`
	Tenant       string `json:"tenant,omitempty"`
	Session      string `json:"session,omitempty"`
	Phase        string `json:"phase,omitempty"`
	Platform     string `json:"platform,omitempty"`
	LaunchDigest string `json:"launch_digest,omitempty"`
	// BindDigest is the bind the guest measured.
	BindDigest string `json:"bind_digest,omitempty"`
	// Receipt says the binding keeps the guest's receipt for its bind, and
	// that this attestation confirms it.
	Receipt           bool     `json:"receipt"`
	Events            []string `json:"events,omitempty"`
	MRTD              string   `json:"mrtd,omitempty"`
	InstanceKeySHA256 string   `json:"instance_key_sha256,omitempty"`
	// Machine is the guest's RTMR[0]: what its firmware measured of the
	// machine the host built. MachinePinned says the launch document lists it.
	Machine       string `json:"machine,omitempty"`
	MachinePinned bool   `json:"machine_pinned"`
	// Egress is where the sandbox may connect. Absent for a guest that runs
	// no sandbox image.
	Egress *egress `json:"egress,omitempty"`
	// Forward is what of the sandbox is opened to streams from outside the
	// guest, and to how many keys. Absent for a guest that runs no sandbox
	// image.
	Forward            *forwarded `json:"forward,omitempty"`
	CollateralVerified bool       `json:"collateral_verified"`
	// Collateral is what the verdict rests on of Intel's documents.
	Collateral *session.CollateralFinding `json:"collateral,omitempty"`
	// NotProven lists what this verdict does not establish.
	NotProven []string `json:"not_proven,omitempty"`
}

// egress is a sandbox's egress policy as a verdict shows it.
type egress struct {
	// AnyPublic: the guest's bind carries no egress area, so the sandbox
	// reaches every public destination. Private networks and the guest
	// itself stay closed.
	AnyPublic bool `json:"any_public"`
	// Allow is the allowlist otherwise. Empty allows nothing.
	Allow []string `json:"allow"`
}

func egressOf(att *session.Attestation) *egress {
	policy, ok := att.Egress()
	switch {
	case !ok:
		return nil
	case policy == nil:
		return &egress{AnyPublic: true, Allow: []string{}}
	}
	return &egress{Allow: append([]string{}, policy.Allow...)}
}

func (e *egress) String() string {
	switch {
	case e.AnyPublic:
		return "any public destination"
	case len(e.Allow) == 0:
		return "none"
	}
	return strings.Join(e.Allow, " ")
}

// forwarded is a sandbox's forward area as a verdict shows it.
type forwarded struct {
	// Ports are the sandbox's ports a stream may be opened to. Empty: none.
	Ports []int `json:"ports"`
	// Keys may open one, each as sha256:<hex> of its PKIX encoding.
	Keys []string `json:"keys"`
}

func forwardOf(att *session.Attestation) *forwarded {
	if _, sandbox := att.Egress(); !sandbox {
		return nil
	}
	out := &forwarded{Ports: []int{}, Keys: []string{}}
	if area, keys := att.Forward(); area != nil {
		out.Ports, out.Keys = append(out.Ports, area.Ports...), append(out.Keys, keys...)
	}
	return out
}

func (f *forwarded) String() string {
	if len(f.Ports) == 0 {
		return "none"
	}
	ports := make([]string, len(f.Ports))
	for i, port := range f.Ports {
		ports[i] = strconv.Itoa(port)
	}
	noun := "keys"
	if len(f.Keys) == 1 {
		noun = "key"
	}
	return fmt.Sprintf("ports %s, to %d %s", strings.Join(ports, " "), len(f.Keys), noun)
}

func newVerifyCmd() *cobra.Command {
	var t trust
	var output string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a bound guest from hardware evidence",
		Long: `Fetch evidence for a fresh nonce and check, in process, that the guest
answering on this connection is the pinned image, was launched for the pool's
launch key, measured exactly the expected launch document, bind and sandbox,
is not debuggable, and holds the key this connection terminates on.

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
	cmd.Flags().BoolVar(&t.allowBound, "allow-bound", false, "accept a guest that has measured its bind but not yet its sandbox")
	cmd.Flags().StringVarP(&output, "output", "o", "text", "text or json")
	return cmd
}

func runVerify(ctx context.Context, t *trust, asJSON bool, stdout, stderr io.Writer) int {
	// To verify is to judge fresh evidence, whatever a binding has kept.
	fresh := *t
	fresh.fresh = true
	t = &fresh
	client, err := t.client(stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	defer t.close()
	defer client.Close()
	defer t.keep(client, stderr)
	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	att, err := client.Attest(ctx)
	// A receipt kept with the binding is the guest's own word that it took
	// the bind. The guest that was just attested must be the one that gave
	// it, with the register the receipt lists.
	var receipted bool
	if err == nil && t.binding != "" {
		var kept *session.SignedReceipt
		if kept, err = session.LoadReceipt(t.binding); err == nil && kept != nil {
			if _, err = client.ConfirmReceipt(ctx, kept, att); err != nil {
				err = &session.VerificationError{Err: fmt.Errorf("the receipt kept with the binding is not this guest's word on its bind: %w", err)}
			}
			receipted = err == nil
		}
	}
	v := verdict{Verified: err == nil, Receipt: receipted}
	if err != nil {
		v.Error = err.Error()
	} else {
		v.Tenant, v.Session = att.Tenant, att.Session
		v.Phase, v.Platform = string(att.Phase), string(att.Result.Platform)
		v.LaunchDigest, v.Events = session.DocumentDigest(att.Launch), att.Events
		if att.Bind != nil {
			v.BindDigest = session.DocumentDigest(att.Bind.Raw)
		}
		v.MRTD = att.Result.Claims.LaunchDigest
		v.Egress, v.Forward = egressOf(att), forwardOf(att)
		v.InstanceKeySHA256 = certutil.CertFingerprint(att.InstanceKey)
		if rtmr0, err := att.Result.Claims.RTMR(0); err == nil {
			v.Machine, v.MachinePinned = hex.EncodeToString(rtmr0), att.Document.Machine != nil
		}
		v.CollateralVerified = att.Result.CollateralVerified
		v.Collateral = session.CollateralOf(att.Result)
		if !att.Result.CollateralVerified {
			v.NotProven = append(v.NotProven, "platform TCB level, quoting enclave version and certificate revocation (collateral was not checked)")
		}
		if v.Collateral != nil && v.Collateral.Stale {
			v.NotProven = append(v.NotProven, fmt.Sprintf("that Intel has published nothing newer about this platform since %s: its service could not be reached, and the verdict rests on the collateral fetched then",
				v.Collateral.Fetched.UTC().Format(time.RFC3339)))
		}
		if v.Collateral != nil && !v.Collateral.UpToDate() {
			v.NotProven = append(v.NotProven, "that the platform is patched: its TCB is behind Intel's current level and was accepted by --accept-tcb-status")
		}
		if v.Machine != "" && !v.MachinePinned {
			v.NotProven = append(v.NotProven, "that the guest's host built it a machine anyone recorded: its launch document lists none (RTMR[0])")
		}
	}
	if asJSON {
		_ = json.NewEncoder(stdout).Encode(v)
	} else if err != nil {
		fmt.Fprintf(stderr, "NOT VERIFIED: %v\n", err)
	} else {
		fmt.Fprintf(stdout, "VERIFIED %s session guest\n  tenant        %s\n  session       %s\n  phase         %s\n  launch doc    %s\n",
			v.Platform, v.Tenant, v.Session, v.Phase, v.LaunchDigest)
		if v.BindDigest != "" {
			fmt.Fprintf(stdout, "  bind          %s\n", v.BindDigest)
		}
		if v.Receipt {
			fmt.Fprintf(stdout, "  receipt       the guest's receipt for the bind, confirmed by this quote\n")
		}
		if v.Egress != nil {
			fmt.Fprintf(stdout, "  egress        %s\n", v.Egress)
		}
		if v.Forward != nil {
			fmt.Fprintf(stdout, "  forward       %s\n", v.Forward)
		}
		fmt.Fprintf(stdout, "  events        %s\n  image (MRTD)  %s\n  instance key  sha256:%s\n", strings.Join(v.Events, " "), v.MRTD, v.InstanceKeySHA256)
		if v.Machine != "" {
			pinned := "pinned by the launch document"
			if !v.MachinePinned {
				pinned = "not pinned"
			}
			fmt.Fprintf(stdout, "  machine       %s (%s)\n", v.Machine, pinned)
		}
		if v.Collateral != nil && v.Collateral.Platform != "" {
			tcb := "platform " + v.Collateral.Platform
			if v.Collateral.Module != "" {
				tcb += ", TDX module " + v.Collateral.Module
			}
			fmt.Fprintf(stdout, "  TCB           %s, quoting enclave %s\n", tcb, v.Collateral.QuotingEnclave)
		}
		if v.Collateral != nil && v.Collateral.Stapled {
			fmt.Fprintf(stdout, "  collateral    handed over by the guest, the oldest signed by Intel at %s\n", v.Collateral.Fetched.UTC().Format(time.RFC3339))
		}
		for _, gap := range v.NotProven {
			fmt.Fprintf(stdout, "  NOT PROVEN    %s\n", gap)
		}
	}
	return exitCode(err)
}

// bindFlags are what 'c8s session bind' needs besides the sandbox: where the
// guest is, what it must be, and whose it becomes.
type bindFlags struct {
	trust
	authorityKey string
	out          string
	ttl          time.Duration
	w            sandboxFlags
}

// bound is the machine-readable result of `c8s session bind`.
type bound struct {
	Bound        bool   `json:"bound"`
	Error        string `json:"error,omitempty"`
	Tenant       string `json:"tenant,omitempty"`
	Session      string `json:"session,omitempty"`
	Phase        string `json:"phase,omitempty"`
	LaunchDigest string `json:"launch_digest,omitempty"`
	BindDigest   string `json:"bind_digest,omitempty"`
	Binding      string `json:"binding,omitempty"`
	// How long each step took, as this process saw it.
	ReadyCheckMillis int64 `json:"ready_check_ms,omitempty"`
	BindMillis       int64 `json:"bind_ms,omitempty"`
	AttestMillis     int64 `json:"attest_ms,omitempty"`
	// Admission is how the guest says it spent the bind, step by step.
	Admission []session.AdmissionStep `json:"admission,omitempty"`
}

// admissionText is a guest's admission steps on one line.
func admissionText(steps []session.AdmissionStep) string {
	parts := make([]string, len(steps))
	for i, step := range steps {
		parts[i] = fmt.Sprintf("%s %s", step.Name, (time.Duration(step.Micros) * time.Microsecond).Round(100*time.Microsecond))
	}
	return strings.Join(parts, ", ")
}

func newBindCmd() *cobra.Command {
	var b bindFlags
	var output string
	cmd := &cobra.Command{
		Use:   "bind",
		Short: "Make one guest a session's, once",
		Long: `Check that the guest at --url is of the pinned image, launched under the
pool's launch key, and bound to nobody. Then sign a bind for it with the
owner's authority key and hand it over. The bind names this guest's instance
key, so it is of no use to any other. The guest measures it before anything
in it takes effect, and takes no second one.

A fresh access key is generated, granted exec, credential release and, with
--forward-port, streams to those ports, and written with the documents to
--out:

  <out>/bind.json, bind.json.sig      the bind and its signature
  <out>/launch.yaml, launch.yaml.sig  the launch document the guest measured
  <out>/pubkey                        the pool's launch key
  <out>/access.key                    the key that now drives the guest

Pass that directory as --binding to 'verify', 'credential put' and 'exec'.
The command ends with a fresh attestation under exactly those documents.

Exit codes: 0 bound and verified, 1 usage error, 2 verification failed (before
the bind: nothing was sent; after it: do not use the guest), 3 the guest could
not be reached or would not take the bind.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if output != "text" && output != "json" {
				return errors.New("-o must be text or json")
			}
			os.Exit(runBind(cmd.Context(), &b, output == "json", cmd.OutOrStdout(), cmd.ErrOrStderr()))
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&b.url, "url", "", "the guest agent, https://<address>:8443")
	f.StringVar(&b.manifest, "image-manifest", "", "manifest.json published with the session guest image")
	f.StringVar(&b.launchKey, "launch-key", "", "the pool's launch public key PEM, which its guests are launched under")
	f.StringVar(&b.authorityKey, "authority-key", "", "the owner's authority private key, which signs the bind")
	f.StringVar(&b.tenant, "tenant", "", "the tenant the session belongs to")
	f.StringVar(&b.session, "session", "", "session name, an RFC1123 label")
	f.StringVar(&b.out, "out", "", "binding directory to create (must not exist)")
	f.DurationVar(&b.ttl, "valid-for", session.DefaultBindTTL, "how long the bind may still be applied if this command does not get to deliver it")
	b.w.register(f, "the access key")
	b.collateralFlags(f)
	f.DurationVar(&b.timeout, "timeout", 2*time.Minute, "overall deadline")
	f.StringVarP(&output, "output", "o", "text", "text or json")
	for _, name := range []string{"url", "image-manifest", "launch-key", "authority-key", "tenant", "session", "out"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

func runBind(ctx context.Context, b *bindFlags, asJSON bool, stdout, stderr io.Writer) int {
	result := bound{}
	finish := func(code int, err error) int {
		if err != nil {
			result.Error = err.Error()
		}
		if asJSON {
			_ = json.NewEncoder(stdout).Encode(result)
		} else if err != nil {
			fmt.Fprintf(stderr, "NOT BOUND: %v\n", err)
		}
		return code
	}
	identity, err := runtimemeasure.LoadImageManifest(b.manifest)
	if err != nil {
		return finish(ExitUsage, fmt.Errorf("--image-manifest: %w", err))
	}
	launchKey, err := session.ReadBounded(b.launchKey, 8192)
	if err != nil {
		return finish(ExitUsage, fmt.Errorf("--launch-key: %w", err))
	}
	authority, err := certutil.LoadECPrivateKeyFile(b.authorityKey)
	if err != nil {
		return finish(ExitUsage, fmt.Errorf("--authority-key: %w", err))
	}
	authorityPub, err := session.PublicKeyPEM(&authority.PublicKey)
	if err != nil {
		return finish(ExitUsage, err)
	}
	policy, accessPEM, err := b.w.policy()
	if err != nil {
		return finish(ExitUsage, err)
	}
	keyService, err := b.w.pin()
	if err != nil {
		return finish(ExitUsage, err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(accessPEM)
	if err != nil {
		return finish(ExitUsage, err)
	}
	if _, err := os.Stat(b.out); err == nil {
		return finish(ExitUsage, fmt.Errorf("--out %s already exists", b.out))
	}
	// How long the guest took to answer the bind, which the answer's evidence
	// is judged after.
	var answered atomic.Int64
	printed := b.steps(stderr)
	road := []session.ClientOption{session.Timed(func(step string, took time.Duration) {
		if step == session.TimedRequest+" "+session.PathBind {
			answered.Store(int64(took))
		}
		if printed != nil {
			printed(step, took)
		}
	})}
	readyPolicy := session.Policy{
		Image: identity, LaunchKey: launchKey, Authority: authorityPub, AllowReady: true,
		AcceptTCBStatus: b.acceptedTCB(),
	}
	// One engine: what it fetched of the vendor's documents for one verdict
	// serves the next.
	engine := b.engine()
	client, err := session.NewClient(b.url, readyPolicy, engine, signer, road...)
	if err != nil {
		return finish(ExitUsage, err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()

	started := time.Now()
	ready, err := client.Ready(ctx)
	if err != nil {
		return finish(exitCode(err), err)
	}
	result.ReadyCheckMillis = time.Since(started).Milliseconds()
	if err := servedBy(keyService, ready.Document.KeyService); err != nil {
		return finish(ExitRefused, err)
	}
	// The bind names the replica of the key service this command judged.
	members, err := judgedMembers(ctx, keyService, engine)
	if err != nil {
		return finish(exitCode(err), fmt.Errorf("the key service's replica was not judged, and nothing was signed: %w", err))
	}
	bind, err := session.NewBind(session.BindOptions{
		Authority: authority, InstanceKey: ready.InstanceKey,
		Tenant: b.tenant, Session: b.session, NotAfter: time.Now().Add(b.ttl), Policy: policy, KeyService: keyService, Members: members,
	})
	if err != nil {
		return finish(ExitUsage, err)
	}
	// Written before it is sent: if the answer is lost the bind may still have
	// taken effect, and this record is then the only way back to the guest.
	if err := session.WriteBinding(b.out, launchKey, ready, bind, accessPEM); err != nil {
		return finish(ExitUsage, err)
	}
	result.Binding = b.out
	result.LaunchDigest, result.BindDigest = session.DocumentDigest(ready.Launch), session.DocumentDigest(bind.Raw)
	// What the guest says in its answer proves nothing. The evidence the
	// answer carries does, judged under exactly these documents, on the
	// connection the guest was reached on.
	binding := session.Binding{LaunchKey: launchKey, Launch: ready.Launch, Bind: bind}
	bound := binding.Policy(identity)
	bound.AcceptTCBStatus = b.acceptedTCB()
	started = time.Now()
	answer, att, err := client.BindAttested(ctx, bind, bound)
	if err != nil {
		if answer == nil {
			return finish(ExitUnavailable, fmt.Errorf("the guest did not take the bind: %w", err))
		}
		return finish(exitCode(err), fmt.Errorf("the bind was sent, but the guest does not verify as bound by it: %w", err))
	}
	result.Admission = answer.Admission
	// The guest's signed word that it took the bind, which its quote
	// confirmed: 'c8s session verify' holds it to a fresh quote.
	if answer.Receipt != nil {
		if err := session.WriteReceipt(b.out, answer.Receipt); err != nil {
			fmt.Fprintf(stderr, "the guest's receipt for the bind was not kept: %v\n", err)
		}
	}
	result.BindMillis = time.Duration(answered.Load()).Milliseconds()
	result.AttestMillis = (time.Since(started) - time.Duration(answered.Load())).Milliseconds()
	// For the owner's next command, which then asks the guest for no quote.
	if v, ok := client.Verdict(); ok {
		if err := session.WriteVerdict(b.out, v); err != nil {
			fmt.Fprintf(stderr, "the next command will attest the guest again: %v\n", err)
		}
	}
	result.Bound, result.Tenant, result.Session, result.Phase = true, att.Tenant, att.Session, string(att.Phase)
	if !asJSON {
		fmt.Fprintf(stdout, "BOUND %s session guest\n  tenant        %s\n  session       %s\n  phase         %s\n  launch doc    %s\n  bind          %s\n  events        %s\n  instance key  sha256:%s\n  binding       %s\n  timing        ready check %d ms, bind %d ms, attest %d ms\n",
			att.Result.Platform, att.Tenant, att.Session, att.Phase, result.LaunchDigest, result.BindDigest, strings.Join(att.Events, " "),
			certutil.CertFingerprint(att.InstanceKey), b.out, result.ReadyCheckMillis, result.BindMillis, result.AttestMillis)
		if len(result.Admission) > 0 {
			fmt.Fprintf(stdout, "  in the guest  %s\n", admissionText(result.Admission))
		}
	}
	return finish(ExitOK, nil)
}

func newCredentialPutCmd() *cobra.Command {
	var t trust
	var fromFile string
	cmd := &cobra.Command{
		Use:   "put <name>",
		Short: "Release one credential into a bound guest, after attesting it",
		Long: `Attest the guest for a fresh nonce and, only if it verifies with its
sandbox admitted, send the value on a connection that terminates at the key
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
				value, err = session.ReadBounded(fromFile, session.MaxCredentialBytes)
			} else {
				value, err = io.ReadAll(io.LimitReader(cmd.InOrStdin(), session.MaxCredentialBytes+1))
			}
			if err != nil {
				return err
			}
			if len(value) == 0 || len(value) > session.MaxCredentialBytes {
				return fmt.Errorf("credential value must be 1..%d bytes", session.MaxCredentialBytes)
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
	client, err := t.client(stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	defer t.close()
	defer client.Close()
	defer t.keep(client, stderr)
	att, err := client.PutCredential(ctx, name, value)
	if err != nil {
		fmt.Fprintf(stderr, "credential %s was not released: %v\n", name, err)
		return exitCode(err)
	}
	// The byte count confirms which value was sent; the value is never echoed.
	fmt.Fprintf(stdout, "released %d bytes as %s to tenant %s session %s (launch document %s)\n",
		len(value), name, att.Tenant, att.Session, session.DocumentDigest(att.Launch))
	return ExitOK
}

func newExecCmd() *cobra.Command {
	var t trust
	var req session.ExecRequest
	var seconds int
	var stdin bool
	cmd := &cobra.Command{
		Use:   "exec -- <command> [args...]",
		Short: "Run one command in a verified guest",
		Long: `Attest the guest, then run one command in its sandbox context and print
what it wrote. The process exits with the command's own status.

Exit codes above the command's range: 124 the guest could not be reached or
could not run the command, 125 verification or policy failed (nothing was
sent), 1 usage error.`,
		Args:         cobra.MinimumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			req.Argv, req.TimeoutSeconds = args, seconds
			if stdin {
				data, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), session.MaxExecStdin+1))
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
	f.IntVar(&seconds, "exec-timeout", 0, fmt.Sprintf("seconds before the guest kills the command (default %d, max %d)", session.DefaultExecLimit, session.MaxExecTimeout))
	f.BoolVarP(&stdin, "stdin", "i", false, "send this process's stdin to the command")
	return cmd
}

func runExec(ctx context.Context, t *trust, req session.ExecRequest, stdout, stderr io.Writer) int {
	client, err := t.client(stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	ctx, cancel := context.WithTimeout(ctx, t.timeout+time.Duration(req.TimeoutSeconds)*time.Second)
	defer cancel()
	defer t.close()
	defer client.Close()
	defer t.keep(client, stderr)
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
		fmt.Fprintf(stderr, "c8s: output was truncated at %d bytes per stream\n", session.MaxExecOutput)
	}
	if resp.TimedOut {
		fmt.Fprintln(stderr, "c8s: the command was killed at its timeout")
	}
	return resp.ExitCode
}
