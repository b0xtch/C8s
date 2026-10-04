package sessioncli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	sessionv1alpha1 "github.com/confidential-dot-ai/c8s/api/session/v1alpha1"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/daemon"
)

// retryPause is the wait before a call the daemon could not complete is
// made again, under the same request id.
const retryPause = 250 * time.Millisecond

// daemonFlags say how the c8s daemon of a guest's host is reached.
type daemonFlags struct {
	address, ca, name, cert, key string
}

func (d *daemonFlags) register(f *pflag.FlagSet, orchestrator bool) {
	f.StringVar(&d.address, "daemon", "", "the c8s daemon of the guest's host, as host:port")
	f.StringVar(&d.ca, "daemon-ca", "", "CA certificate PEM the daemon's certificate chains to (default: the system's roots)")
	f.StringVar(&d.name, "daemon-name", "", "the name the daemon's certificate carries, when it is not --daemon's host")
	if orchestrator {
		f.StringVar(&d.cert, "daemon-cert", "", "an orchestrator's certificate PEM: the daemon takes claims, binds and destroys from no one else")
		f.StringVar(&d.key, "daemon-key", "", "the private key of --daemon-cert")
	}
}

// route is how the flags reach a TD, over what a binding kept. Nil is a
// guest reached by its address.
func (d *daemonFlags) route(kept *daemon.Route, td string) (*daemon.Route, error) {
	route := daemon.Route{}
	if kept != nil {
		route = *kept
	}
	if d.address != "" {
		// Another daemon is another certificate.
		if kept != nil && d.address != kept.Daemon {
			route.CA, route.ServerName = nil, ""
		}
		route.Daemon = d.address
	}
	if d.name != "" {
		route.ServerName = d.name
	}
	if d.ca != "" {
		ca, err := session.ReadBounded(d.ca, 1<<20)
		if err != nil {
			return nil, fmt.Errorf("--daemon-ca: %w", err)
		}
		route.CA = ca
	}
	if td != "" {
		route.TD = td
	}
	if route.Daemon == "" {
		return nil, nil
	}
	return &route, nil
}

// dial opens a client of the route's daemon, under the orchestrator's
// certificate when the flags name one.
func (d *daemonFlags) dial(route *daemon.Route) (*daemon.Client, error) {
	var cert *tls.Certificate
	if d.cert != "" || d.key != "" {
		pair, err := tls.LoadX509KeyPair(d.cert, d.key)
		if err != nil {
			return nil, fmt.Errorf("--daemon-cert and --daemon-key: %w", err)
		}
		cert = &pair
	}
	opts, err := route.Options(cert)
	if err != nil {
		return nil, fmt.Errorf("--daemon-ca: %w", err)
	}
	return daemon.Dial(opts)
}

// reach is where the flags and the binding say the guest is: its address, or
// a TD behind a daemon that carries the client's connections there. The name
// in the URL of a guest behind a daemon is only a name.
func (t *trust) reach() (url string, through session.ClientOption, err error) {
	var kept *daemon.Route
	if t.binding != "" {
		if kept, err = daemon.LoadRoute(t.binding); err != nil {
			return "", nil, fmt.Errorf("--binding: %w", err)
		}
	}
	route, err := t.daemon.route(kept, t.td)
	switch {
	case err != nil:
		return "", nil, err
	case t.url != "" && (t.daemon.address != "" || t.td != ""):
		return "", nil, errors.New("--url and --daemon are alternatives")
	case t.url != "":
		return t.url, nil, nil
	case route == nil:
		return "", nil, errors.New("--url is required, or --daemon and --td, or a --binding that 'c8s session start' wrote")
	case route.TD == "":
		return "", nil, errors.New("--daemon needs --td: the guest's TD there")
	}
	if t.through, err = t.daemon.dial(route); err != nil {
		return "", nil, err
	}
	return fmt.Sprintf("https://%s:%d", route.TD, session.AgentPort), session.Through(t.through.Dialer(route.TD)), nil
}

// startFlags are what 'c8s session start' needs: the daemon and its pool,
// what a guest of the pool must be, and whose the session is.
type startFlags struct {
	bindFlags
	pool string
	wait time.Duration
}

// startedSession is the machine-readable result of `c8s session start`.
type startedSession struct {
	Started      bool   `json:"started"`
	Error        string `json:"error,omitempty"`
	Tenant       string `json:"tenant,omitempty"`
	Session      string `json:"session,omitempty"`
	TD           string `json:"td,omitempty"`
	Host         string `json:"host,omitempty"`
	Phase        string `json:"phase,omitempty"`
	LaunchDigest string `json:"launch_digest,omitempty"`
	BindDigest   string `json:"bind_digest,omitempty"`
	Binding      string `json:"binding,omitempty"`
	// How long each step took, as this process saw it.
	ClaimMillis      int64 `json:"claim_ms"`
	ReadyCheckMillis int64 `json:"ready_check_ms"`
	BindMillis       int64 `json:"bind_ms"`
	AttestMillis     int64 `json:"attest_ms"`
}

func newStartCmd() *cobra.Command {
	var s startFlags
	var output string
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start a session on a guest from a daemon's pool",
		Long: `Claim a ready guest of --pool from the c8s daemon at --daemon. Check, from
the evidence the daemon relays, that the guest is of the pinned image and was
launched under the pool's launch key, and that nobody has bound it. Then sign
a bind for it with the owner's authority key, hand it over through the
daemon, and judge the guest's answer: evidence fresh for the bind's nonce.

The daemon is trusted for none of this. It relays documents and evidence, and
a daemon that cheats produces a session that does not start.

A fresh access key is generated, granted what 'c8s session bind' grants one,
and written with the documents to --out, beside the route to the guest
through its daemon. Pass that directory as --binding to 'verify', 'credential
put', 'exec' and 'destroy'.

Exit codes: 0 started and verified, 1 usage error, 2 verification failed
(before the bind: nothing was signed, and the claim is given back; after it:
do not use the session), 3 the daemon or the guest could not complete a step.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if output != "text" && output != "json" {
				return errors.New("-o must be text or json")
			}
			os.Exit(runStart(cmd.Context(), &s, output == "json", cmd.OutOrStdout(), cmd.ErrOrStderr()))
			return nil
		},
	}
	f := cmd.Flags()
	s.daemon.register(f, true)
	f.StringVar(&s.pool, "pool", "", "the pool to take a guest from")
	f.DurationVar(&s.wait, "wait", 30*time.Second, "how long to wait for a ready guest when the pool has none")
	f.StringVar(&s.manifest, "image-manifest", "", "manifest.json published with the session guest image")
	f.StringVar(&s.launchKey, "launch-key", "", "the pool's launch public key PEM, which its guests are launched under")
	f.StringVar(&s.authorityKey, "authority-key", "", "the owner's authority private key, which signs the bind")
	f.StringVar(&s.tenant, "tenant", "", "the tenant the session belongs to")
	f.StringVar(&s.session, "session", "", "session name, an RFC1123 label")
	f.StringVar(&s.out, "out", "", "binding directory to create (must not exist)")
	f.DurationVar(&s.ttl, "valid-for", session.DefaultBindTTL, "how long the bind may still be applied if this command does not get to deliver it")
	s.w.register(f, "the access key")
	s.collateralFlags(f)
	f.DurationVar(&s.timeout, "timeout", 3*time.Minute, "overall deadline")
	f.StringVarP(&output, "output", "o", "text", "text or json")
	for _, name := range []string{"daemon", "daemon-cert", "daemon-key", "pool", "image-manifest", "launch-key", "authority-key", "tenant", "session", "out"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

// again reports whether the daemon could not complete a call that the same
// request, sent again, may complete.
func again(err error) bool {
	switch status.Code(err) {
	case codes.Unavailable, codes.Aborted:
		return true
	}
	return false
}

// retried makes a call until the daemon answers it for good or ctx ends. The
// call carries one request id, so a repeat changes nothing twice.
func retried[T any](ctx context.Context, call func() (T, error)) (T, error) {
	for {
		out, err := call()
		if !again(err) {
			return out, err
		}
		select {
		case <-ctx.Done():
			return out, err
		case <-time.After(retryPause):
		}
	}
}

func runStart(ctx context.Context, s *startFlags, asJSON bool, stdout, stderr io.Writer) int {
	result := startedSession{}
	finish := func(code int, err error) int {
		if err != nil {
			result.Error = err.Error()
		}
		if asJSON {
			_ = json.NewEncoder(stdout).Encode(result)
		} else if err != nil {
			fmt.Fprintf(stderr, "NOT STARTED: %v\n", err)
		}
		return code
	}
	identity, err := runtimemeasure.LoadImageManifest(s.manifest)
	if err != nil {
		return finish(ExitUsage, fmt.Errorf("--image-manifest: %w", err))
	}
	launchKey, err := session.ReadBounded(s.launchKey, 8192)
	if err != nil {
		return finish(ExitUsage, fmt.Errorf("--launch-key: %w", err))
	}
	authority, err := certutil.LoadECPrivateKeyFile(s.authorityKey)
	if err != nil {
		return finish(ExitUsage, fmt.Errorf("--authority-key: %w", err))
	}
	authorityPub, err := session.PublicKeyPEM(&authority.PublicKey)
	if err != nil {
		return finish(ExitUsage, err)
	}
	policy, accessPEM, err := s.w.policy()
	if err != nil {
		return finish(ExitUsage, err)
	}
	if _, err := os.Stat(s.out); err == nil {
		return finish(ExitUsage, fmt.Errorf("--out %s already exists", s.out))
	}
	route, err := s.daemon.route(nil, "")
	if err != nil {
		return finish(ExitUsage, err)
	}
	host, err := s.daemon.dial(route)
	if err != nil {
		return finish(ExitUsage, err)
	}
	defer host.Close()
	claimID, err := daemon.NewRequestID()
	if err != nil {
		return finish(ExitUsage, err)
	}
	bindID, err := daemon.NewRequestID()
	if err != nil {
		return finish(ExitUsage, err)
	}
	engine := s.engine()
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	began := time.Now()
	claimed, err := retried(ctx, func() (*daemon.Claimed, error) {
		return host.Claim(ctx, claimID, s.pool, s.session, s.wait)
	})
	if err != nil {
		return finish(ExitUnavailable, fmt.Errorf("claim a guest of pool %s: %w", s.pool, err))
	}
	result.ClaimMillis, result.TD, result.Host = time.Since(began).Milliseconds(), claimed.TD, claimed.Host
	// A claim this command does not see through is given back: its guest has
	// taken nothing, and the pool has it again at once.
	release := func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if id, err := daemon.NewRequestID(); err == nil {
			_, _ = host.Destroy(ctx, id, s.session)
		}
	}

	began = time.Now()
	readyPolicy := session.Policy{Image: identity, LaunchKey: launchKey, Authority: authorityPub, AllowReady: true, RequireMachine: s.requireMachine}
	ready, err := session.VerifyReady(ctx, readyPolicy, engine, claimed.Evidence, time.Now())
	if err != nil {
		release()
		return finish(exitCode(err), fmt.Errorf("the guest the daemon offers is not what this session pins, and nothing was signed: %w", err))
	}
	result.ReadyCheckMillis = time.Since(began).Milliseconds()
	bind, err := session.NewBind(session.BindOptions{
		Authority: authority, InstanceKey: ready.InstanceKey,
		Tenant: s.tenant, Session: s.session, NotAfter: time.Now().Add(s.ttl), Policy: policy,
	})
	if err != nil {
		release()
		return finish(ExitUsage, err)
	}
	// Written before the bind is sent: if the answer is lost the bind may
	// still have taken effect, and this record is then the only way back to
	// the guest.
	if err := session.WriteBinding(s.out, launchKey, ready, bind, accessPEM); err != nil {
		release()
		return finish(ExitUsage, err)
	}
	route.TD = claimed.TD
	if err := daemon.WriteRoute(s.out, route); err != nil {
		release()
		return finish(ExitUsage, err)
	}
	result.Binding = s.out
	result.LaunchDigest, result.BindDigest = session.DocumentDigest(ready.Launch), session.DocumentDigest(bind.Raw)

	began = time.Now()
	answer, err := retried(ctx, func() (*session.Relayed, error) {
		return host.Bind(ctx, bindID, claimed.TD, bind)
	})
	if err != nil {
		return finish(ExitUnavailable, fmt.Errorf("the guest did not take the bind: %w", err))
	}
	result.BindMillis = time.Since(began).Milliseconds()

	// What the daemon says of the bind proves nothing. The guest's evidence
	// does, judged under exactly these documents for the key the bind names.
	began = time.Now()
	binding := session.Binding{LaunchKey: launchKey, Launch: ready.Launch, Bind: bind}
	bound := binding.Policy(identity)
	bound.RequireMachine = s.requireMachine
	att, verdict, err := judgeBound(ctx, s, host, claimed.TD, bound, engine, ready, bind, answer, accessPEM, stderr)
	if err != nil {
		return finish(exitCode(err), fmt.Errorf("the bind was sent, but the guest does not verify as bound by it: %w", err))
	}
	result.AttestMillis = time.Since(began).Milliseconds()
	// For the owner's next command, which then asks the guest for no quote.
	if verdict != nil {
		if err := session.WriteVerdict(s.out, verdict); err != nil {
			fmt.Fprintf(stderr, "the next command will attest the guest again: %v\n", err)
		}
	}
	result.Started, result.Tenant, result.Session, result.Phase = true, att.Tenant, att.Session, string(att.Phase)
	if !asJSON {
		fmt.Fprintf(stdout, "STARTED %s session\n  tenant        %s\n  session       %s\n  phase         %s\n  TD            %s on %s\n  launch doc    %s\n  bind          %s\n  events        %s\n  instance key  sha256:%s\n  binding       %s\n  timing        claim %d ms, ready check %d ms, bind %d ms, attest %d ms\n",
			att.Result.Platform, att.Tenant, att.Session, att.Phase, claimed.TD, claimed.Host, result.LaunchDigest, result.BindDigest,
			strings.Join(att.Events, " "), certutil.CertFingerprint(att.InstanceKey), s.out,
			result.ClaimMillis, result.ReadyCheckMillis, result.BindMillis, result.AttestMillis)
	}
	return finish(ExitOK, nil)
}

// judgeBound judges the guest's answer to the bind, and gives the verdict to
// keep on it. A guest whose answer carries no evidence, because its ration of
// quotes had none to give, is asked for it over a connection of its own.
func judgeBound(ctx context.Context, s *startFlags, host *daemon.Client, td string, bound session.Policy, engine session.Engine,
	ready *session.ReadyTD, bind *session.SignedBind, answer *session.Relayed, accessPEM []byte, stderr io.Writer,
) (*session.Attestation, *session.Verdict, error) {
	if len(answer.Evidence) > 0 {
		att, err := session.VerifyBound(ctx, bound, engine, ready.InstanceKey, bind, answer)
		if err != nil {
			return nil, nil, err
		}
		leaf, err := x509.ParseCertificate(answer.Certificate)
		if err != nil {
			leaf = nil
		}
		verdict, err := session.VerdictOn(bound, engine, att, leaf, time.Now())
		return att, verdict, err
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(accessPEM)
	if err != nil {
		return nil, nil, err
	}
	options := append(s.road(stderr), session.Through(host.Dialer(td)))
	client, err := session.NewClient(fmt.Sprintf("https://%s:%d", td, session.AgentPort), bound, engine, signer, options...)
	if err != nil {
		return nil, nil, err
	}
	defer client.Close()
	att, err := client.Attest(ctx)
	if err != nil {
		return nil, nil, err
	}
	verdict, _ := client.Verdict()
	return att, verdict, nil
}

func newDestroyCmd() *cobra.Command {
	var d daemonFlags
	var binding, name string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "destroy",
		Short: "End a session",
		Long: `Have the c8s daemon end the session's guest. The guest is asked nothing:
ending it needs no cooperation, and what it held is gone with it.

Exit codes: 0 the session is ended, 1 usage error, 3 the daemon could not be
reached or knows no such session.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			os.Exit(runDestroy(cmd.Context(), &d, binding, name, timeout, cmd.OutOrStdout(), cmd.ErrOrStderr()))
			return nil
		},
	}
	f := cmd.Flags()
	d.register(f, true)
	f.StringVar(&binding, "binding", "", "the session's binding directory, which names its daemon and the session")
	f.StringVar(&name, "session", "", "the session's name, when no --binding is at hand")
	f.DurationVar(&timeout, "timeout", time.Minute, "overall deadline")
	for _, flag := range []string{"daemon-cert", "daemon-key"} {
		_ = cmd.MarkFlagRequired(flag)
	}
	return cmd
}

func runDestroy(ctx context.Context, d *daemonFlags, binding, name string, timeout time.Duration, stdout, stderr io.Writer) int {
	var kept *daemon.Route
	if binding != "" {
		loaded, err := session.LoadBinding(binding)
		if err != nil {
			fmt.Fprintf(stderr, "--binding: %v\n", err)
			return ExitUsage
		}
		if name == "" {
			name = loaded.Bind.Doc.Session
		}
		if kept, err = daemon.LoadRoute(binding); err != nil {
			fmt.Fprintf(stderr, "--binding: %v\n", err)
			return ExitUsage
		}
	}
	route, err := d.route(kept, "")
	switch {
	case err != nil:
		fmt.Fprintln(stderr, err)
		return ExitUsage
	case route == nil:
		fmt.Fprintln(stderr, "--daemon is required, or a --binding that 'c8s session start' wrote")
		return ExitUsage
	case name == "":
		fmt.Fprintln(stderr, "--session or --binding is required")
		return ExitUsage
	}
	host, err := d.dial(route)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	defer host.Close()
	id, err := daemon.NewRequestID()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	gone, err := retried(ctx, func() (*sessionv1alpha1.Session, error) { return host.Destroy(ctx, id, name) })
	if err != nil {
		fmt.Fprintf(stderr, "NOT DESTROYED: %v\n", err)
		return ExitUnavailable
	}
	fmt.Fprintf(stdout, "DESTROYED session %s\n  TD            %s on %s\n", gone.GetName(), gone.GetTd(), gone.GetHost())
	return ExitOK
}
