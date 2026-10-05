package sessioncli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strconv"
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
	// command is the session's first command, which goes with its bind.
	command []string
	// sealed are the credentials this command holds and seals with the bind,
	// each as NAME[:MAXBYTES]=FILE.
	sealed []string
}

// heldCredentials reads the credentials a start seals with its bind. It
// returns what the bind declares of them and their values.
func (s *startFlags) heldCredentials() ([]session.Credential, map[string][]byte, error) {
	var declared []session.Credential
	held := map[string][]byte{}
	for _, spec := range s.sealed {
		decl, file, ok := strings.Cut(spec, "=")
		if !ok || file == "" {
			return nil, nil, fmt.Errorf("--sealed-credential %q must be NAME[:MAXBYTES]=FILE", spec)
		}
		name, limit, _ := strings.Cut(decl, ":")
		c := session.Credential{Name: name, Source: session.SourceBinder}
		if limit != "" {
			n, err := strconv.Atoi(limit)
			if err != nil || n <= 0 {
				return nil, nil, fmt.Errorf("--sealed-credential %q: size must be a positive byte count", spec)
			}
			c.MaxBytes = n
		}
		if !session.ValidCredentialName(name) {
			return nil, nil, fmt.Errorf("--sealed-credential %q: %q cannot name a credential", spec, name)
		}
		if _, twice := held[name]; twice {
			return nil, nil, fmt.Errorf("--sealed-credential names %s twice", name)
		}
		value, err := session.ReadBounded(file, int64(c.Limit()))
		if err != nil {
			return nil, nil, fmt.Errorf("--sealed-credential %s: %w", name, err)
		}
		held[name] = value
		declared = append(declared, c)
	}
	return declared, held, nil
}

// sealedCredentialsResult is what became of the credentials a start sealed
// with its bind.
type sealedCredentialsResult struct {
	// WithBind are those the guest had in place before its sandbox started,
	// and After those it was sent over the session's connection.
	WithBind []string `json:"with_bind,omitempty"`
	After    []string `json:"after,omitempty"`
}

// firstCommandResult is what became of a start's first command.
type firstCommandResult struct {
	ExitCode int `json:"exit_code"`
	// WithBind says the guest took the command with its bind, where
	// otherwise it was sent over the session's connection.
	WithBind bool   `json:"with_bind"`
	Stdout   []byte `json:"stdout,omitempty"`
	Stderr   []byte `json:"stderr,omitempty"`
	TimedOut bool   `json:"timed_out,omitempty"`
	Millis   int64  `json:"ms"`
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
	// Receipt says the guest answered the bind with a receipt that its quote
	// confirmed. Quote says where that quote came from: with the answer,
	// with the guest's evidence after it, or from an attestation this
	// command asked for.
	Receipt bool   `json:"receipt"`
	Quote   string `json:"quote,omitempty"`
	// FirstCommand is the result of the command the start was given, and
	// Credentials what became of the credentials it sealed with the bind.
	FirstCommand *firstCommandResult      `json:"first_command,omitempty"`
	Credentials  *sealedCredentialsResult `json:"credentials,omitempty"`
}

// Where the quote that a start judged came from.
const (
	quoteWithAnswer   = "answer"
	quoteWithEvidence = "evidence"
	quoteAskedFor     = "attestation"
)

func newStartCmd() *cobra.Command {
	var s startFlags
	var output string
	cmd := &cobra.Command{
		Use:   "start [-- <command> [args...]]",
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

A command after -- is the session's first, and goes with its bind: sealed to
a key the guest made for its one bind and erases before any of the session's
code runs, so the daemon carries it unread and the guest runs it as soon as
its sandbox does, with no round trip of its own. What it wrote is printed
once the session has verified, and its status is reported: it does not change
this command's. A guest that did not take the command with its bind is sent
it over the session's own connection, and runs it once either way.

A --sealed-credential goes with the bind the same way, in the same sealed
message, and the guest has it in place before its sandbox starts: the bind
declares it as one its binder holds. One the guest did not take with its bind
is released to it over the session's own connection.

Exit codes: 0 started and verified, 1 usage error, 2 verification failed
(before the bind: nothing was signed, and the claim is given back; after it:
do not use the session), 3 the daemon or the guest could not complete a step.`,
		Args:         cobra.ArbitraryArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if output != "text" && output != "json" {
				return errors.New("-o must be text or json")
			}
			if len(args) > 0 && cmd.ArgsLenAtDash() != 0 {
				return errors.New("the session's first command follows --")
			}
			s.command = args
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
	f.StringArrayVar(&s.sealed, "sealed-credential", nil, "credential NAME[:MAXBYTES]=FILE this command holds: read from FILE and sealed with the bind, so that the guest has it in place before its sandbox starts (repeatable)")
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
	declared, held, err := s.heldCredentials()
	if err != nil {
		return finish(ExitUsage, err)
	}
	if len(declared) > 0 {
		// One order, whatever order the flags came in.
		policy.Credentials = append(policy.Credentials, declared...)
		slices.SortFunc(policy.Credentials, func(a, b session.Credential) int { return strings.Compare(a.Name, b.Name) })
		for i := 1; i < len(policy.Credentials); i++ {
			if name := policy.Credentials[i].Name; name == policy.Credentials[i-1].Name {
				return finish(ExitUsage, fmt.Errorf("credential %s is declared by more than one flag", name))
			}
		}
	}
	keyService, err := s.w.pin()
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
	// What this command sends its guest goes on the vendor's documents as it
	// fetched them itself: those it can name are on their way meanwhile.
	session.Prefetch(engine)

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
	readyPolicy := session.Policy{
		Image: identity, LaunchKey: launchKey, Authority: authorityPub, AllowReady: true,
		AcceptTCBStatus: s.acceptedTCB(),
	}
	// What goes with the bind is sealed on this verdict, so it is then made
	// as one that lets a secret go: on the vendor's documents as this command
	// fetched them itself, where a verdict that only leads to a bind may rest
	// on those the guest's host handed over.
	verify := session.VerifyReady
	if len(s.command) > 0 || len(held) > 0 {
		verify = session.VerifyReadyToRelease
	}
	ready, err := verify(ctx, readyPolicy, engine, claimed.Evidence, time.Now())
	if err != nil {
		release()
		return finish(exitCode(err), fmt.Errorf("the guest the daemon offers is not what this session pins, and nothing was signed: %w", err))
	}
	result.ReadyCheckMillis = time.Since(began).Milliseconds()
	if err := servedBy(keyService, ready.Document.KeyService); err != nil {
		release()
		return finish(ExitRefused, fmt.Errorf("nothing was signed: %w", err))
	}
	bind, err := session.NewBind(session.BindOptions{
		Authority: authority, InstanceKey: ready.InstanceKey,
		Tenant: s.tenant, Session: s.session, NotAfter: time.Now().Add(s.ttl), Policy: policy, KeyService: keyService,
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

	// The first command and the credentials this command holds are sealed
	// to the key the check of the guest's evidence just bound, and go with
	// the bind.
	var message *session.SealedMessage
	var sealed []byte
	if len(s.command) > 0 || len(held) > 0 {
		signer, err := operatorauth.NewSignerFromKeyPEM(accessPEM)
		if err != nil {
			release()
			return finish(ExitUsage, err)
		}
		parts := session.SealedParts{Credentials: held}
		if len(s.command) > 0 {
			parts.Command = &session.ExecRequest{Argv: s.command}
		}
		if message, err = session.SealWithBind(ready, bind, signer, parts); err != nil {
			release()
			return finish(ExitUsage, fmt.Errorf("what goes with the bind was not sealed: %w", err))
		}
		sealed = message.Sealed
	}

	began = time.Now()
	call, err := retried(ctx, func() (*daemon.BindCall, error) {
		return host.BindWith(ctx, bindID, claimed.TD, bind, sealed)
	})
	if err != nil {
		return finish(ExitUnavailable, fmt.Errorf("the guest did not take the bind: %w", err))
	}
	defer call.Close()
	answer := call.Answer
	result.BindMillis = time.Since(began).Milliseconds()

	// What the daemon says of the bind proves nothing. The guest's evidence
	// does, judged under exactly these documents for the key the bind names.
	began = time.Now()
	binding := session.Binding{LaunchKey: launchKey, Launch: ready.Launch, Bind: bind}
	bound := binding.Policy(identity)
	bound.AcceptTCBStatus = s.acceptedTCB()
	judged, err := judgeBound(ctx, s, host, claimed.TD, bound, engine, ready, bind, answer, accessPEM, stderr)
	if err != nil {
		// The guest took the bind and cannot be held to it: it is of no use
		// to anyone, and a check that could not be made counts as failed.
		release()
		return finish(exitCode(err), fmt.Errorf("the bind was sent, but the guest does not verify as bound by it, and its session was ended: %w", err))
	}
	att, verdict, quote := judged.att, judged.verdict, judged.quote
	result.AttestMillis = time.Since(began).Milliseconds()
	// For the owner's next command, which then asks the guest for no quote.
	if verdict != nil {
		if err := session.WriteVerdict(s.out, verdict); err != nil {
			fmt.Fprintf(stderr, "the next command will attest the guest again: %v\n", err)
		}
	}
	// The guest's signed word that it took the bind, which its quote
	// confirmed: 'c8s session verify' holds it to a fresh quote.
	result.Quote = quote
	if answer.Receipt != nil {
		result.Receipt = true
		if err := session.WriteReceipt(s.out, answer.Receipt); err != nil {
			fmt.Fprintf(stderr, "the guest's receipt for the bind was not kept: %v\n", err)
		}
	}
	// The quote is the guest's, and agrees with its receipt, but where its
	// platform stands could not be judged for want of one of Intel's
	// documents. The session runs, and nothing was kept on it: the owner's
	// next command judges the guest itself before it sends anything.
	// The session runs, so what went with its bind has an answer, whatever
	// became of the verdict: it is read before anything else is said.
	var ran *session.ExecResponse
	var firstErr error
	if message != nil {
		began = time.Now()
		var outcome *sealedOutcome
		outcome, firstErr = sealedResult(ctx, s, host, call, message, held, claimed.TD, bound, engine, accessPEM, verdict, stderr)
		if len(held) > 0 {
			result.Credentials = &sealedCredentialsResult{WithBind: outcome.held, After: outcome.after}
		}
		if ran = outcome.ran; ran != nil {
			result.FirstCommand = &firstCommandResult{
				ExitCode: ran.ExitCode, WithBind: outcome.withBind, Stdout: ran.Stdout, Stderr: ran.Stderr, TimedOut: ran.TimedOut,
				Millis: time.Since(began).Milliseconds(),
			}
		}
	}
	// showFirst prints what became of the credentials that went with the
	// bind, what the first command wrote, and how it went.
	showFirst := func() {
		if c := result.Credentials; c != nil && !asJSON {
			if len(c.WithBind) > 0 {
				fmt.Fprintf(stdout, "  credentials   %s in place before the sandbox started\n", strings.Join(c.WithBind, ", "))
			}
			if len(c.After) > 0 {
				fmt.Fprintf(stdout, "  credentials   %s released over the session's connection\n", strings.Join(c.After, ", "))
			}
		}
		if ran == nil || asJSON {
			return
		}
		how := "sent with the bind"
		if !result.FirstCommand.WithBind {
			how = "sent over the session's connection"
		}
		fmt.Fprintf(stdout, "  first command exit %d, %s\n", ran.ExitCode, how)
		_, _ = stdout.Write(ran.Stdout)
		_, _ = stderr.Write(ran.Stderr)
		if ran.StdoutTruncated || ran.StderrTruncated {
			fmt.Fprintf(stderr, "c8s: output was truncated at %d bytes per stream\n", session.MaxExecOutput)
		}
		if ran.TimedOut {
			fmt.Fprintln(stderr, "c8s: the command was killed at its timeout")
		}
	}
	if judged.pending != nil {
		showFirst()
		return finish(exitCode(judged.pending), fmt.Errorf("the session runs and its guest's quote is held to the bind, but the quote could not be judged, so no verdict was kept: %w", judged.pending))
	}
	result.Started, result.Tenant, result.Session, result.Phase = true, att.Tenant, att.Session, string(att.Phase)
	if firstErr != nil {
		return finish(exitCode(firstErr), fmt.Errorf("the session started, and what went with its bind was not all done: %w", firstErr))
	}
	if !asJSON {
		fmt.Fprintf(stdout, "STARTED %s session\n  tenant        %s\n  session       %s\n  phase         %s\n  TD            %s on %s\n  launch doc    %s\n  bind          %s\n  events        %s\n  instance key  sha256:%s\n  binding       %s\n  timing        claim %d ms, ready check %d ms, bind %d ms, attest %d ms\n",
			att.Result.Platform, att.Tenant, att.Session, att.Phase, claimed.TD, claimed.Host, result.LaunchDigest, result.BindDigest,
			strings.Join(att.Events, " "), certutil.CertFingerprint(att.InstanceKey), s.out,
			result.ClaimMillis, result.ReadyCheckMillis, result.BindMillis, result.AttestMillis)
		if result.Receipt {
			fmt.Fprintf(stdout, "  receipt       the guest's receipt for the bind, confirmed by its quote\n")
		}
		showFirst()
	}
	return finish(ExitOK, nil)
}

// owed is what a start still owes its guest once it has the guest's sealed
// answer to message, or has none (said is nil): the credentials to release
// over the session's connection, and whether the command goes there too.
// held are the credentials the answer says the guest holds. It goes by the
// guest's sealed answer alone: what the daemon said became of the message is
// not among what it is given.
func owed(message *session.SealedMessage, credentials map[string][]byte, said *session.SealedAnswer) (held, again []string, resend bool) {
	for _, name := range slices.Sorted(maps.Keys(credentials)) {
		if said != nil && said.Credentials[name] == session.SealedHeld {
			held = append(held, name)
			continue
		}
		again = append(again, name)
	}
	return held, again, message.Command != nil && said == nil
}

// sealedOutcome is what became of what a start sealed with its bind.
type sealedOutcome struct {
	// ran is the first command's result, nil for a start with no command or
	// one whose command gave none. withBind says the guest took the command
	// with its bind.
	ran      *session.ExecResponse
	withBind bool
	// held are the credentials the guest had in place before its sandbox
	// started, and after those released to it over the session's connection.
	held, after []string
}

// sealedResult is what became of what a start sealed with its bind. A guest
// that took the message answers on the call that carried it, sealed to that
// message, and only an answer that opens says the guest acted on it: the
// daemon's word on the message counts for nothing. What no such answer says
// is done goes over the session's own connection: each credential the guest
// does not hold, which it takes once, and then the command, which the guest
// runs once per id, so it answers with the first run's result if there was
// one.
func sealedResult(ctx context.Context, s *startFlags, host *daemon.Client, call *daemon.BindCall, message *session.SealedMessage,
	credentials map[string][]byte, td string, bound session.Policy, engine session.Engine, accessPEM []byte, verdict *session.Verdict,
	stderr io.Writer,
) (*sealedOutcome, error) {
	out := &sealedOutcome{}
	var said *session.SealedAnswer
	if call.SealedStatus == session.SealedTaken {
		if answer, status, err := call.SealedAnswer(); err == nil && status == session.SealedTaken {
			if said, err = message.Open(answer); err != nil {
				fmt.Fprintf(stderr, "the sealed answer is not the guest's, so what was sealed goes over the session's connection: %v\n", err)
			}
		}
	}
	var again []string
	var resend bool
	out.held, again, resend = owed(message, credentials, said)
	if len(again) > 0 || resend {
		signer, err := operatorauth.NewSignerFromKeyPEM(accessPEM)
		if err != nil {
			return out, err
		}
		options := append(s.road(stderr), session.Through(host.Dialer(td)))
		if verdict != nil {
			options = append(options, session.Kept(verdict))
		}
		client, err := session.NewClient(fmt.Sprintf("https://%s:%d", td, session.AgentPort), bound, engine, signer, options...)
		if err != nil {
			return out, err
		}
		defer client.Close()
		for _, name := range again {
			if _, err := client.PutCredential(ctx, name, credentials[name]); err != nil {
				return out, fmt.Errorf("credential %s: %w", name, err)
			}
			out.after = append(out.after, name)
		}
		if resend {
			ran, err := client.Exec(ctx, *message.Command)
			if err != nil {
				return out, fmt.Errorf("the first command: %w", err)
			}
			out.ran = ran
		}
	}
	if message.Command != nil && said != nil {
		// What the guest's own answer says of the command is its last word.
		if said.Command == nil {
			return out, fmt.Errorf("the guest opened the first command and did not run it: %s", said.CommandError)
		}
		out.ran, out.withBind = said.Command, true
	}
	return out, nil
}

// quoteWait is how long this command waits for the quote its guest takes
// over the bind's nonce before it asks the guest for an attestation itself.
const quoteWait = 5 * time.Second

// judgedBind is what a start made of its guest's answer to the bind.
type judgedBind struct {
	att     *session.Attestation
	verdict *session.Verdict
	// quote says where the quote came from: see quoteWithAnswer.
	quote string
	// pending is set when the quote is the guest's and agrees with its
	// receipt, and could not be judged for want of one of the vendor's
	// documents: it is why. The session then runs with no verdict kept.
	pending error
}

// judgeBound judges the guest's answer to the bind, and gives the verdict to
// keep on it. This command keeps a verdict for the owner's next one, and a
// verdict is made from a quote, so it waits for the quote before it says the
// session started: the one over the bind's nonce, which comes with the answer
// or with the guest's evidence a moment later. A receipt in the answer is
// verified first, and the quote is held to it. A guest that gives no quote
// for the bind's nonce, because its quoting service failed it, is asked for
// an attestation over a connection of its own.
//
// An error is a guest that cannot be held to its bind, and its caller ends
// the session: a receipt or a quote that is refused, a quote that disagrees
// with its receipt, and no quote at all. A quote that passes everything that
// needs none of the vendor's documents, and cannot be judged for want of
// one, leaves the session running: that comes back as pending.
func judgeBound(ctx context.Context, s *startFlags, host *daemon.Client, td string, bound session.Policy, engine session.Engine,
	ready *session.ReadyTD, bind *session.SignedBind, answer *session.Relayed, accessPEM []byte, stderr io.Writer,
) (*judgedBind, error) {
	var receipt *session.BindReceipt
	judged := &judgedBind{quote: quoteWithAnswer}
	if answer.Receipt != nil {
		var err error
		if receipt, err = session.VerifyBoundReceipt(bound, ready, bind, answer); err != nil {
			return nil, err
		}
		if len(answer.Evidence) == 0 {
			// Until the quote is there, the guest says it gave up on it, or
			// a few seconds have passed.
			waiting, cancel := context.WithTimeout(ctx, quoteWait)
			quoted, err := host.BoundEvidence(waiting, td)
			cancel()
			if err == nil {
				answer, judged.quote = quoted, quoteWithEvidence
			}
		}
	}
	confirm := func(att *session.Attestation) error {
		if receipt == nil {
			return nil
		}
		return receipt.Confirmed(att)
	}
	if len(answer.Evidence) > 0 {
		att, err := session.VerifyBound(ctx, bound, engine, ready.InstanceKey, bind, answer)
		if err != nil {
			if exitCode(err) == ExitRefused {
				return nil, err
			}
			// No verdict for want of a document. What needs none still
			// decides whether the session goes on.
			held, holdErr := session.HoldBound(ctx, bound, engine, ready.InstanceKey, bind, answer)
			if holdErr != nil {
				return nil, fmt.Errorf("the quote could not be judged (%w), and does not hold without the vendor's documents: %w", err, holdErr)
			}
			if err := confirm(held); err != nil {
				return nil, err
			}
			judged.att, judged.pending = held, err
			return judged, nil
		}
		if err := confirm(att); err != nil {
			return nil, err
		}
		leaf, err := x509.ParseCertificate(answer.Certificate)
		if err != nil {
			leaf = nil
		}
		judged.att = att
		judged.verdict, err = session.VerdictOn(bound, engine, att, leaf, time.Now())
		return judged, err
	}

	// No quote over the bind's nonce: this command asks for one over a nonce
	// of its own, on a connection that ends in the guest.
	judged.quote = quoteAskedFor
	signer, err := operatorauth.NewSignerFromKeyPEM(accessPEM)
	if err != nil {
		return nil, err
	}
	options := append(s.road(stderr), session.Through(host.Dialer(td)))
	client, err := session.NewClient(fmt.Sprintf("https://%s:%d", td, session.AgentPort), bound, engine, signer, options...)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	evidence, err := client.FetchEvidence(ctx)
	if err != nil {
		return nil, fmt.Errorf("the guest gave no quote over its bind's nonce, and none when asked: %w", err)
	}
	att, err := client.Judge(ctx, evidence)
	if err != nil {
		if exitCode(err) == ExitRefused {
			return nil, err
		}
		held, holdErr := evidence.Hold(ctx, bound, engine)
		if holdErr != nil {
			return nil, fmt.Errorf("the quote could not be judged (%w), and does not hold without the vendor's documents: %w", err, holdErr)
		}
		if err := confirm(held); err != nil {
			return nil, err
		}
		judged.att, judged.pending = held, err
		return judged, nil
	}
	if err := confirm(att); err != nil {
		return nil, err
	}
	judged.att = att
	judged.verdict, _ = client.Verdict()
	return judged, nil
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
