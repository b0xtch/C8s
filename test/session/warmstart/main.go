// Command warmstart times a session's warm activation as an orchestrator
// sees it: one process that holds its connection to the session daemon
// starts sessions from a pool of ready TDs and runs each one's first command.
//
//	warmstart --daemon 127.0.0.1:7443 --daemon-ca ca.pem --daemon-cert o.pem --daemon-key o.key \
//	    --pool agents --image-manifest manifest.json --launch-key pubkey --authority-key authority.key \
//	    --sandbox-image name@sha256:... --rounds 20 --before-round ./wait-until-the-pool-is-full
//
// A round is a claim, the check of the unbound guest, a signed bind that
// carries the session's first command sealed for the guest, the check of the
// guest's receipt for it, the command's answer, and more commands over a
// connection that ends in the guest, which is made and held to the guest's
// key while the first command runs. The quote the guest takes over the
// bind's nonce is judged and held to the receipt beside the first command,
// and a guest whose quote disagrees is destroyed. With
// --command-with-bind=false the first command is sent over that connection
// once the receipt is checked, and with --quote-first once the quote is
// judged, as an owner does who sends nothing on a receipt.
// Each round prints one JSON record on standard output, with times in
// microseconds on this process's monotonic clock. The first round finds the
// engine's documents unread and its connections unmade: a reader who wants
// the steady state leaves it out.
//
// It is a measuring tool for a host that runs a session daemon
// (test/session/hardware.sh shows how one is set up). It verifies everything
// an owner's tool verifies, and is no product surface.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/daemon"
)

type options struct {
	daemon, ca, cert, key              string
	pool, manifest, launchKey          string
	authorityKey, tenant, prefix       string
	sandboxImage, keyService, stored   string
	acceptTCB, collateralCache, before string
	rounds, commands                   int
	wait, timeout                      time.Duration
	keep, attest, quoteFirst           bool
	prejudge, preconnect, withBind     bool
}

// record is one round. Every time is in microseconds.
type record struct {
	Kind    string `json:"kind"`
	Round   int    `json:"round"`
	Session string `json:"session"`
	TD      string `json:"td"`
	// Claim to Judge are the steps of a start, in order. Seal is the first
	// command sealed for the guest, when it goes with the bind. Bind is the
	// call that carries the bind to the guest and its answer back: the guest
	// measures the bind, takes what its key service releases, admits its
	// sandbox and signs its receipt. Judge is what this side checks before it
	// takes the first command's answer, or sends the command: the receipt, or
	// with --quote-first the quote.
	Claim      int64 `json:"claim_us"`
	ReadyCheck int64 `json:"ready_check_us"`
	Sign       int64 `json:"sign_us"`
	Seal       int64 `json:"seal_us,omitempty"`
	Bind       int64 `json:"bind_us"`
	Judge      int64 `json:"judge_us"`
	// Start is those together, as their caller waited for them.
	Start int64 `json:"start_us"`
	// FirstExec is what the session's first command took after the start:
	// the wait for its sealed answer when it went with the bind, and
	// otherwise a connection to the guest, held to the key the start
	// verified, and the command.
	FirstExec int64 `json:"first_exec_us"`
	// FirstCommand is from the claim to the first command's answer.
	FirstCommand int64 `json:"first_cmd_us"`
	// WithBind says the guest took the first command with its bind. OnReceipt
	// says the command's answer was taken, or the command sent, on the
	// guest's receipt, and ReachedAhead that the first command sent over a
	// connection found that connection made already. QuoteInAnswer says the
	// quote came with the bind's answer. Quote is from the bind's answer
	// until the quote was there, judged and held to the receipt, and
	// Confirmed the same from the claim.
	WithBind      bool  `json:"with_bind"`
	OnReceipt     bool  `json:"on_receipt"`
	ReachedAhead  bool  `json:"reached_ahead"`
	QuoteInAnswer bool  `json:"quote_in_answer"`
	Quote         int64 `json:"quote_us"`
	Confirmed     int64 `json:"confirmed_us"`
	// Exec are the commands after the first, on the kept connection.
	Exec []int64 `json:"exec_us,omitempty"`
	// Attest is one more attestation, asked for after the commands: a quote
	// the guest takes for a fresh nonce, and this side's judgment of it.
	Attest  int64 `json:"attest_us,omitempty"`
	Destroy int64 `json:"destroy_us,omitempty"`
}

func main() {
	var o options
	flag.StringVar(&o.daemon, "daemon", "", "the session daemon, as host:port")
	flag.StringVar(&o.ca, "daemon-ca", "", "PEM file of the authority that signed the daemon's certificate")
	flag.StringVar(&o.cert, "daemon-cert", "", "an orchestrator's certificate, PEM")
	flag.StringVar(&o.key, "daemon-key", "", "the orchestrator's private key, PEM")
	flag.StringVar(&o.pool, "pool", "", "the pool to start sessions from")
	flag.StringVar(&o.manifest, "image-manifest", "", "manifest.json published with the session guest image")
	flag.StringVar(&o.launchKey, "launch-key", "", "the pool's public launch key, PEM")
	flag.StringVar(&o.authorityKey, "authority-key", "", "the tenant's authority private key, which signs each bind")
	flag.StringVar(&o.tenant, "tenant", "acme", "the tenant")
	flag.StringVar(&o.prefix, "session-prefix", "warm", "each session is named <prefix>-<round>")
	flag.StringVar(&o.sandboxImage, "sandbox-image", "", "OCI image each session runs, as name@sha256:<digest>")
	flag.StringVar(&o.keyService, "key-service", "", "pin of the key service the sessions trust")
	flag.StringVar(&o.stored, "stored-credential", "", "a credential each guest takes from the key service at its bind (needs --key-service); the first command then reads it")
	flag.StringVar(&o.acceptTCB, "accept-tcb-status", "", "Intel TCB statuses, besides UpToDate, that the guests' platform may have, comma-separated")
	flag.StringVar(&o.collateralCache, "collateral-cache", "", "directory that keeps Intel's collateral between runs")
	flag.StringVar(&o.before, "before-round", "", "a program run before each round, with the round's number: it returns once the host is as a round should find it")
	flag.IntVar(&o.rounds, "rounds", 1, "how many sessions to start")
	flag.IntVar(&o.commands, "commands", 3, "commands each session runs after its first")
	flag.DurationVar(&o.wait, "wait", 2*time.Minute, "how long a claim waits for a ready TD")
	flag.DurationVar(&o.timeout, "timeout", 5*time.Minute, "deadline of one round")
	flag.BoolVar(&o.keep, "keep", false, "leave each session's TD running")
	flag.BoolVar(&o.attest, "attest", false, "after the commands, ask each guest for one more attestation and time it")
	flag.BoolVar(&o.quoteFirst, "quote-first", false, "judge the quote over the bind's nonce before the first command is sent")
	flag.BoolVar(&o.prejudge, "prejudge", true, "judge the guest's serving certificate while the guest takes its bind, so that the first command's connection does not wait for it")
	flag.BoolVar(&o.preconnect, "preconnect", true, "with --prejudge, also make the connection the session's commands take ahead of the first that needs it")
	flag.BoolVar(&o.withBind, "command-with-bind", true, "send the first command with the bind, sealed to the guest's one-time key (not with --quote-first)")
	flag.Parse()
	if err := run(&o); err != nil {
		fmt.Fprintln(os.Stderr, "warmstart:", err)
		os.Exit(1)
	}
}

func run(o *options) error {
	for name, value := range map[string]string{
		"--daemon": o.daemon, "--daemon-ca": o.ca, "--daemon-cert": o.cert, "--daemon-key": o.key, "--pool": o.pool,
		"--image-manifest": o.manifest, "--launch-key": o.launchKey, "--authority-key": o.authorityKey,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if o.stored != "" && o.keyService == "" {
		return errors.New("--stored-credential needs --key-service")
	}
	identity, err := runtimemeasure.LoadImageManifest(o.manifest)
	if err != nil {
		return fmt.Errorf("--image-manifest: %w", err)
	}
	launchKey, err := os.ReadFile(o.launchKey)
	if err != nil {
		return err
	}
	authority, err := certutil.LoadECPrivateKeyFile(o.authorityKey)
	if err != nil {
		return fmt.Errorf("--authority-key: %w", err)
	}
	authorityPub, err := session.PublicKeyPEM(&authority.PublicKey)
	if err != nil {
		return err
	}
	var pin *session.KeyService
	if o.keyService != "" {
		if pin, err = session.LoadKeyServicePin(o.keyService); err != nil {
			return fmt.Errorf("--key-service: %w", err)
		}
	}
	var accepted []string
	if o.acceptTCB != "" {
		accepted = strings.Split(o.acceptTCB, ",")
	}
	if err := session.ValidateTCBStatuses(accepted); err != nil {
		return fmt.Errorf("--accept-tcb-status: %w", err)
	}

	ca, err := os.ReadFile(o.ca)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return fmt.Errorf("--daemon-ca %s holds no certificate", o.ca)
	}
	pair, err := tls.LoadX509KeyPair(o.cert, o.key)
	if err != nil {
		return fmt.Errorf("--daemon-cert and --daemon-key: %w", err)
	}
	host, err := daemon.Dial(daemon.Options{Address: o.daemon, RootCAs: roots, Certificate: &pair})
	if err != nil {
		return err
	}
	defer host.Close()
	connecting, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = host.Connect(connecting)
	cancel()
	if err != nil {
		return err
	}

	engine := session.NewEngine(session.EngineOptions{CollateralCacheDir: o.collateralCache})
	out := json.NewEncoder(os.Stdout)
	for round := range o.rounds {
		if o.before != "" {
			hook := exec.Command(o.before, strconv.Itoa(round))
			hook.Stdout, hook.Stderr = os.Stderr, os.Stderr
			if err := hook.Run(); err != nil {
				return fmt.Errorf("--before-round, round %d: %w", round, err)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
		rec, err := one(ctx, o, round, host, engine, identity, launchKey, authority, authorityPub, pin, accepted)
		cancel()
		if err != nil {
			return fmt.Errorf("round %d: %w", round, err)
		}
		if err := out.Encode(rec); err != nil {
			return err
		}
	}
	return nil
}

func micros(since time.Time) int64 { return time.Since(since).Microseconds() }

// one starts one session and runs its commands.
func one(ctx context.Context, o *options, round int, host *daemon.Client, engine session.Engine, identity runtimemeasure.ImageIdentity,
	launchKey []byte, authority *ecdsa.PrivateKey, authorityPub []byte, pin *session.KeyService, accepted []string,
) (*record, error) {
	rec := &record{Kind: "session", Round: round, Session: fmt.Sprintf("%s-%d", o.prefix, round)}

	// What an orchestrator has before a session is asked of it: a key for
	// the session, and the policy its bind will carry.
	access, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	accessPEM, err := certutil.MarshalECKeyPEM(access)
	if err != nil {
		return nil, err
	}
	accessPub, err := session.PublicKeyPEM(&access.PublicKey)
	if err != nil {
		return nil, err
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(accessPEM)
	if err != nil {
		return nil, err
	}
	policy := session.BindPolicy{Access: session.Access{Exec: []string{string(accessPub)}, Credentials: []string{string(accessPub)}}}
	if o.sandboxImage != "" {
		policy.Sandbox = &session.Sandbox{Image: o.sandboxImage}
	}
	argv := []string{"true"}
	if o.stored != "" {
		policy.Credentials = []session.Credential{{Name: o.stored, Source: session.SourceKeyService, MaxBytes: 256}}
		argv = []string{"sh", "-c", `cat "$C8S_CREDENTIALS_DIR/` + o.stored + `"`}
	}
	claimID, err := daemon.NewRequestID()
	if err != nil {
		return nil, err
	}
	bindID, err := daemon.NewRequestID()
	if err != nil {
		return nil, err
	}

	began := time.Now()
	step := began
	claimed, err := host.Claim(ctx, claimID, o.pool, rec.Session, o.wait)
	if err != nil {
		return nil, fmt.Errorf("claim: %w", err)
	}
	rec.TD, rec.Claim = claimed.TD, micros(step)
	ended := false
	destroy := func() {
		if ended {
			return
		}
		ended = true
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		id, err := daemon.NewRequestID()
		if err != nil {
			return
		}
		at := time.Now()
		if _, err := host.Destroy(ctx, id, rec.Session); err != nil {
			fmt.Fprintf(os.Stderr, "warmstart: destroy %s: %v\n", rec.Session, err)
			return
		}
		rec.Destroy = micros(at)
	}
	defer func() {
		if !o.keep {
			destroy()
		}
	}()

	step = time.Now()
	readyPolicy := session.Policy{Image: identity, LaunchKey: launchKey, Authority: authorityPub, AllowReady: true, AcceptTCBStatus: accepted}
	ready, err := session.VerifyReady(ctx, readyPolicy, engine, claimed.Evidence, time.Now())
	if err != nil {
		return nil, fmt.Errorf("the guest the daemon offers: %w", err)
	}
	if pin != nil && !pin.Equal(ready.Document.KeyService) {
		return nil, errors.New("the pool's guests open their sessions with another key service than --key-service pins")
	}
	rec.ReadyCheck = micros(step)

	step = time.Now()
	bind, err := session.NewBind(session.BindOptions{
		Authority: authority, InstanceKey: ready.InstanceKey, Tenant: o.tenant, Session: rec.Session, Policy: policy, KeyService: pin,
	})
	if err != nil {
		return nil, err
	}
	rec.Sign = micros(step)

	// The first command goes with the bind, sealed to the key the check of
	// the guest's evidence just bound: an owner who waits for the quote
	// sends nothing ahead of it.
	var first *session.FirstCommand
	if o.withBind && !o.quoteFirst {
		step = time.Now()
		if first, err = session.SealFirstCommand(ready, bind, signer, session.ExecRequest{Argv: argv}); err != nil {
			return nil, fmt.Errorf("seal the first command: %w", err)
		}
		rec.Seal = micros(step)
	}

	binding := session.Binding{LaunchKey: launchKey, Launch: ready.Launch, Bind: bind}
	bound := binding.Policy(identity)
	bound.AcceptTCBStatus = accepted
	// While the guest takes its bind: the client the session's commands go
	// through and its judgment of the certificate the guest serves under.
	// Its connection to the guest is made then too when the first command
	// needs it, and tried until the daemon carries one, which it does once
	// it has the TD's bind. A first command that goes with the bind needs
	// none, so the connection is made once the guest has answered: a bind
	// ends the connections that reached its guest before it.
	var ahead *session.Client
	var reached chan bool
	bindAnswered := make(chan struct{})
	if o.prejudge && !o.quoteFirst {
		if ahead, err = session.NewClient(fmt.Sprintf("https://%s:%d", claimed.TD, session.AgentPort), bound, engine, signer,
			session.Through(host.Dialer(claimed.TD)), session.Receipted(ready.InstanceKey)); err != nil {
			return nil, err
		}
		defer ahead.Close()
		if leaf, err := x509.ParseCertificate(claimed.Evidence.Certificate); err == nil {
			reached = make(chan bool, 1)
			go func() {
				if err := ahead.Prejudge(ctx, leaf); err != nil {
					fmt.Fprintf(os.Stderr, "warmstart: round %d: the certificate was not judged ahead: %v\n", round, err)
					reached <- false
					return
				}
				if first != nil {
					<-bindAnswered
					reached <- o.preconnect && ahead.Reach(ctx) == nil
					return
				}
				for o.preconnect {
					if ahead.Reach(ctx) == nil {
						reached <- true
						return
					}
					select {
					case <-bindAnswered:
						// The first command makes its own connection.
						reached <- false
						return
					case <-time.After(200 * time.Microsecond):
					}
				}
				reached <- false
			}()
		}
	}

	step = time.Now()
	var sealed []byte
	if first != nil {
		sealed = first.Sealed
	}
	call, err := host.BindWith(ctx, bindID, claimed.TD, bind, sealed)
	close(bindAnswered)
	if err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}
	defer call.Close()
	answer := call.Answer
	rec.Bind = micros(step)

	answered := time.Now()
	step = answered
	var receipt *session.BindReceipt
	if answer.Receipt != nil {
		if receipt, err = session.VerifyBoundReceipt(bound, ready, bind, answer); err != nil {
			return nil, fmt.Errorf("the guest's receipt for the bind: %w", err)
		}
	}
	rec.QuoteInAnswer = len(answer.Evidence) > 0
	rec.OnReceipt = receipt != nil && !o.quoteFirst

	// quoted judges the quote the guest took over the bind's nonce, which is
	// in the answer or comes with the guest's evidence, and holds it to the
	// receipt. The verdict an owner keeps on its guest is made from it.
	type judgment struct {
		att  *session.Attestation
		leaf *x509.Certificate
		kept *session.Verdict
		err  error
	}
	quoted := func() (j judgment) {
		defer func() { rec.Quote, rec.Confirmed = micros(answered), micros(began) }()
		relayed := answer
		if len(relayed.Evidence) == 0 {
			if relayed, j.err = host.BoundEvidence(ctx, claimed.TD); j.err != nil {
				j.err = fmt.Errorf("the quote over the bind's nonce: %w", j.err)
				return j
			}
		}
		if j.att, j.err = session.VerifyBound(ctx, bound, engine, ready.InstanceKey, bind, relayed); j.err != nil {
			j.err = fmt.Errorf("the bound guest: %w", j.err)
			return j
		}
		if receipt != nil {
			if j.err = receipt.Confirmed(j.att); j.err != nil {
				return j
			}
		}
		if j.leaf, j.err = x509.ParseCertificate(relayed.Certificate); j.err != nil {
			j.err = fmt.Errorf("the bound guest's certificate: %w", j.err)
			return j
		}
		j.kept, j.err = session.VerdictOn(bound, engine, j.att, j.leaf, time.Now())
		return j
	}

	var pinned session.ClientOption
	confirmed := make(chan judgment, 1)
	if rec.OnReceipt {
		pinned = session.Receipted(ready.InstanceKey)
		go func() { confirmed <- quoted() }()
		if o.prejudge {
			pinned = nil
		}
	} else {
		first := quoted()
		if first.err != nil {
			return nil, first.err
		}
		pinned = session.Kept(first.kept)
		confirmed <- first
	}
	rec.Judge, rec.Start = micros(step), micros(began)

	step = time.Now()
	// The answer of a command the guest took with its bind follows the
	// receipt on the same call, sealed to this side.
	request := session.ExecRequest{Argv: argv}
	if first != nil {
		request = first.Request
		if receipt == nil {
			return nil, errors.New("the guest gave no receipt for a bind that carried a command")
		}
		answer, state, err := call.Result()
		if err != nil {
			return nil, fmt.Errorf("the first command's answer: %w", err)
		}
		if state == session.CommandTaken {
			result, err := first.Open(answer)
			if err != nil {
				return nil, fmt.Errorf("the first command's answer: %w", err)
			}
			if result.ExitCode != 0 {
				return nil, fmt.Errorf("the first command exited %d: %s", result.ExitCode, result.Stderr)
			}
			rec.WithBind = true
		} else {
			fmt.Fprintf(os.Stderr, "warmstart: round %d: the guest did not take the command sent with its bind: %s\n", round, state)
		}
	}
	if reached != nil && pinned == nil && !rec.WithBind {
		select {
		case rec.ReachedAhead = <-reached:
		default:
		}
	}
	client := ahead
	if pinned != nil {
		if client, err = session.NewClient(fmt.Sprintf("https://%s:%d", claimed.TD, session.AgentPort), bound, engine, signer,
			session.Through(host.Dialer(claimed.TD)), pinned); err != nil {
			return nil, err
		}
		defer client.Close()
	}
	if !rec.WithBind {
		// Over the session's connection, under the id it was sealed with if
		// it was: the guest runs a command once, whatever carried it there.
		if err := command(ctx, client, request); err != nil {
			return nil, fmt.Errorf("the first command: %w", err)
		}
	}
	rec.FirstExec, rec.FirstCommand = micros(step), micros(began)
	// A guest whose quote disagrees with its receipt is ended, whatever
	// --keep says, and the round fails.
	final := <-confirmed
	if final.err != nil {
		destroy()
		return nil, final.err
	}
	if rec.OnReceipt {
		if err := client.Confirmed(final.att, final.leaf); err != nil {
			return nil, err
		}
		if _, ok := client.Verdict(); !ok {
			return nil, errors.New("the client keeps no verdict after its quote was confirmed")
		}
	}
	if rec.WithBind && reached != nil && pinned == nil {
		// The connection the later commands take was made while the first
		// ran: their times are of commands alone.
		rec.ReachedAhead = <-reached
	}
	for range o.commands {
		step = time.Now()
		if err := command(ctx, client, session.ExecRequest{Argv: []string{"true"}}); err != nil {
			return nil, err
		}
		rec.Exec = append(rec.Exec, micros(step))
	}
	if o.attest {
		step = time.Now()
		if _, err := client.Attest(ctx); err != nil {
			// A guest rations its quotes, and has just given one.
			fmt.Fprintf(os.Stderr, "warmstart: round %d: no further attestation: %v\n", round, err)
		} else {
			rec.Attest = micros(step)
		}
	}
	return rec, nil
}

func command(ctx context.Context, client *session.Client, req session.ExecRequest) error {
	answer, err := client.Exec(ctx, req)
	if err != nil {
		return err
	}
	if answer.ExitCode != 0 {
		return fmt.Errorf("%v exited %d: %s", req.Argv, answer.ExitCode, answer.Stderr)
	}
	return nil
}
