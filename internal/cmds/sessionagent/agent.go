package sessionagent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	agratls "github.com/confidential-dot-ai/attestation-go/ratls"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/disclosure"
)

// Config is everything the agent is told. All of it is measured: the unit file
// that passes these flags is on the verity root.
type Config struct {
	// Platform is the TEE the image was built for: "tdx" or "snp".
	Platform string
	// PubkeyPath is where the measured initrd staged the launch public key.
	PubkeyPath string
	// LaunchDir holds launch.yaml and launch.yaml.sig from the opkeydata disk.
	LaunchDir string
	// CredentialDir is the RAM-backed directory released credentials land in.
	CredentialDir string
	TEE           TEE
	Runner        Runner
	// Bare lets a bind name no sandbox image: commands then run on the
	// guest's own file system, as its sandbox user, in the guest's own
	// namespaces and beside its services. That is a mode for tests. A guest
	// image for sessions leaves it off, and its agent takes no bind without a
	// sandbox image.
	Bare bool
	// Guard, when set, is asked before the guest serves and again before a
	// sandbox starts. An error from it ends the guest.
	Guard func(context.Context) error
	// ClockSource reads the kernel's current clocksource. A guest that must
	// end if it is not bound in time needs one the host cannot slow:
	// "tsc". The kernel can leave it while the guest runs, so it is asked
	// again when a bind arrives. Nil reads as no clocksource.
	ClockSource func() string
	// Now is the clock that deadline is counted on. Nil means time.Now, whose
	// monotonic reading it uses.
	Now func() time.Time
	// Memory accepts the guest's memory ahead of its sandbox. Nil leaves
	// that to whoever touches it first.
	Memory *Memory
	Logger *slog.Logger
	// CertTTL bounds one serving certificate; the instance key outlives it.
	CertTTL time.Duration
	// Engine verifies the evidence of the key service a launch document
	// pins. A guest with none refuses such a document.
	Engine session.Engine
	// KeyServiceDial opens the connection to the key service. Nil dials its
	// address.
	KeyServiceDial func(ctx context.Context, network, addr string) (net.Conn, error)
	// CollateralDial opens a connection to the host's answer to an ask for
	// Intel's documents: see Agent.AskHost. Nil is a guest that asks nobody
	// and serves none.
	CollateralDial func(ctx context.Context) (net.Conn, error)
}

// Agent is a staged guest: its launch document is authenticated and
// measured. Handler serves it.
type Agent struct {
	cfg       Config
	log       *slog.Logger
	tee       TEE
	doc       *session.Document
	launch    []byte
	signature string
	launchPub []byte

	// chain is nil on a platform without a runtime register.
	chain *chain
	// events is the full chain of a running guest, as far as it is known: the
	// launch document, and from the bind on the rest. The first staged events
	// are measured so far.
	events []string

	// measured guards events, staged, bind, admitted, admission and prestaged. A quote is taken under
	// its read side and the register is extended under its write side, so the
	// events a response reports are always the ones its quote carries.
	measured sync.RWMutex
	staged   int
	// bind is the guest's bind, from the moment it is measured.
	bind *session.SignedBind
	// retired: an unbound guest read a bind it would not take, or waited for
	// one too long, and is on its way out.
	retired bool
	// stagedAt is when the launch document was measured.
	stagedAt time.Time
	// binding orders bind requests: the first decides what the rest find.
	// The fence is raised under it too.
	binding sync.Mutex
	// fence cuts an unbound guest's connections when its host claims it.
	fence fence
	// bound is closed when the first bind's sandbox has been admitted, or has
	// failed to be.
	bound chan struct{}
	// admitted: the sandbox this agent process started is running. Commands
	// and credentials wait for it.
	admitted bool
	// receipt is the guest's signed word on its bind, from when the bind's
	// sandbox runs. bindQuote is the evidence it took over the bind's nonce,
	// from when it has it: what its state then serves.
	receipt   *session.SignedReceipt
	bindQuote *session.AttestResponse
	// settling is set while a bind's sandbox is being admitted: the register
	// already holds the sandbox's image, and the guest does not say so until
	// the sandbox runs. It is closed when that is decided. A quote for anyone
	// but the bind's sender waits for it, so that no quote shows a register
	// its guest's state does not explain.
	settling chan struct{}
	// admission is how long each step of admitting the sandbox took.
	admission []session.AdmissionStep
	// prestaged is closed when the guest is done with what it does ahead of
	// a bind: the images its launch document lists are unpacked and its
	// memory reserve is accepted. Nil until that began.
	prestaged <-chan struct{}
	// fatal carries the one error after which the guest must end.
	fatal chan error

	key *ecdsa.PrivateKey
	// keyDER is the instance public key, PKIX.
	keyDER []byte
	// audience is the name this guest takes tokens under: its instance key's
	// digest. A token for another guest that grants the same key names another.
	audience string
	certs    *ratls.CertManager
	tlsCfg   *tls.Config
	creds    *credentialStore
	execs    *execService
	attests  chan struct{}
	// quotes rations the fresh quotes this guest asks its host for.
	quotes   *quoteBudget
	inflight chan struct{}
	// forwards counts the streams open to the sandbox's ports.
	forwards forwards

	// platform says which of Intel's documents this guest's evidence is
	// judged against, from the first quote the guest took. Nil before that,
	// and on a platform whose evidence names none.
	platform atomic.Pointer[session.CollateralPlatform]
	// collateral is what the host last answered an ask with, unread: the
	// guest's answer to PathCollateral.
	collateral atomic.Pointer[[]byte]
	// kept is closed at the first answer kept.
	kept     chan struct{}
	keptOnce sync.Once
	// keyService is the guest's session with the key service its launch
	// document pins, or nil.
	keyService *keyService
	// unpinned: a TD whose launch document lists no machine it may be. It
	// serves what says which machine it is, and takes no bind: see Unpinned.
	unpinned bool
}

// Unpinned reports whether this guest is a TD whose launch document lists no
// machine (RTMR[0]) it may be. RTMR[0] holds what the host declared to the
// firmware: the shape of the machine. A guest that took a bind under a
// document that lists none would run a session on whatever machine its host
// chose to build. It takes none. It still says what it is to anyone, so that
// whoever writes the document can read the machine's value from its evidence
// and list it.
func (a *Agent) Unpinned() bool { return a.unpinned }

// Stage authenticates this boot's launch document and measures it. Nothing the
// host supplied is acted on before its signature verifies under the key the
// hardware binds.
func Stage(ctx context.Context, cfg Config) (*Agent, error) {
	if cfg.TEE == nil || cfg.Runner == nil {
		return nil, errors.New("agent requires a TEE and a runner")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.CertTTL <= 0 {
		cfg.CertTTL = ratls.DefaultCertTTL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	pub, launch, signature, self, err := launchFiles(ctx, cfg.TEE, cfg.Platform, cfg.PubkeyPath, cfg.LaunchDir)
	if err != nil {
		return nil, err
	}
	doc, err := session.VerifySigned(pub, launch, string(signature))
	if err != nil {
		return nil, err
	}
	if err := checkOwnImage(self, doc.Image); err != nil {
		return nil, err
	}
	if err := checkOwnMachine(self, doc.Machine); err != nil {
		return nil, err
	}
	// A deadline counted on a clock the host feeds is no deadline. The TSC of
	// a confidential guest keeps its own time, also while the guest is paused.
	if source := cfg.clockSource(); doc.AgeLimitSeconds > 0 && source != ownClockSource {
		return nil, fmt.Errorf("the launch document bounds how long this guest waits for a bind, and its clocksource is %q, not %s", source, ownClockSource)
	}
	// The chain ends at the launch document until a bind extends it.
	events, err := session.ExpectedEvents(launch, nil, session.PhaseReady)
	if err != nil {
		return nil, err
	}
	a := &Agent{
		cfg: cfg, log: cfg.Logger, tee: cfg.TEE, doc: doc, launch: launch,
		signature: string(bytes.TrimSpace(signature)), launchPub: pub, events: events,
		stagedAt: cfg.Now(),
		bound:    make(chan struct{}),
		kept:     make(chan struct{}),
		fatal:    make(chan error, 1),
		attests:  make(chan struct{}, maxConcurrentAttests),
		quotes:   newQuoteBudget(cfg.Now),
		inflight: make(chan struct{}, maxInflightRequests),
		// A TD has a register for what its host declared, and a document
		// that lists no value for it leaves the host free to declare
		// anything. Other TEEs measure the machine with the image.
		unpinned: doc.Machine == nil && doc.Image.HasMachineRegister(),
	}
	if a.unpinned {
		cfg.Logger.Warn("the launch document lists no machine this guest may be: it takes no bind, and serves only what says which machine it is")
	}
	// The pubkey file is not itself measured, only its digest: confirm the
	// staged key is the one the hardware binds before trusting anything it signed.
	reg, err := cfg.TEE.Register()
	switch {
	case err == nil:
		a.chain = newChain(reg, pub, events)
		if _, err := a.chain.position(); err != nil {
			return nil, fmt.Errorf("launch key is not the one this guest was launched for: %w", err)
		}
		if err := a.chain.advance(1); err != nil {
			return nil, fmt.Errorf("measure launch document: %w", err)
		}
		// The register is the record. An earlier agent process in this guest
		// may have taken it further than the document.
		if a.staged, err = a.chain.position(); err != nil {
			return nil, err
		}
	case errors.Is(err, runtimemeasure.ErrNoRegister):
		if err := runtimemeasure.VerifyBinding(self, pub, nil); err != nil {
			return nil, fmt.Errorf("launch key is not the one this guest was launched for: %w", err)
		}
		a.staged = 1
	default:
		return nil, err
	}
	uid, gid := cfg.Runner.CredentialOwner()
	if a.creds, err = newCredentialStore(cfg.CredentialDir, uid, gid); err != nil {
		return nil, err
	}
	a.execs = newExecService(cfg.Runner)
	if a.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return nil, fmt.Errorf("generate instance key: %w", err)
	}
	if a.keyDER, err = x509.MarshalPKIXPublicKey(&a.key.PublicKey); err != nil {
		return nil, fmt.Errorf("encode instance key: %w", err)
	}
	if a.audience, err = session.InstanceKeyDigest(&a.key.PublicKey); err != nil {
		return nil, err
	}
	a.tlsCfg, a.certs, err = ratls.NewServerTLSConfig(&ratls.ServerConfig{
		CertProvider: &instanceProvider{key: a.key, tee: a.tee, ttl: cfg.CertTTL, seen: a.notePlatform},
		CertTTL:      cfg.CertTTL,
		Logger:       cfg.Logger,
	})
	if err != nil {
		return nil, err
	}
	if doc.KeyService != nil {
		if a.keyService, err = a.newKeyService(doc.KeyService); err != nil {
			return nil, err
		}
	}
	a.log.Info("launch document staged", "pool", doc.Pool, "class", doc.Class,
		"launch_digest", session.DocumentDigest(launch), "key_service", doc.KeyService != nil)
	return a, nil
}

// launchFiles reads this boot's launch files and the guest's own
// measurements, and refuses a guest of another platform than its image's or
// one its host can debug. Nothing in the files is authenticated yet.
func launchFiles(ctx context.Context, tee TEE, platform, pubkeyPath, launchDir string) (pub, launch, signature []byte, self *teetypes.VerificationResult, err error) {
	family, err := teetypes.ParseFamily(platform)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("--platform: %w", err)
	}
	if tee.Family() != family {
		return nil, nil, nil, nil, fmt.Errorf("image was built for %s but this guest is %s", family, tee.Family())
	}
	if pub, err = session.ReadBounded(pubkeyPath, 8192); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("launch public key (was the VM launched with opkeydata?): %w", err)
	}
	if launch, err = session.ReadBounded(filepath.Join(launchDir, session.DocumentFile), session.MaxDocumentSize); err != nil {
		return nil, nil, nil, nil, err
	}
	if signature, err = session.ReadBounded(filepath.Join(launchDir, session.SignatureFile), 4096); err != nil {
		return nil, nil, nil, nil, err
	}
	if self, err = tee.Measurements(ctx); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("read this guest's measurements: %w", err)
	}
	if self.Platform.Family() != family {
		return nil, nil, nil, nil, fmt.Errorf("hardware reports platform %q, image was built for %s", self.Platform, family)
	}
	// A debug guest's memory is readable by the host. No verifier would accept
	// it, and nothing should be staged where the host can watch.
	if debug, err := self.Claims.DebugEnabled(); err != nil || debug {
		return nil, nil, nil, nil, fmt.Errorf("refusing to run in a debuggable guest (debug=%v, %v)", debug, err)
	}
	return pub, launch, signature, self, nil
}

// MeasuredDocument is a guest's own launch document, authenticated under the
// key the hardware binds and measured.
type MeasuredDocument struct {
	Launch    []byte
	Signature string
	LaunchKey []byte
}

// MeasureDocument does for another measured service of a guest image what
// Stage does for a session guest's agent: it authenticates this boot's launch
// document under the key the hardware binds, holds it to this guest's own
// image and to the machines it lists, and measures it before anything in it
// is acted on. verify checks the document's signature and returns the image
// it was signed for and the machines it lists.
//
// It needs a runtime register, so that the document is in the guest's
// evidence: Intel TDX today.
func MeasureDocument(ctx context.Context, tee TEE, platform, pubkeyPath, launchDir string,
	verify func(pub, launch []byte, signature string) (session.Image, *session.Machine, error),
) (*MeasuredDocument, error) {
	pub, launch, signature, self, err := launchFiles(ctx, tee, platform, pubkeyPath, launchDir)
	if err != nil {
		return nil, err
	}
	image, machine, err := verify(pub, launch, string(signature))
	if err != nil {
		return nil, err
	}
	if err := checkOwnImage(self, image); err != nil {
		return nil, err
	}
	if err := checkOwnMachine(self, machine); err != nil {
		return nil, err
	}
	reg, err := tee.Register()
	if err != nil {
		return nil, fmt.Errorf("measure launch document: %w", err)
	}
	// The pubkey file is not itself measured, only its digest: confirm the
	// staged key is the one the hardware binds before trusting what it signed.
	chain := newChain(reg, pub, []string{session.DocumentDigest(launch)})
	if _, err := chain.position(); err != nil {
		return nil, fmt.Errorf("launch key is not the one this guest was launched for: %w", err)
	}
	if err := chain.advance(1); err != nil {
		return nil, fmt.Errorf("measure launch document: %w", err)
	}
	return &MeasuredDocument{Launch: launch, Signature: string(bytes.TrimSpace(signature)), LaunchKey: pub}, nil
}

// Admit begins what the guest does ahead of a bind: it unpacks the images its
// launch document lists and accepts its memory reserve. Nothing of an image
// runs here, and no sandbox is admitted: that waits for the bind.
func (a *Agent) Admit(ctx context.Context) error {
	var ahead <-chan struct{}
	if len(a.doc.Prestage) > 0 {
		// Not under ctx's deadline, if it has one: the unpacking goes on
		// while the guest serves, until a bind names its image.
		ahead = a.cfg.Runner.Prestage(context.WithoutCancel(ctx), a.doc.Prestage)
	}
	if a.cfg.Memory != nil {
		// After the unpacking, which takes memory of its own: the reserve
		// is what the session's start finds free.
		unpacked, reserved := ahead, make(chan struct{})
		go func() {
			defer close(reserved)
			if unpacked != nil {
				<-unpacked
			}
			a.cfg.Memory.Reserve()
		}()
		ahead = reserved
	}
	a.measured.Lock()
	a.prestaged = ahead
	a.measured.Unlock()
	a.log.Info("waiting for a bind", "phase", session.PhaseReady, "prestage", len(a.doc.Prestage))
	return nil
}

// admit prepares, measures and starts the sandbox, signs the receipt that
// answers the bind, and takes the quote that follows it.
//
// The register is made final before the slow steps: the sandbox's image is
// extended into it as soon as the image is in place. The quote over the
// bind's nonce is then taken while the guest takes its credentials and starts
// its sandbox. Once the sandbox runs the guest signs its receipt, and the
// bind is answered with it: with the quote too if that is there by then, and
// otherwise the quote is served with the guest's state when it arrives. A
// guest whose admission fails after the extend ends, as it does on any other
// failure here, and gives no quote on its way out.
func (a *Agent) admit(ctx context.Context, bind *session.SignedBind) (*session.SignedReceipt, *session.AttestResponse, error) {
	ctx, steps := withAdmission(ctx)
	sandbox, egress := bind.Doc.Policy.Sandbox, bind.Doc.Policy.Egress
	if sandbox != nil {
		if err := a.cfg.Runner.Prepare(ctx, sandbox, egress); err != nil {
			return nil, nil, fmt.Errorf("prepare sandbox: %w", err)
		}
		// The image names the user it runs as, so the owner of its credentials
		// is known only now. None can have been written: that waits on admission.
		uid, gid := a.cfg.Runner.CredentialOwner()
		if err := a.creds.setOwner(uid, gid); err != nil {
			return nil, nil, err
		}
		// Asked before the image is measured: a guest that will not start
		// its sandbox does not say it admitted one.
		if a.cfg.Guard != nil {
			if err := a.cfg.Guard(ctx); err != nil {
				return nil, nil, fmt.Errorf("before starting the sandbox: %w", err)
			}
		}
	}
	events, err := a.settle(ctx, sandbox != nil)
	if err != nil {
		return nil, nil, err
	}
	evidence := make(chan *session.AttestResponse, 1)
	go func() { evidence <- a.bindEvidence(ctx, bind, events) }()
	// What the bind has the key service hold for the session is in place
	// before the sandbox starts, so the sandbox finds it at its first read.
	if err := a.acquire(ctx, bind); err != nil {
		return nil, nil, err
	}
	if sandbox != nil {
		began := time.Now()
		if err := a.cfg.Runner.Start(ctx, a.creds.dir); err != nil {
			return nil, nil, fmt.Errorf("start sandbox: %w", err)
		}
		recordStep(ctx, stepStart, time.Since(began))
	}
	// What the guest extended after its launch document, which a quote from
	// before the bind does not hold.
	receipt, err := session.NewBindReceipt(a.key, bind, events[1:], session.PhaseRunning)
	if err != nil {
		return nil, nil, err
	}
	a.settled(receipt)
	// The quote goes with the answer only if it is there. Otherwise it is
	// served with the guest's state once it is, and nobody waits.
	var resp *session.AttestResponse
	attempted := false
	select {
	case resp = <-evidence:
		attempted = true
		a.keepBindQuote(resp)
	default:
	}
	go func() {
		quote := resp
		if !attempted {
			quote = <-evidence
			a.keepBindQuote(quote)
		}
		// The serving certificate's quote predates the last extend; reissue
		// it so a handshake alone shows the final register. A certificate
		// from before passes a verifier's handshake too, so nobody waits for
		// this one, and it follows the bind's quote: the quoting service
		// takes one request of a guest at a time.
		if a.certs.CertReady() {
			if err := a.certs.SwapProvider(ctx, &instanceProvider{key: a.key, tee: a.tee, ttl: a.cfg.CertTTL}); err != nil {
				a.log.Warn("reissue serving certificate after sandbox admission", "error", err)
			}
		}
		if quote == nil {
			a.keepBindQuote(a.bindEvidenceAgain(ctx, bind, events))
		}
	}()
	taken := steps.list()
	a.measured.Lock()
	a.admission = taken
	a.measured.Unlock()
	a.log.Info("sandbox admitted", "phase", session.PhaseRunning, "steps", taken)
	// The guest has its sandbox. What it has not accepted of its memory is
	// accepted behind it, for as long as the guest lives if it takes that.
	go a.cfg.Memory.AcceptRest(context.WithoutCancel(ctx))
	return receipt, resp, nil
}

// bindQuotePauses are how long a guest that could not take the quote over
// its bind's nonce waits before each further attempt. Together they stay
// under the time a binder waits for the quote before it asks for an
// attestation itself.
var bindQuotePauses = []time.Duration{250 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second}

// bindEvidenceAgain takes the quote over the bind's nonce for a guest whose
// first attempt gave none: its ration had none due, or its quoting service
// failed. Nil is a guest that got none in a few more attempts.
func (a *Agent) bindEvidenceAgain(ctx context.Context, bind *session.SignedBind, events []string) *session.AttestResponse {
	for _, pause := range bindQuotePauses {
		select {
		case <-time.After(pause):
		case <-ctx.Done():
			return nil
		}
		if resp := a.bindEvidence(ctx, bind, events); resp != nil {
			return resp
		}
	}
	return nil
}

// keepBindQuote keeps the evidence the guest took over its bind's nonce, for
// its state to serve. Nil is an attempt that gave none.
func (a *Agent) keepBindQuote(resp *session.AttestResponse) {
	if resp == nil {
		return
	}
	a.measured.Lock()
	a.bindQuote = resp
	a.measured.Unlock()
}

// settle makes the register final for the bind: with a sandbox, it extends
// the sandbox's image into it. It returns the events the register then
// holds. From here until settled, the guest still says it is bound and no
// more, and a quote for anyone but the bind's sender waits.
func (a *Agent) settle(ctx context.Context, sandbox bool) ([]string, error) {
	a.measured.Lock()
	defer a.measured.Unlock()
	if sandbox && a.chain != nil {
		began := time.Now()
		if err := a.chain.advance(len(a.events)); err != nil {
			return nil, fmt.Errorf("measure sandbox image: %w", err)
		}
		recordStep(ctx, stepMeasure, time.Since(began))
	}
	a.settling = make(chan struct{})
	return append([]string(nil), a.events...), nil
}

// settled is the end of an admission that succeeded: the guest runs its
// sandbox, says so, keeps the receipt it answers its bind with, and gives
// quotes again.
func (a *Agent) settled(receipt *session.SignedReceipt) {
	a.measured.Lock()
	defer a.measured.Unlock()
	a.staged, a.admitted, a.receipt = len(a.events), true, receipt
	close(a.settling)
	a.settling = nil
}

// errNoSandbox refuses a bind that would have a session's commands run
// outside a container.
var errNoSandbox = errors.New("this guest runs a session's code inside a sandbox image only, and the bind names none")

var (
	errAlreadyBound = errors.New("this guest is already bound by another bind")
	errRetired      = errors.New("this guest takes no bind any more and is shutting down")
	errFenced       = errors.New("this connection was opened before the guest was claimed, and the guest takes no bind from it")
	errNotReady     = errors.New("this guest takes no bind yet: its key service has not judged it")
	errNoMachine    = errors.New("this guest's launch document lists no machine it may be, so it takes no bind")
	errBindInFlight = errors.New("this guest is reading a bind: it is not as it was booted")
	errBindTooLate  = errors.New("this guest waited for a bind longer than its launch document allows")
	errClockLeft    = errors.New("this guest's kernel left the " + ownClockSource + " clocksource, so it cannot tell how long it waited for a bind")
)

// ownClockSource is the clocksource a confidential guest keeps itself. Every
// other one is a device the host emulates, or a page the host writes.
const ownClockSource = "tsc"

func (c Config) clockSource() string {
	if c.ClockSource == nil {
		return ""
	}
	return c.ClockSource()
}

// bindRefusal is a bind the guest will not accept. The code is what the
// sender is told: one of a list, and nothing of the reason's own words.
type bindRefusal struct {
	code disclosure.Code
	err  error
}

func (r *bindRefusal) Error() string { return r.err.Error() }
func (r *bindRefusal) Unwrap() error { return r.err }

func refused(code disclosure.Code, err error) *bindRefusal { return &bindRefusal{code: code, err: err} }

// Bind makes the guest one session's. The bind is extended into the register
// before anything in it takes effect, and the first one is the only one. Once
// bound, the guest answers the same bind as it did the first time and refuses
// any other without reading it.
//
// An unbound guest that reads a bind it will not take has taken in input of
// somebody's choosing while it belonged to nobody. It is not handed to anyone
// after that: it ends.
//
// The guest does not judge the authority that signed. Whoever relies on the
// guest reads the bind from its evidence and checks that.
//
// The sender is given the guest's receipt for the bind, and the evidence for
// the bind's nonce with it if the guest has it by then: see admit.
func (a *Agent) Bind(ctx context.Context, raw []byte, signature string) (replayed bool, answer *BindAnswer, err error) {
	a.binding.Lock()
	a.measured.RLock()
	current, retired := a.bind, a.retired
	a.measured.RUnlock()
	// The server refuses such a bind before it reads it (letIn). This holds
	// the same for a caller that hands the agent a bind directly: an unbound
	// guest that was claimed does not look at what came before, so it stays
	// as it was booted and does not end over it.
	if current == nil && !retired && !a.fence.admits(connOf(ctx)) {
		a.binding.Unlock()
		return false, nil, errFenced
	}
	// The same for a bind that comes before the guest takes any, and for
	// one to a guest that takes none.
	if current == nil && !retired && a.unpinned {
		a.binding.Unlock()
		return false, nil, errNoMachine
	}
	if current == nil && !retired && !a.takesBinds() {
		a.binding.Unlock()
		return false, nil, errNotReady
	}
	if current != nil || retired {
		a.binding.Unlock()
		switch {
		case retired:
			return false, nil, errRetired
		case !bytes.Equal(current.Raw, raw):
			return false, nil, errAlreadyBound
		}
		select {
		case <-a.bound:
			// As the first time: the receipt, and the quote if it is there.
			a.measured.RLock()
			again := &BindAnswer{Receipt: a.receipt, Attestation: a.bindQuote}
			a.measured.RUnlock()
			return true, again, nil
		case <-ctx.Done():
			return true, nil, ctx.Err()
		}
	}
	bind, events, refusal := a.acceptable(raw, signature)
	if err := refusal; err != nil {
		a.measured.Lock()
		a.retired = true
		a.measured.Unlock()
		a.binding.Unlock()
		_ = a.fail(fmt.Errorf("refused a bind while unbound: %w", err))
		return false, nil, err
	}
	a.measured.Lock()
	// Launch document, then bind: two events.
	if a.chain != nil {
		a.chain.extendTo(events)
		if err := a.chain.advance(2); err != nil {
			a.retired = true
			a.measured.Unlock()
			a.binding.Unlock()
			// The register may hold a bind this agent does not: no verifier
			// could follow the guest from here.
			return false, nil, a.fail(fmt.Errorf("measure bind: %w", err))
		}
	}
	a.events, a.staged, a.bind = events, 2, bind
	a.admitted = bind.Doc.Policy.Sandbox == nil
	a.measured.Unlock()
	a.binding.Unlock()
	a.log.Info("bound", "bind_digest", session.DocumentDigest(raw), "sandbox", bind.Doc.Policy.Sandbox != nil)

	// The first bind is the only one, so a guest whose sandbox cannot be
	// admitted is of no use to anyone and ends. The caller going away changes
	// nothing about that.
	receipt, evidence, err := a.admit(context.WithoutCancel(ctx), bind)
	close(a.bound)
	if err != nil {
		return false, nil, a.fail(err)
	}
	return false, &BindAnswer{Receipt: receipt, Attestation: evidence}, nil
}

// BindAnswer is what a guest answers a bind it took with: its receipt, and
// the evidence over the bind's nonce if it has that already.
type BindAnswer struct {
	Receipt     *session.SignedReceipt
	Attestation *session.AttestResponse
}

// acceptable checks a bind for this guest: well-formed, signed by the
// authority it names, written for this instance key, and not past its time.
func (a *Agent) acceptable(raw []byte, signature string) (*session.SignedBind, []string, *bindRefusal) {
	// Checked before the bind is parsed: a guest past its deadline reads
	// nothing more that a stranger sends it.
	if a.bindTooLate() {
		return nil, nil, refused(disclosure.BindTooLate, errBindTooLate)
	}
	// The deadline was counted on whatever clock the kernel used since the
	// guest staged. If that is no longer its own, the count means nothing.
	if a.doc.AgeLimitSeconds > 0 && a.cfg.clockSource() != ownClockSource {
		return nil, nil, refused(disclosure.BindClock, errClockLeft)
	}
	// Parsed first, so that the two ways a bind fails to verify are told
	// apart: it is no bind, or its signature is not its authority's.
	if _, err := session.ParseBind(raw); err != nil {
		return nil, nil, refused(disclosure.BindInvalid, err)
	}
	bind, err := session.VerifyBind(raw, signature)
	if err != nil {
		return nil, nil, refused(disclosure.BindSignature, err)
	}
	if err := bind.Doc.Targets(&a.key.PublicKey); err != nil {
		return nil, nil, refused(disclosure.BindOtherGuest, err)
	}
	if !a.cfg.Bare && bind.Doc.Policy.Sandbox == nil {
		return nil, nil, refused(disclosure.BindNoSandbox, errNoSandbox)
	}
	// The guest holds one key service to a pin, its pool's, and opened its
	// session with that one before it was anybody's.
	if pin := bind.Doc.KeyService; pin != nil && !pin.Equal(a.doc.KeyService) {
		return nil, nil, refused(disclosure.BindKeyService, errors.New("the bind trusts a key service that this guest's launch document does not pin"))
	}
	if time.Now().After(bind.Doc.Expiry().Add(tokenClockSkew)) {
		return nil, nil, refused(disclosure.BindExpired, fmt.Errorf("bind expired at %s", bind.Doc.NotAfter))
	}
	events, err := session.ExpectedEvents(a.launch, bind, session.PhaseRunning)
	if err != nil {
		return nil, nil, refused(disclosure.BindInvalid, err)
	}
	return bind, events, nil
}

// takesBinds reports whether the guest takes a bind yet. One whose launch
// document pins a key service takes none until the key service has judged
// it: the evidence the key service judges is of a guest that is nobody's.
// One whose document lists no machine never takes one.
func (a *Agent) takesBinds() bool {
	return !a.unpinned && (a.keyService == nil || a.keyService.isOpen())
}

// preparedLocked reports whether the guest is done with what it does ahead
// of a bind: its session with its key service is open, if its launch document
// pins one, and what Admit began has ended.
func (a *Agent) preparedLocked() bool {
	// A host offers a guest to a session once it takes a bind.
	if !a.takesBinds() {
		return false
	}
	if len(a.doc.Prestage) == 0 && a.cfg.Memory == nil {
		return true
	}
	select {
	case <-a.prestaged:
		// A nil channel never is: the unpacking has not begun.
		return true
	default:
		return false
	}
}

// bindTooLate reports whether the guest has been unbound longer than its
// launch document allows.
func (a *Agent) bindTooLate() bool {
	limit := a.doc.AgeLimit()
	return limit > 0 && a.cfg.Now().Sub(a.stagedAt) > limit
}

// UnboundFor is how much longer the guest waits for its bind, and whether
// its launch document bounds that at all.
func (a *Agent) UnboundFor() (time.Duration, bool) {
	if a.doc.AgeLimitSeconds == 0 {
		return 0, false
	}
	return a.doc.AgeLimit() - a.cfg.Now().Sub(a.stagedAt), true
}

// ExpireUnbound ends a guest that is still unbound past its deadline. A
// guest that was bound in time, or is in the middle of being bound, is left
// alone.
func (a *Agent) ExpireUnbound() {
	a.binding.Lock()
	defer a.binding.Unlock()
	a.measured.Lock()
	expired := a.bind == nil && !a.retired && a.bindTooLate()
	if expired {
		a.retired = true
	}
	a.measured.Unlock()
	if expired {
		_ = a.fail(errBindTooLate)
	}
}

// Fence is what a guest does when its host claims it for a session. A bound
// guest reports its phase and changes nothing. An unbound one closes every
// connection it accepted so far, except the one ctx came on, and from then on
// takes a bind only from a connection accepted later. ok is false for a guest
// on its way out.
//
// An answer of ready is settled: the guest has read no bind, and no bind sent
// before the fence can take effect. A guest that is reading one, or has read
// one it has not acted on yet, answers errBindInFlight and changes nothing.
// Its host treats that as bound.
func (a *Agent) Fence(ctx context.Context) (phase session.Phase, closed int, ok bool, err error) {
	a.binding.Lock()
	defer a.binding.Unlock()
	a.measured.RLock()
	phase, _ = a.stateLocked()
	bound, retired := a.bind != nil, a.retired
	a.measured.RUnlock()
	switch {
	case retired:
		return phase, 0, false, nil
	case bound:
		return phase, 0, true, nil
	}
	closed, raised := a.fence.raise(connOf(ctx))
	if !raised {
		return phase, 0, true, errBindInFlight
	}
	return phase, closed, true, nil
}

// fail records the error that ends the guest and returns it.
func (a *Agent) fail(err error) error {
	select {
	case a.fatal <- err:
	default:
	}
	return err
}

// Fatal delivers an error after which the guest must end.
func (a *Agent) Fatal() <-chan error { return a.fatal }

// WarmUp provisions the serving certificate before the first handshake.
func (a *Agent) WarmUp(ctx context.Context) error { return a.certs.WarmUp(ctx) }

// stateLocked returns the phase and the events the register holds. The caller
// holds measured.
func (a *Agent) stateLocked() (session.Phase, []string) {
	phase := session.PhaseBound
	switch {
	case a.bind == nil:
		phase = session.PhaseReady
	case a.staged == len(a.events):
		phase = session.PhaseRunning
	}
	return phase, append([]string(nil), a.events[:a.staged]...)
}

// grants returns who may drive the guest and which credentials it may be
// handed: the bind's word. An unbound guest grants nothing to anyone.
func (a *Agent) grants() (session.Access, []session.Credential) {
	a.measured.RLock()
	defer a.measured.RUnlock()
	if a.bind == nil {
		return session.Access{}, nil
	}
	return a.bind.Doc.Policy.Access, a.bind.Doc.Policy.Credentials
}

// forward returns the ports the guest's bind opens to streams from outside.
// Nil opens none.
func (a *Agent) forward() *session.Forward {
	a.measured.RLock()
	defer a.measured.RUnlock()
	if a.bind == nil {
		return nil
	}
	return a.bind.Doc.Policy.Forward
}

// sandboxRunning reports whether commands and credentials have a sandbox to
// go to.
func (a *Agent) sandboxRunning() bool {
	a.measured.RLock()
	defer a.measured.RUnlock()
	return a.admitted
}

// checkOwnImage refuses a document signed for another build: a launch key
// holder who pinned image A must not have that signature honoured by image B.
func checkOwnImage(self *teetypes.VerificationResult, image session.Image) error {
	if self.Platform.Family() != image.Family() {
		return fmt.Errorf("launch document is for a %s image, this guest is %s", image.Family(), self.Platform.Family())
	}
	identity, err := runtimemeasure.IdentityFromResult(self)
	if err != nil {
		return fmt.Errorf("this guest's image identity: %w", err)
	}
	digests := identity.LaunchDigests()
	if len(digests) != 1 || hex.EncodeToString(digests[0].Digest[:]) != image.Measurement {
		return errors.New("launch document image measurement does not match this boot")
	}
	observed := identity.RTMRs()
	for idx, want := range image.RTMRs {
		got, ok := observed[idx]
		if !ok || hex.EncodeToString(got[:]) != want {
			return fmt.Errorf("launch document RTMR[%d] does not match this boot", idx)
		}
	}
	return nil
}

// checkOwnMachine refuses a document that lists other machines than the one
// the host built around this guest. A verifier refuses such a guest too; the
// guest ends here, before it serves anything.
func checkOwnMachine(self *teetypes.VerificationResult, machine *session.Machine) error {
	if machine == nil {
		return nil
	}
	rtmr0, err := self.Claims.RTMR(0)
	if err != nil {
		return fmt.Errorf("the launch document pins this guest's machine: %w", err)
	}
	if !machine.Allows(rtmr0) {
		return fmt.Errorf("this guest's machine (RTMR[0] %x) is none of the %d its launch document lists", rtmr0, len(machine.RTMR0))
	}
	return nil
}

// instanceProvider issues serving certificates over one in-memory key for the
// life of the agent, so the key a verifier attested stays the key it talks to.
type instanceProvider struct {
	key *ecdsa.PrivateKey
	tee TEE
	ttl time.Duration
	// seen, when set, is shown the evidence a certificate is issued over.
	seen func(teetypes.AttestationEvidence)
}

func (p *instanceProvider) Provision(ctx context.Context) (*tls.Certificate, time.Duration, error) {
	rd, err := ratls.ReportDataForKey(&p.key.PublicKey, nil)
	if err != nil {
		return nil, 0, err
	}
	env, err := p.tee.Evidence(ctx, rd[:48])
	if err != nil {
		return nil, 0, fmt.Errorf("attest instance key: %w", err)
	}
	if p.seen != nil {
		p.seen(env)
	}
	att, err := agratls.NewAttestation(env)
	if err != nil {
		return nil, 0, err
	}
	der, err := ratls.CreateAttestedCert(p.key, att, &ratls.CertOptions{
		// One name for every guest: whose it is, its evidence says.
		Subject: pkix.Name{CommonName: "c8s session", Organization: []string{"Confidential"}},
		TTL:     p.ttl,
	})
	if err != nil {
		return nil, 0, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, 0, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: p.key, Leaf: leaf}, p.ttl, nil
}
