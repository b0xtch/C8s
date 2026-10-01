package podagent

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
	"path/filepath"
	"sync"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	agratls "github.com/confidential-dot-ai/attestation-go/ratls"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/podcvm"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
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
	Logger        *slog.Logger
	// CertTTL bounds one serving certificate; the instance key outlives it.
	CertTTL time.Duration
}

// Agent is a staged pod CVM: its launch document is authenticated and
// measured. Handler serves it.
type Agent struct {
	cfg       Config
	log       *slog.Logger
	tee       TEE
	doc       *podcvm.Document
	launch    []byte
	signature string
	launchPub []byte

	// chain is nil on a platform without a runtime register.
	chain *chain
	// events is the full chain of a running guest; the first staged events
	// are measured so far.
	events []string

	// measured guards staged and admitted. A quote is taken under its read
	// side and the register is extended under its write side, so the events a
	// response reports are always the ones its quote carries.
	measured sync.RWMutex
	staged   int
	// admitted: the workload this agent process started is running. Commands
	// and credentials wait for it.
	admitted bool

	key      *ecdsa.PrivateKey
	certs    *ratls.CertManager
	tlsCfg   *tls.Config
	creds    *credentialStore
	execs    *execService
	attests  chan struct{}
	inflight chan struct{}
}

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
	family, err := teetypes.ParseFamily(cfg.Platform)
	if err != nil {
		return nil, fmt.Errorf("--platform: %w", err)
	}
	if cfg.TEE.Family() != family {
		return nil, fmt.Errorf("image was built for %s but this guest is %s", family, cfg.TEE.Family())
	}
	pub, err := podcvm.ReadBounded(cfg.PubkeyPath, 8192)
	if err != nil {
		return nil, fmt.Errorf("launch public key (was the VM launched with opkeydata?): %w", err)
	}
	launch, err := podcvm.ReadBounded(filepath.Join(cfg.LaunchDir, podcvm.DocumentFile), podcvm.MaxDocumentSize)
	if err != nil {
		return nil, err
	}
	signature, err := podcvm.ReadBounded(filepath.Join(cfg.LaunchDir, podcvm.SignatureFile), 4096)
	if err != nil {
		return nil, err
	}
	self, err := cfg.TEE.Measurements(ctx)
	if err != nil {
		return nil, fmt.Errorf("read this guest's measurements: %w", err)
	}
	if self.Platform.Family() != family {
		return nil, fmt.Errorf("hardware reports platform %q, image was built for %s", self.Platform, family)
	}
	// A debug guest's memory is readable by the host. No verifier would accept
	// it, and nothing should be staged where the host can watch.
	if debug, err := self.Claims.DebugEnabled(); err != nil || debug {
		return nil, fmt.Errorf("refusing to run in a debuggable guest (debug=%v, %v)", debug, err)
	}
	doc, err := podcvm.VerifySigned(pub, launch, string(signature))
	if err != nil {
		return nil, err
	}
	if err := checkOwnImage(self, doc.Image); err != nil {
		return nil, err
	}
	events, err := podcvm.ExpectedEvents(launch, doc, podcvm.PhaseRunning)
	if err != nil {
		return nil, err
	}
	a := &Agent{
		cfg: cfg, log: cfg.Logger, tee: cfg.TEE, doc: doc, launch: launch,
		signature: string(bytes.TrimSpace(signature)), launchPub: pub, events: events,
		attests:  make(chan struct{}, maxConcurrentAttests),
		inflight: make(chan struct{}, maxInflightRequests),
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
	a.admitted = doc.Workload == nil
	uid, gid := cfg.Runner.CredentialOwner()
	if a.creds, err = newCredentialStore(cfg.CredentialDir, uid, gid); err != nil {
		return nil, err
	}
	a.execs = newExecService(cfg.Runner)
	if a.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return nil, fmt.Errorf("generate instance key: %w", err)
	}
	a.tlsCfg, a.certs, err = ratls.NewServerTLSConfig(&ratls.ServerConfig{
		CertProvider: &instanceProvider{key: a.key, tee: a.tee, ttl: cfg.CertTTL, sandbox: doc.Sandbox},
		CertTTL:      cfg.CertTTL,
		Logger:       cfg.Logger,
	})
	if err != nil {
		return nil, err
	}
	a.log.Info("launch document staged", "tenant", doc.Tenant, "sandbox", doc.Sandbox, "id", doc.ID,
		"launch_digest", podcvm.LaunchDigest(launch), "workload", doc.Workload != nil)
	return a, nil
}

// Admit prepares the workload the document names, measures it, and only then
// starts it: nothing unmeasured ever runs. A document with no workload is
// already running.
func (a *Agent) Admit(ctx context.Context) error {
	if a.doc.Workload != nil {
		if err := a.cfg.Runner.Prepare(ctx, a.doc.Workload); err != nil {
			return fmt.Errorf("prepare workload: %w", err)
		}
		if err := a.measureAndStart(ctx); err != nil {
			return err
		}
	}
	// The serving certificate's quote predates the last extend; reissue it so
	// a handshake alone shows the final register.
	if a.certs.CertReady() {
		if err := a.certs.SwapProvider(ctx, &instanceProvider{key: a.key, tee: a.tee, ttl: a.cfg.CertTTL, sandbox: a.doc.Sandbox}); err != nil {
			a.log.Warn("reissue serving certificate after workload admission", "error", err)
		}
	}
	a.log.Info("workload admitted", "phase", podcvm.PhaseRunning)
	return nil
}

// measureAndStart extends the register with the workload image and starts the
// workload, as one step no quote can fall inside.
func (a *Agent) measureAndStart(ctx context.Context) error {
	a.measured.Lock()
	defer a.measured.Unlock()
	if a.chain != nil {
		if err := a.chain.advance(len(a.events)); err != nil {
			return fmt.Errorf("measure workload image: %w", err)
		}
	}
	a.staged = len(a.events)
	if err := a.cfg.Runner.Start(ctx, a.creds.dir); err != nil {
		return fmt.Errorf("start workload: %w", err)
	}
	a.admitted = true
	return nil
}

// WarmUp provisions the serving certificate before the first handshake.
func (a *Agent) WarmUp(ctx context.Context) error { return a.certs.WarmUp(ctx) }

// stateLocked returns the phase and the events the register holds. The caller
// holds measured.
func (a *Agent) stateLocked() (podcvm.Phase, []string) {
	phase := podcvm.PhaseStaged
	if a.staged == len(a.events) {
		phase = podcvm.PhaseRunning
	}
	return phase, append([]string(nil), a.events[:a.staged]...)
}

// workloadRunning reports whether commands and credentials have a workload to
// go to.
func (a *Agent) workloadRunning() bool {
	a.measured.RLock()
	defer a.measured.RUnlock()
	return a.admitted
}

// checkOwnImage refuses a document signed for another build: a launch key
// holder who pinned image A must not have that signature honoured by image B.
func checkOwnImage(self *teetypes.VerificationResult, image podcvm.Image) error {
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

// instanceProvider issues serving certificates over one in-memory key for the
// life of the agent, so the key a verifier attested stays the key it talks to.
type instanceProvider struct {
	key     *ecdsa.PrivateKey
	tee     TEE
	ttl     time.Duration
	sandbox string
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
	att, err := agratls.NewAttestation(env)
	if err != nil {
		return nil, 0, err
	}
	der, err := ratls.CreateAttestedCert(p.key, att, &ratls.CertOptions{
		Subject: pkix.Name{CommonName: "c8s pod CVM " + p.sandbox, Organization: []string{"Confidential"}},
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
