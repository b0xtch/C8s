// Package sessionsim serves a session guest's agent over a simulated trust
// domain, for the tests of programs that drive guests through pkg/session.
//
// The agent is the real one, with its documents, its measurements and its
// API. The hardware is not: the registers extend the way TDX's do and the
// evidence binds REPORTDATA, and only Engine accepts it. Nothing here says
// anything about real silicon, and nothing but a test has a use for it.
package sessionsim

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// Sandbox stands for what a guest runs from the image a bind names.
type Sandbox interface {
	// Start runs it, as the guest starts a sandbox once it has measured the
	// image. credentialDir is where credentials released to the guest appear:
	// the directory a real sandbox finds in C8S_CREDENTIALS_DIR. ctx ends
	// with the test.
	Start(ctx context.Context, image *session.Sandbox, credentialDir string) error
	// Dial connects to one of its ports, as the agent does on the loopback of
	// a real sandbox's network namespace.
	Dial(ctx context.Context, port int) (net.Conn, error)
}

// Guest is one guest that nobody has bound, served on loopback.
type Guest struct {
	// URL is the agent's address: https://127.0.0.1:<port>.
	URL string
	// ManifestPath is the simulated image's manifest.json, and LaunchKeyPath
	// the pool's public launch key: what a binder pins before it binds.
	ManifestPath  string
	LaunchKeyPath string

	// td is the simulated hardware, and launchKey the pool's private launch
	// key: what a twin is made from.
	td        *sessiontest.TD
	launchKey string
	// pinned: the launch document lists the machine the guest runs on.
	pinned bool
	// stop ends the guest.
	stop func()
}

// Close ends the guest before its test does, as a host ends a guest: its
// agent serves nothing more, and its connections are cut.
func (p *Guest) Close() { p.stop() }

// Engine verifies the simulated evidence. A test passes it where production
// passes the engine of session.NewEngine.
func Engine() session.Engine { return sessiontest.Engine{} }

// EngineWithRootCRL is Engine with a finding in each verdict, which says
// the root CA CRL under it was fetched at fetched(). Asked to fetch the CRL
// anew, for session.Client.Renew, it calls refetch.
func EngineWithRootCRL(fetched func() time.Time, refetch func(context.Context) error) session.Engine {
	return rootCRLEngine{fetched: fetched, refetch: refetch}
}

type rootCRLEngine struct {
	sessiontest.Engine
	fetched func() time.Time
	refetch func(context.Context) error
}

func (e rootCRLEngine) VerifyEvidence(ctx context.Context, env teetypes.AttestationEvidence, reportData []byte) (*teetypes.VerificationResult, error) {
	res, err := e.Engine.VerifyEvidence(ctx, env, reportData)
	if err != nil {
		return nil, err
	}
	if res.Claims.PlatformData == nil {
		res.Claims.PlatformData = map[string]any{}
	}
	res.Claims.PlatformData[session.CollateralClaim] = &session.CollateralFinding{RootCRLFetched: e.fetched()}
	return res, nil
}

func (e rootCRLEngine) Refetch(ctx context.Context) error { return e.refetch(ctx) }

// NewGuest boots a guest and serves its agent until the test ends. A bind
// that names an image starts sandbox, and one that names none is refused, as
// a guest image for sessions refuses it. With a nil sandbox the guest is a
// bare one: a bind names no image, and its commands run as the test's own
// processes.
//
// Each call is a pool of its own: another image and another launch key. Twin
// is a second guest of the same pool.
func NewGuest(t testing.TB, sandbox Sandbox) *Guest {
	t.Helper()
	td := sessiontest.NewTD()
	return boot(t, td, td.WriteManifest(t), "", sandbox, false)
}

// NewPinnedGuest is NewGuest in a pool whose launch document lists the
// machine its guests run on, which a verifier that requires a pinned machine
// accepts.
func NewPinnedGuest(t testing.TB, sandbox Sandbox) *Guest {
	t.Helper()
	td := sessiontest.NewTD()
	return boot(t, td, td.WriteManifest(t), "", sandbox, true)
}

// Twin boots another guest of the same pool: the same image, launched under
// the same launch key, with an instance key of its own. A verifier that pins
// the pool accepts either. One that pins a guest's bind accepts that guest
// alone.
func (p *Guest) Twin(t testing.TB, sandbox Sandbox) *Guest {
	t.Helper()
	td := sessiontest.NewTD()
	td.MRTD, td.RTMR[0], td.RTMR[1], td.RTMR[2] = p.td.MRTD, p.td.RTMR[0], p.td.RTMR[1], p.td.RTMR[2]
	return boot(t, td, p.ManifestPath, p.launchKey, sandbox, p.pinned)
}

// boot launches one guest under launchKey, or under a new key when that is
// empty, and serves its agent.
func boot(t testing.TB, td *sessiontest.TD, manifest, launchKey string, sandbox Sandbox, pinned bool) *Guest {
	t.Helper()
	bundle := filepath.Join(t.TempDir(), "bundle")
	opts := session.BundleOptions{Dir: bundle, ManifestPath: manifest, Pool: "sim", Class: "sim", KeyPath: launchKey}
	if pinned {
		opts.Machines = []string{hex.EncodeToString(td.RTMR[0][:])}
	}
	if err := session.NewBundle(opts); err != nil {
		t.Fatal(err)
	}
	if launchKey == "" {
		launchKey = filepath.Join(bundle, session.BundleKeyFile)
	}
	loaded, err := session.LoadBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	// What the measured initrd does with the launch key.
	td.SeedLaunchKey(loaded.LaunchKey)

	credentials := filepath.Join(t.TempDir(), "credentials")
	process, err := sessionagent.NewProcessRunner(sessionagent.RunnerConfig{UID: -1, GID: -1, Home: t.TempDir(), CredentialDir: credentials})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var runner sessionagent.Runner = process
	if sandbox != nil {
		runner = &simulated{ProcessRunner: process, sandbox: sandbox, ctx: ctx}
	}
	keys := filepath.Join(bundle, session.OpkeyDir)
	agent, err := sessionagent.Stage(ctx, sessionagent.Config{
		Platform: "tdx", PubkeyPath: filepath.Join(keys, session.PubkeyFile), LaunchDir: keys,
		CredentialDir: credentials, TEE: sessiontest.TEE{TD: td}, Runner: runner, Bare: sandbox == nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.WarmUp(ctx); err != nil {
		t.Fatal(err)
	}
	if err := agent.Admit(ctx); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := agent.Server()
	go func() { _ = agent.Serve(srv, ln) }()
	stop := sync.OnceFunc(func() {
		_ = srv.Close()
		cancel()
	})
	t.Cleanup(stop)
	return &Guest{
		URL: "https://" + ln.Addr().String(), ManifestPath: manifest, LaunchKeyPath: filepath.Join(keys, session.PubkeyFile),
		td: td, launchKey: launchKey, pinned: pinned, stop: stop,
	}
}

// simulated is the runner of a guest whose sandbox is the test's own.
type simulated struct {
	*sessionagent.ProcessRunner
	sandbox Sandbox
	// ctx ends with the test. A sandbox outlives the request that bound it.
	ctx   context.Context
	image *session.Sandbox
}

func (s *simulated) Prepare(_ context.Context, image *session.Sandbox, _ *session.Egress) error {
	s.image = image
	return nil
}

func (s *simulated) Start(_ context.Context, credentialDir string) error {
	if s.image == nil {
		return errors.New("no sandbox prepared")
	}
	return s.sandbox.Start(s.ctx, s.image, credentialDir)
}

func (s *simulated) Dial(ctx context.Context, port int) (net.Conn, error) {
	return s.sandbox.Dial(ctx, port)
}
