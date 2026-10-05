// Package sessiondtest runs the session daemon over simulated guests, for the
// tests of the daemon and of the programs that drive sessions through it.
//
// The daemon and the agents are the real ones. The trust domains are
// pkg/session/sessionsim's, so nothing here says anything about real silicon.
package sessiondtest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/keyservice/keyservicetest"
	"github.com/confidential-dot-ai/c8s/internal/sessiond"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/daemon"
	"github.com/confidential-dot-ai/c8s/pkg/session/sessionsim"
)

// Pool is the name of the host's one pool.
const Pool = "sim"

// Runner boots simulated guests: each TD is a twin of the pool's first guest.
// It stands for the host, and so outlives a daemon: a later daemon adopts
// what it started.
type Runner struct {
	t     testing.TB
	first *sessionsim.Guest
	// sandbox is what the TDs run from the image a bind names. Nil is a pool
	// of bare guests, whose binds name none.
	sandbox sessionsim.Sandbox

	mu      sync.Mutex
	started []*TD
	fail    error
}

// TD is one simulated guest, as the daemon holds it.
type TD struct {
	guest  *sessionsim.Guest
	handle sessiond.Handle
	done   chan struct{}
	stop   sync.Once
}

func (i *TD) Address() string { return strings.TrimPrefix(i.guest.URL, "https://") }

// Accepted is how many connections the TD's guest has accepted, and Asked
// how many requests it was sent for a path, or for any when path is empty.
func (i *TD) Accepted() int         { return i.guest.Accepted() }
func (i *TD) Asked(path string) int { return i.guest.Asked(path) }

// Logged is how many times the TD's guest logged message.
func (i *TD) Logged(message string) int { return i.guest.Logged(message) }

// Cut closes every connection the TD's guest has accepted so far.
func (i *TD) Cut() { i.guest.Cut() }

func (i *TD) Handle() sessiond.Handle { return i.handle }
func (i *TD) Done() <-chan struct{}   { return i.done }

// Stop ends the guest, as a host ends a TD and as a guest ends on its own.
func (i *TD) Stop() {
	i.stop.Do(func() {
		i.guest.Close()
		close(i.done)
	})
}

func (r *Runner) Start(context.Context, sessiond.Spec) (sessiond.Instance, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return nil, r.fail
	}
	td := &TD{guest: r.first.Twin(r.t, r.sandbox), done: make(chan struct{})}
	td.handle = sessiond.Handle{PID: 1000 + len(r.started), Start: 1}
	r.started = append(r.started, td)
	return td, nil
}

func (r *Runner) Adopt(_ sessiond.Spec, handle sessiond.Handle) (sessiond.Instance, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, td := range r.started {
		if td.handle == handle {
			select {
			case <-td.done:
				return nil, errors.New("its process is gone")
			default:
				return td, nil
			}
		}
	}
	return nil, errors.New("no such process")
}

// Booted is how many TDs the runner has started.
func (r *Runner) Booted() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.started)
}

// Last is the TD the runner started last.
func (r *Runner) Last() *TD {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.started[len(r.started)-1]
}

// All is every TD the runner started.
func (r *Runner) All() []*TD {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*TD(nil), r.started...)
}

// Fail makes every boot from now on fail with err. Nil lets them succeed.
func (r *Runner) Fail(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fail = err
}

// Host is a host with a daemon on it.
type Host struct {
	Config *sessiond.Config
	Runner *Runner
	// Daemon is the running daemon, and Addr where it serves.
	Daemon *sessiond.Daemon
	Addr   string
	// Roots verify the daemon's certificate, and CAFile holds them as PEM.
	Roots  *x509.CertPool
	CAFile string
	// Orchestrator is a certificate the daemon takes claims under, with its
	// files: the pool's configuration names it as a binder. Other is one of
	// the same authority that no pool names, and Ended one of that authority
	// whose time is over. Stranger is one of an authority the daemon does
	// not know. Binder is one of its holder's own making, which nobody
	// signed: the pool's configuration names its key as a binder's.
	Orchestrator         tls.Certificate
	OrchestratorCertFile string
	OrchestratorKeyFile  string
	Other                tls.Certificate
	Ended                tls.Certificate
	Stranger             tls.Certificate
	Binder               tls.Certificate

	// What a binder pins: the image, with its manifest, and the pool's
	// launch key, with its file.
	Identity      runtimemeasure.ImageIdentity
	ManifestPath  string
	LaunchKey     []byte
	LaunchKeyPath string
	// Engine verifies the simulated evidence.
	Engine session.Engine
	// KeyService is the key service the pool's launch document pins, on a
	// host made with one.
	KeyService *keyservicetest.Sim

	t    testing.TB
	stop func()
}

// NewHost is a host whose one pool keeps depth TDs ready, with its daemon
// running. mutate may change the daemon's configuration first.
func NewHost(t testing.TB, depth int, mutate func(*sessiond.Config)) *Host {
	t.Helper()
	return newHost(t, depth, mutate, false, nil)
}

// NewHostWithSandbox is NewHost for a pool whose guests run sandbox from the
// image a bind names, and take no bind that names none.
func NewHostWithSandbox(t testing.TB, depth int, sandbox sessionsim.Sandbox) *Host {
	t.Helper()
	return newHost(t, depth, nil, false, sandbox)
}

// NewHostWithKeyService is NewHost for a pool whose launch document pins a
// key service, which runs beside the host.
func NewHostWithKeyService(t testing.TB, depth int, mutate func(*sessiond.Config)) *Host {
	t.Helper()
	return newHost(t, depth, mutate, true, nil)
}

func newHost(t testing.TB, depth int, mutate func(*sessiond.Config), keyService bool, sandbox sessionsim.Sandbox) *Host {
	t.Helper()
	pool := sessionsim.NewPool(t)
	var service *keyservicetest.Sim
	var pin *session.KeyService
	if keyService {
		service = keyservicetest.New(t, pool)
		pin = service.Pin
	}
	first := pool.Boot(t, nil, pin)
	h := &Host{
		t: t, Runner: &Runner{t: t, first: first, sandbox: sandbox}, Engine: sessionsim.Engine(), KeyService: service,
		ManifestPath: first.ManifestPath, LaunchKeyPath: first.LaunchKeyPath,
	}
	var err error
	if h.Identity, err = runtimemeasure.LoadImageManifest(first.ManifestPath); err != nil {
		t.Fatal(err)
	}
	if h.LaunchKey, err = os.ReadFile(first.LaunchKeyPath); err != nil {
		t.Fatal(err)
	}
	dir := h.pki()
	var binders []sessiond.Binder
	for _, cert := range []*tls.Certificate{&h.Orchestrator, &h.Binder} {
		binder, err := daemon.BinderName(cert.Leaf)
		if err != nil {
			t.Fatal(err)
		}
		binders = append(binders, sessiond.Binder{Key: binder})
	}
	h.Config = &sessiond.Config{
		Listen: "127.0.0.1:0", Host: "host-a", StateDir: t.TempDir(), Capacity: 4,
		TLS: sessiond.TLSConfig{
			Cert: filepath.Join(dir, "server.pem"), Key: filepath.Join(dir, "server.key"), ClientCA: h.CAFile,
		},
		Network: sessiond.Network{Mode: sessiond.NetworkUser, FirstPort: 20000},
		Classes: map[string]sessiond.Class{"sim": {VCPUs: 1, Memory: "1G"}},
		Pools: []sessiond.Pool{{
			ImageDir: t.TempDir(), LaunchDir: filepath.Dir(first.LaunchKeyPath), Depth: depth,
			BindGrace: sessiond.Duration(time.Second), Binders: binders,
		}},
	}
	if mutate != nil {
		mutate(h.Config)
	}
	if err := h.Config.Validate(); err != nil {
		t.Fatal(err)
	}
	h.StartDaemon()
	return h
}

// pki makes the daemon's certificate and the orchestrators' authority, and
// returns the directory that holds their files.
func (h *Host) pki() string {
	h.t.Helper()
	ends := time.Now().Add(time.Hour)
	issue := func(name string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (tls.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			h.t.Fatal(err)
		}
		serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
		if err != nil {
			h.t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: serial, Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: ends,
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		}
		if parent == nil {
			// An authority, which signs itself.
			template.IsCA, template.BasicConstraintsValid, template.KeyUsage = true, true, x509.KeyUsageCertSign
			parent, parentKey = template, key
		}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
		if err != nil {
			h.t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			h.t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, cert, key
	}
	keyPEM := func(key *ecdsa.PrivateKey) []byte {
		data, err := certutil.MarshalECKeyPEM(key)
		if err != nil {
			h.t.Fatal(err)
		}
		return data
	}
	certPEM := func(cert tls.Certificate) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	}
	authority, ca, caKey := issue("test authority", nil, nil)
	server, _, serverKey := issue("daemon", ca, caKey)
	var orchestratorKey *ecdsa.PrivateKey
	h.Orchestrator, _, orchestratorKey = issue("orchestrator", ca, caKey)
	h.Other, _, _ = issue("another orchestrator", ca, caKey)
	ends = time.Now().Add(-time.Minute)
	h.Ended, _, _ = issue("an orchestrator of before", ca, caKey)
	ends = time.Now().Add(time.Hour)
	_, other, otherKey := issue("another authority", nil, nil)
	h.Stranger, _, _ = issue("stranger", other, otherKey)
	h.Binder, _, _ = issue("a binder of its own making", nil, nil)
	h.Roots = x509.NewCertPool()
	h.Roots.AddCert(ca)

	dir := h.t.TempDir()
	h.CAFile = filepath.Join(dir, "ca.pem")
	h.OrchestratorCertFile, h.OrchestratorKeyFile = filepath.Join(dir, "orchestrator.pem"), filepath.Join(dir, "orchestrator.key")
	for path, data := range map[string][]byte{
		h.CAFile:                         certPEM(authority),
		filepath.Join(dir, "server.pem"): certPEM(server),
		filepath.Join(dir, "server.key"): keyPEM(serverKey),
		h.OrchestratorCertFile:           certPEM(h.Orchestrator),
		h.OrchestratorKeyFile:            keyPEM(orchestratorKey),
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			h.t.Fatal(err)
		}
	}
	return dir
}

// StartDaemon runs a daemon over the host's state, as a restart does after
// Stop. The host's TDs were never its to end.
func (h *Host) StartDaemon() {
	h.t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		h.t.Fatal(err)
	}
	d := sessiond.New(h.Config, h.Runner, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := d.Run(ctx); err != nil {
			h.t.Errorf("daemon: %v", err)
		}
	})
	wg.Go(func() {
		if err := d.Serve(ctx, ln); err != nil {
			h.t.Errorf("serve: %v", err)
		}
	})
	h.Daemon, h.Addr = d, ln.Addr().String()
	h.stop = sync.OnceFunc(func() {
		cancel()
		wg.Wait()
	})
	h.t.Cleanup(h.stop)
}

// Stop ends the daemon. Its TDs run on.
func (h *Host) Stop() { h.stop() }

// Client reaches the daemon, under cert when it is not nil.
func (h *Host) Client(cert *tls.Certificate) *daemon.Client {
	h.t.Helper()
	c, err := daemon.Dial(daemon.Options{Address: h.Addr, RootCAs: h.Roots, Certificate: cert})
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { _ = c.Close() })
	return c
}

// AsOrchestrator reaches the daemon under the orchestrator's certificate.
func (h *Host) AsOrchestrator() *daemon.Client { return h.Client(&h.Orchestrator) }
