// Package keyservicetest runs a key service replica over a simulated trust
// domain, for the tests of the replica and of the guests and tools that use
// one. The replica is the real one. Nothing here says anything about real
// silicon.
package keyservicetest

import (
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/keyservice"
	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	api "github.com/confidential-dot-ai/c8s/pkg/session/keyservice"
	"github.com/confidential-dot-ai/c8s/pkg/session/sessionsim"
)

// Sim is a running key service that serves the pools it was made for.
type Sim struct {
	// Pin is what a pool's launch document and an owner's bind pin of it.
	Pin *session.KeyService
	// Bundle is its launch bundle directory.
	Bundle string
	// Service is the replica itself.
	Service *keyservice.Service
	// Machine is what the replica's RTMR[0] holds.
	Machine [48]byte
}

// Options change the key service New boots.
type Options struct {
	// Engine judges the guests' evidence. Nil is the test engine.
	Engine session.Engine
	// AcceptTCBStatus is what its launch document accepts of its pools'
	// guests besides UpToDate.
	AcceptTCBStatus []string
	// Unpinned boots it from a launch document that lists no machine: such
	// a key service serves its state and nothing else.
	Unpinned bool
	// Machines, when set, is what its launch document lists in place of the
	// machine it is: a replica a host built another machine than the
	// document's signer recorded.
	Machines []string
	// Now is the replica's clock. Nil is the system's.
	Now func() time.Time
}

// New boots a key service whose launch document lists pools, and serves it
// on loopback until the test ends.
func New(t testing.TB, pools ...*sessionsim.Pool) *Sim {
	t.Helper()
	return NewWith(t, Options{}, pools...)
}

// NewWith is New for a key service of these options.
func NewWith(t testing.TB, with Options, pools ...*sessionsim.Pool) *Sim {
	t.Helper()
	if with.Engine == nil {
		with.Engine = sessiontest.Engine{}
	}
	td := sessiontest.NewTD()
	opts := api.BundleOptions{Dir: filepath.Join(t.TempDir(), "key-service"), ManifestPath: td.WriteManifest(t)}
	switch {
	case with.Unpinned:
	case with.Machines != nil:
		opts.Machines = with.Machines
	default:
		opts.Machines = []string{hex.EncodeToString(td.RTMR[0][:])}
	}
	for _, pool := range pools {
		opts.Pools = append(opts.Pools, api.PoolOptions{
			ManifestPath: pool.ManifestPath, LaunchKeyPath: pool.LaunchKeyPath, AcceptTCBStatus: with.AcceptTCBStatus,
		})
	}
	if err := api.NewBundle(opts); err != nil {
		t.Fatal(err)
	}
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(opts.Dir, session.OpkeyDir, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	pub, launch, signature := read(session.PubkeyFile), read(session.DocumentFile), read(session.SignatureFile)
	// What the measured initrd does with the launch key, and the key service
	// with its launch document.
	td.SeedLaunchKey(pub)
	event := runtimemeasure.Event(session.DocumentDigest(launch))
	if err := td.Extend(event[:]); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	service, err := keyservice.New(ctx, keyservice.Config{
		Launch: launch, Signature: string(signature), LaunchKey: pub,
		TEE: sessiontest.TEE{TD: td}, Engine: with.Engine, Now: with.Now,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = service.Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	pin, err := api.Pin(opts.Dir, "https://"+ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return &Sim{Pin: pin, Bundle: opts.Dir, Service: service, Machine: td.RTMR[0]}
}
