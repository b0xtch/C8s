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
	// Pin is what a pool's launch document and an owner's bind pin of it,
	// and Members what a bind names as its replicas: this one.
	Pin     *session.KeyService
	Members []string
	// Bundle is its launch bundle directory.
	Bundle string
	// Service is the replica itself.
	Service *keyservice.Service
	// Machine is what the replica's RTMR[0] holds.
	Machine [48]byte

	// addr is where this replica listens, and the rest what a twin is made
	// from: the image's registers as they are before a launch is measured
	// into them, the launch document and its options.
	addr      string
	image     registers
	launch    []byte
	signature string
	pub       []byte
	with      Options
}

// registers are what an image measures to, in any TD that boots it.
type registers struct {
	mrtd [48]byte
	rtmr [3][48]byte
}

func registersOf(td *sessiontest.TD) registers {
	return registers{mrtd: td.MRTD, rtmr: [3][48]byte{td.RTMR[0], td.RTMR[1], td.RTMR[2]}}
}

// Dial is a road to this replica whatever address is asked for: what a test
// gives a client or a pool whose pin names another replica's address.
func (s *Sim) Dial(ctx context.Context, network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, s.addr)
}

// Twin boots another replica of the same key service: the same image, under
// the same launch document, with an instance key of its own, and nothing of
// what the first holds. Its pin is the first's, which names the first's
// address, so a connection is led to the twin by its Dial.
func (s *Sim) Twin(t testing.TB) *Sim {
	t.Helper()
	td := sessiontest.NewTD()
	td.MRTD, td.RTMR[0], td.RTMR[1], td.RTMR[2] = s.image.mrtd, s.image.rtmr[0], s.image.rtmr[1], s.image.rtmr[2]
	twin := serve(t, td, s.launch, s.signature, s.pub, s.with)
	twin.Pin, twin.Bundle = s.Pin, s.Bundle
	return twin
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
	sim := serve(t, td, launch, string(signature), pub, with)
	sim.Bundle = opts.Dir
	pin, err := api.Pin(opts.Dir, "https://"+sim.addr)
	if err != nil {
		t.Fatal(err)
	}
	sim.Pin = pin
	return sim
}

// serve boots one replica in td under the launch document and serves it on
// loopback until the test ends.
func serve(t testing.TB, td *sessiontest.TD, launch []byte, signature string, pub []byte, with Options) *Sim {
	t.Helper()
	image := registersOf(td)
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
		Launch: launch, Signature: signature, LaunchKey: pub,
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
	return &Sim{
		Members: []string{service.Replica()}, Service: service, Machine: td.RTMR[0],
		addr: ln.Addr().String(), image: image, launch: launch, signature: signature, pub: pub, with: with,
	}
}
