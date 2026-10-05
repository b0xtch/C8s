//go:build linux

package sessionlauncher

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/keyservice/keyservicetest"
	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/internal/vsock"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	api "github.com/confidential-dot-ai/c8s/pkg/session/keyservice"
	"github.com/confidential-dot-ai/c8s/pkg/session/sessionsim"
)

// vsockRelay runs a launcher's relay for the guest with this context id, in
// front of an echo service.
func vsockRelay(t *testing.T, cid uint32) (port uint32, taken func() int32) {
	t.Helper()
	service, count := echoService(t)
	r, port, err := keyServiceRelay(&session.KeyService{URL: "https://" + service}, cid, quiet)
	if err != nil {
		t.Skipf("no vsock here: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return port, count.Load
}

// The kernel's loopback transport stands in for a guest: its connections come
// as context id 1.
func TestKeyServiceRelayCarriesItsGuestOverVsock(t *testing.T) {
	port, taken := vsockRelay(t, vsock.LocalCID)
	conn, err := vsock.Dial(vsock.LocalCID, port)
	if err != nil {
		t.Skipf("no vsock loopback transport here: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if !carried(conn) {
		t.Fatal("nothing came back through the relay")
	}
	if taken() != 1 {
		t.Fatalf("the service took %d connections, want 1", taken())
	}
}

// The relay's port is the host's, and every guest on the host reaches it. A
// connection under another context id is closed, and the key service never
// sees it.
func TestKeyServiceRelayRefusesAnotherGuest(t *testing.T) {
	port, taken := vsockRelay(t, 70000)
	conn, err := vsock.Dial(vsock.LocalCID, port)
	if err != nil {
		t.Skipf("no vsock loopback transport here: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if !ended(conn) {
		t.Fatal("another guest's connection was not closed")
	}
	if taken() != 0 {
		t.Fatal("another guest's connection reached the key service")
	}
}

var relayPortRE = regexp.MustCompile(`"key_service_port":([0-9]+)`)

// A guest whose launch document pins a key service is told the port its
// launcher carries the connection on. One whose document pins none, or that
// has no vsock device, is told none.
func TestRunTellsTheGuestItsRelayPort(t *testing.T) {
	if ln, err := vsock.Listen(vsock.AnyPort, 1); err != nil {
		t.Skipf("no vsock here: %v", err)
	} else {
		_ = ln.Close()
	}
	pinned := func(t *testing.T, cfg *Config) {
		td := sessiontest.NewTD()
		bundle := filepath.Join(t.TempDir(), "bundle")
		if err := session.NewBundle(session.BundleOptions{
			Dir: bundle, ManifestPath: td.WriteManifest(t), Pool: "agents", Class: "s-4x16",
			KeyService: keyservicetest.New(t, sessionsim.NewPool(t)).Pin,
		}); err != nil {
			t.Fatal(err)
		}
		cfg.LaunchDir = filepath.Join(bundle, session.OpkeyDir)
	}
	for name, tc := range map[string]struct {
		prepare func(*testing.T, *Config)
		relayed bool
	}{
		"a pinned key service and a vsock device": {func(t *testing.T, cfg *Config) { pinned(t, cfg); cfg.VsockCID = 7 }, true},
		"a pinned key service and no vsock":       {pinned, false},
		"no key service":                          {func(_ *testing.T, cfg *Config) { cfg.VsockCID = 7 }, false},
	} {
		t.Run(name, func(t *testing.T) {
			qemu, record := fakeQEMU(t, "exec sleep 30")
			cfg := launchConfig(t, qemu)
			tc.prepare(t, &cfg)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- Run(ctx, cfg, quiet) }()
			defer func() {
				cancel()
				<-done
			}()
			waitFor(t, filepath.Join(record, "fd9"), done)
			// A launch disk stores its files as they are, so host.json is
			// read out of the image with no tool.
			disk, err := os.ReadFile(filepath.Join(record, "opkey.iso"))
			if err != nil {
				t.Fatal(err)
			}
			told := relayPortRE.FindSubmatch(disk)
			if (told != nil) != tc.relayed {
				t.Fatalf("the guest was told %s", told)
			}
			if !tc.relayed {
				return
			}
			port, err := strconv.ParseUint(string(told[1]), 10, 32)
			if err != nil || port == 0 {
				t.Fatalf("the guest was told relay port %s", told[1])
			}
			// The port is one the launcher listens on while the guest runs.
			conn, err := vsock.Dial(vsock.LocalCID, uint32(port))
			if err != nil {
				t.Skipf("no vsock loopback transport here: %v", err)
			}
			_ = conn.Close()
		})
	}
}

// A guest with no network device serves on a port of its socket to the
// host, and its launcher publishes that port on a TCP port of the host:
// whoever reaches the host's port reaches the guest's. The kernel's loopback
// transport stands in for the guest.
func TestPublishedPortCarriesToTheGuestsSocket(t *testing.T) {
	guest, err := vsock.Listen(vsock.AnyPort, 8)
	if err != nil {
		t.Skipf("no vsock here: %v", err)
	}
	defer guest.Close()
	go func() {
		for {
			conn, err := guest.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	if probe, err := vsock.Dial(vsock.LocalCID, guest.Port()); err != nil {
		t.Skipf("no vsock loopback transport here: %v", err)
	} else {
		_ = probe.Close()
	}
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	_ = free.Close()

	publisher, err := publishRelay(Forward{Address: "127.0.0.1", Host: port, Guest: int(guest.Port())}, vsock.LocalCID, quiet)
	if err != nil {
		t.Fatal(err)
	}
	if publisher.slots != published {
		t.Fatalf("a published port carries %d connections at a time, want %d", publisher.slots, published)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		publisher.run(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()
	for range 3 {
		conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if !carried(conn) {
			t.Fatal("nothing came back from the guest's port")
		}
		_ = conn.Close()
	}

	// A port the guest does not serve yet: the connection ends, and the
	// next one is tried anew.
	idle, err := publishRelay(Forward{Address: "127.0.0.1", Host: 0, Guest: 1}, vsock.LocalCID, quiet)
	if err != nil {
		t.Fatal(err)
	}
	idleDone := make(chan struct{})
	go func() {
		defer close(idleDone)
		idle.run(ctx)
	}()
	defer func() {
		cancel()
		<-idleDone
	}()
	conn, err := net.Dial("tcp", idle.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if !ended(conn) {
		t.Fatal("a connection to a port the guest does not serve was kept")
	}
}

// A key service replica's launcher carries the replica's connections to the
// vendor's service, and nobody else's: the port is the host's, and every
// guest on the host reaches it.
func TestVendorRelayCarriesItsGuestToTheVendor(t *testing.T) {
	service, count := echoService(t)
	run := func(cid uint32) uint32 {
		t.Helper()
		road, port, err := vendorRelay(service, cid, quiet)
		if err != nil {
			t.Skipf("no vsock here: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			road.run(ctx)
		}()
		t.Cleanup(func() {
			cancel()
			<-done
		})
		return port
	}
	conn, err := vsock.Dial(vsock.LocalCID, run(vsock.LocalCID))
	if err != nil {
		t.Skipf("no vsock loopback transport here: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if !carried(conn) || count.Load() != 1 {
		t.Fatalf("the guest's connection did not reach the vendor's service (%d taken)", count.Load())
	}
	other, err := vsock.Dial(vsock.LocalCID, run(70000))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	_ = other.SetDeadline(time.Now().Add(10 * time.Second))
	if !ended(other) || count.Load() != 1 {
		t.Fatal("another guest's connection reached the vendor's service")
	}
}

var vendorPortsRE = regexp.MustCompile(`"vendor_ports":\{[^}]*\}`)

// A key service replica is told the ports its launcher carries its
// connections to the vendor's services on, one for each service, and with no
// network device its launcher publishes the port it serves. A session
// guest's launcher names no road to the vendor: such a guest asks its host
// for the vendor's documents, and judges by nothing it could not check.
func TestRunGivesAReplicaItsRoads(t *testing.T) {
	if ln, err := vsock.Listen(vsock.AnyPort, 1); err != nil {
		t.Skipf("no vsock here: %v", err)
	} else {
		_ = ln.Close()
	}
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	_ = free.Close()
	launch := func(t *testing.T, prepare func(*Config)) ([]byte, func()) {
		t.Helper()
		qemu, record := fakeQEMU(t, "exec sleep 30")
		cfg := launchConfig(t, qemu)
		cfg.Network, cfg.VsockCID = NetworkNone, 7
		cfg.Forwards = []Forward{{Address: "127.0.0.1", Host: port, Guest: 8443}}
		prepare(&cfg)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- Run(ctx, cfg, quiet) }()
		stop := func() {
			cancel()
			<-done
		}
		waitFor(t, filepath.Join(record, "fd9"), done)
		disk, err := os.ReadFile(filepath.Join(record, "opkey.iso"))
		if err != nil {
			stop()
			t.Fatal(err)
		}
		args, _ := os.ReadFile(filepath.Join(record, "args"))
		if strings.Contains(string(args), "-netdev") {
			stop()
			t.Fatalf("a guest with no network device was given one:\n%s", args)
		}
		return disk, stop
	}

	disk, stop := launch(t, func(cfg *Config) {
		cfg.LaunchDir = filepath.Join(keyservicetest.New(t, sessionsim.NewPool(t)).Bundle, session.OpkeyDir)
	})
	told := vendorPortsRE.Find(disk)
	if told == nil {
		stop()
		t.Fatal("a replica was told no road to the vendor's services")
	}
	host, err := session.ParseHostConfig(append(append([]byte("{"), told...), '}'))
	if err != nil {
		stop()
		t.Fatalf("the replica's roads %s: %v", told, err)
	}
	services, err := session.VendorServices("tdx")
	if err != nil {
		t.Fatal(err)
	}
	if len(host.VendorPorts) != len(services) {
		stop()
		t.Fatalf("the replica was told %v, want a road to each of %v", host.VendorPorts, services)
	}
	seen := map[uint32]bool{}
	for _, service := range services {
		at := host.VendorPorts[service]
		if at == 0 || seen[at] {
			stop()
			t.Fatalf("the replica's road to %s is port %d of %v", service, at, host.VendorPorts)
		}
		seen[at] = true
		// The launcher listens there while the guest runs.
		if conn, err := vsock.Dial(vsock.LocalCID, at); err == nil {
			_ = conn.Close()
		}
	}
	// The published port is the host's while the guest runs. Nothing
	// serves the guest's side here, so a connection to it ends.
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		stop()
		t.Fatalf("the replica's port is not published: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if !ended(conn) {
		t.Error("a connection to a guest that serves nothing was kept")
	}
	_ = conn.Close()
	stop()
	// And it is nobody's once the guest is gone.
	if conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err == nil {
		_ = conn.Close()
		t.Fatal("the replica's port is still published after its guest ended")
	}

	disk, stop = launch(t, func(*Config) {})
	defer stop()
	if told := vendorPortsRE.Find(disk); told != nil {
		t.Fatalf("a session guest was told a road to the vendor's services: %s", told)
	}
}

// A replica with no network device is reached through the port its launcher
// publishes: an owner's client verifies it and registers a tenant there as it
// would at an address of the replica's own, on one connection that the
// launcher carries to the replica's socket.
func TestReplicaIsReachedThroughItsPublishedPort(t *testing.T) {
	guest, err := vsock.Listen(vsock.AnyPort, 16)
	if err != nil {
		t.Skipf("no vsock here: %v", err)
	}
	if probe, err := vsock.Dial(vsock.LocalCID, guest.Port()); err != nil {
		_ = guest.Close()
		t.Skipf("no vsock loopback transport here: %v", err)
	} else {
		_ = probe.Close()
	}
	sim := keyservicetest.New(t, sessionsim.NewPool(t))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = sim.Service.Serve(ctx, guest)
	}()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	_ = free.Close()
	publisher, err := publishRelay(Forward{Address: "127.0.0.1", Host: port, Guest: int(guest.Port())}, vsock.LocalCID, quiet)
	if err != nil {
		t.Fatal(err)
	}
	carried := make(chan struct{})
	go func() {
		defer close(carried)
		publisher.run(ctx)
	}()
	defer func() {
		cancel()
		<-carried
		<-served
	}()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := session.PublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	published := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	client, err := api.NewClient(api.Options{
		Pin: sim.Pin, Engine: sessiontest.Engine{},
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, published)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.RegisterAuthority(ctx, "acme", authority, signer); err != nil {
		t.Fatalf("register a tenant through the published port: %v", err)
	}
	if err := client.PutCredential(ctx, "acme", "api-token", []byte("a stored secret"), signer); err != nil {
		t.Fatalf("store a credential through the published port: %v", err)
	}
}
