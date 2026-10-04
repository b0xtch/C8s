//go:build linux

package sessionlauncher

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/keyservice/keyservicetest"
	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/internal/vsock"
	"github.com/confidential-dot-ai/c8s/pkg/session"
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
