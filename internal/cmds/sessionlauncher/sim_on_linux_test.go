//go:build linux && c8s_simtee

package sessionlauncher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/simtee"
	"github.com/confidential-dot-ai/c8s/internal/vsock"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// simulatedOver turns cfg into a guest whose TEE is simulated, with the
// authority's documents served at address.
func simulatedOver(t *testing.T, cfg *Config, address string) *simtee.Directory {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "authority")
	authority, err := simtee.NewDirectory(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, simtee.VendorFile), []byte(address+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Platform, cfg.sim.Dir = "tdx", dir
	if err := cfg.sim.open(cfg); err != nil {
		t.Fatal(err)
	}
	return authority
}

// Every road a simulated replica's launcher makes to one of the vendor's
// services leads to whoever serves the simulated authority's documents: a
// connection its guest opens on any of them arrives there, and nowhere else.
func TestSimulatedReplicasRoadsLeadToTheSimulatedVendor(t *testing.T) {
	service, count := echoService(t)
	var cfg Config
	simulatedOver(t, &cfg, service)
	roads, ports, err := vendorRoads(&cfg, vsock.LocalCID, quiet)
	if err != nil {
		t.Skipf("no vsock here: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{}, len(roads))
	for _, road := range roads {
		go func() {
			road.run(ctx)
			done <- struct{}{}
		}()
	}
	t.Cleanup(func() {
		cancel()
		for range roads {
			<-done
		}
	})
	services, err := session.VendorServices("tdx")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != len(services) || len(roads) != len(services) {
		t.Fatalf("roads to %v, and the vendor's services are %v", ports, services)
	}
	for i, name := range services {
		conn, err := vsock.Dial(vsock.LocalCID, ports[name])
		if err != nil {
			t.Skipf("no vsock loopback transport here: %v", err)
		}
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if !carried(conn) || count.Load() != int32(i+1) {
			t.Fatalf("the road named for %s did not reach the simulated vendor (%d taken)", name, count.Load())
		}
		_ = conn.Close()
	}
}

// A simulated guest's launcher answers its guest's asks with the simulated
// authority's documents, fetched from whoever serves them, and keeps them
// apart from the vendor's.
func TestSimulatedGuestsStockAsksTheSimulatedVendor(t *testing.T) {
	var asked atomic.Int64
	var vendor http.Handler
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		vendor.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	cfg := Config{CollateralCache: t.TempDir()}
	authority := simulatedOver(t, &cfg, strings.TrimPrefix(server.URL, "http://"))
	vendor = simtee.Handler(simtee.NewVendor(authority.Authority, time.Now))
	keeper, port, err := collateralStock(&cfg, vsock.LocalCID, quiet)
	if err != nil {
		t.Skipf("no vsock here: %v", err)
	}
	t.Cleanup(func() { _ = keeper.ln.Close() })
	if port == 0 || keeper.dir != filepath.Join(cfg.CollateralCache, "simulated") {
		t.Fatalf("the stock listens on port %d and keeps its documents in %s", port, keeper.dir)
	}
	docs, err := keeper.fetch(context.Background(), session.CollateralPlatform{FMSPC: simtee.FMSPC, CA: "platform"})
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 4 || asked.Load() != 4 {
		t.Fatalf("%d documents, and the simulated vendor was asked %d times", len(docs), asked.Load())
	}
}
