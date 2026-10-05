//go:build c8s_simtee

package session

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"path/filepath"
	"time"

	"github.com/google/go-tdx-guest/verify/trust"
)

// SimulatedVendor is whoever stands for the vendor's service to a verifier
// of a simulated TEE: it is asked for each document by the address that
// document has at the vendor's.
type SimulatedVendor interface {
	trust.HTTPSGetter
	trust.ContextHTTPSGetter
}

// NewSimulatedEngine is NewEngine for a TEE simulated in software
// (internal/simtee), in a build made for one: the second baseline of
// docs/session-performance.md. It holds evidence, and the vendor's documents
// evidence is judged by, to root in place of the vendor's own root, never
// beside it, and asks vendor for those documents in place of the vendor's
// service. Everything else is NewEngine's: the same checks, in the same
// order, at the same cost. An engine that asks nobody
// (EngineOptions.HandedCollateralOnly) takes no vendor.
//
// Such an engine refuses real evidence, as every other engine refuses a
// simulated TEE's, and says so in what scopes its verdicts.
func NewSimulatedEngine(opts EngineOptions, root *x509.Certificate, vendor SimulatedVendor) (Engine, error) {
	if root == nil {
		return nil, errors.New("a simulated TEE's verifier needs the simulated authority's root")
	}
	// The simulated authority's documents have the addresses of the vendor's
	// own. They are kept apart from those, and from another authority's.
	if opts.CollateralCacheDir != "" {
		of := sha256.Sum256(root.Raw)
		opts.CollateralCacheDir = filepath.Join(opts.CollateralCacheDir, "simulated-"+hex.EncodeToString(of[:8]))
	}
	engine, ok := NewEngine(opts).(*dcapEngine)
	if !ok {
		return nil, errors.New("the engine of this build takes no other authority")
	}
	engine.roots = x509.NewCertPool()
	engine.roots.AddCert(root)
	if _, none := engine.fetch.(noRoad); !none {
		if vendor == nil {
			return nil, errors.New("a simulated TEE's verifier needs whoever serves the simulated authority's documents")
		}
		engine.fetch = &trust.RetryHTTPSGetter{Timeout: 30 * time.Second, MaxRetryDelay: 5 * time.Second, Getter: vendor}
	}
	return engine, nil
}

// FetchSimulatedCollateral is FetchCollateral from whoever stands for the
// vendor's service: what the host of a simulated guest answers its guest's
// asks with.
func FetchSimulatedCollateral(ctx context.Context, vendor SimulatedVendor, p CollateralPlatform) ([]CollateralDocument, error) {
	return fetchCollateral(ctx, vendor, p)
}
