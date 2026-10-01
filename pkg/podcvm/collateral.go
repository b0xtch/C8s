package podcvm

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/go-tdx-guest/verify/trust"
)

// collateralTTL is how long one fetched Intel PCS response is reused. TCB info
// and CRLs are reissued on a scale of days; this only keeps a burst of
// verifications from fetching the same four documents each time.
const collateralTTL = 5 * time.Minute

// collateralCache holds Intel PCS responses that carried a verification to
// success, for the life of an engine. One attestation is verified twice, the
// serving certificate and then the fresh evidence, and both need the same TCB
// info, QE identity and CRLs.
type collateralCache struct {
	now func() time.Time

	mu      sync.Mutex
	entries map[string]collateralEntry
}

type collateralEntry struct {
	header  map[string][]string
	body    []byte
	fetched time.Time
}

func newCollateralCache() *collateralCache {
	return &collateralCache{now: time.Now, entries: map[string]collateralEntry{}}
}

func (c *collateralCache) lookup(url string) (collateralEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[url]
	if !ok || c.now().Sub(entry.fetched) >= collateralTTL {
		return collateralEntry{}, false
	}
	return entry, true
}

func (c *collateralCache) store(url string, entry collateralEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[url] = entry
}

// fetchRecorder serves one verification's collateral: from the cache when it
// can, from Intel PCS otherwise. It notes which fetches failed, because
// go-tdx-guest flattens fetch errors into text and their type is gone by the
// time the verification error comes back. It holds what it fetched until the
// verification succeeds, so a response that parsed badly is never cached.
type fetchRecorder struct {
	cache *collateralCache
	inner trust.HTTPSGetter

	mu      sync.Mutex
	failed  []string
	fetched map[string]collateralEntry
}

func (r *fetchRecorder) Get(url string) (map[string][]string, []byte, error) {
	return r.GetContext(context.Background(), url)
}

func (r *fetchRecorder) GetContext(ctx context.Context, url string) (map[string][]string, []byte, error) {
	if entry, ok := r.cache.lookup(url); ok {
		return entry.header, entry.body, nil
	}
	header, body, err := trust.GetWith(ctx, r.inner, url)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		// The URL makes the message specific enough to recognise later.
		err = fmt.Errorf("fetch %s: %w", url, err)
		r.failed = append(r.failed, err.Error())
		return nil, nil, err
	}
	if r.fetched == nil {
		r.fetched = map[string]collateralEntry{}
	}
	r.fetched[url] = collateralEntry{header: header, body: body, fetched: r.cache.now()}
	return header, body, nil
}

// caused reports whether err stems from a fetch this recorder saw fail.
func (r *fetchRecorder) caused(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, failure := range r.failed {
		if strings.Contains(msg, failure) {
			return true
		}
	}
	return false
}

// commit publishes this verification's fetches to the shared cache.
func (r *fetchRecorder) commit() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for url, entry := range r.fetched {
		r.cache.store(url, entry)
	}
}
