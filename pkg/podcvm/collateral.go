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

// cachingGetter memoizes successful collateral fetches for the life of an
// engine. One attestation is verified twice, the serving certificate and then
// the fresh evidence, and both need the same TCB info, QE identity and CRLs.
type cachingGetter struct {
	inner trust.HTTPSGetter
	now   func() time.Time

	mu      sync.Mutex
	entries map[string]collateralEntry
}

type collateralEntry struct {
	header  map[string][]string
	body    []byte
	fetched time.Time
}

// fetchRecorder notes the collateral fetches that failed during one
// verification. go-tdx-guest flattens fetch errors into text, so their type is
// gone by the time the verification error comes back; their message is not.
type fetchRecorder struct {
	inner trust.HTTPSGetter

	mu     sync.Mutex
	failed []string
}

func (r *fetchRecorder) Get(url string) (map[string][]string, []byte, error) {
	return r.GetContext(context.Background(), url)
}

func (r *fetchRecorder) GetContext(ctx context.Context, url string) (map[string][]string, []byte, error) {
	header, body, err := trust.GetWith(ctx, r.inner, url)
	if err != nil {
		// The URL makes the message specific enough to recognise later.
		err = fmt.Errorf("fetch %s: %w", url, err)
		r.mu.Lock()
		r.failed = append(r.failed, err.Error())
		r.mu.Unlock()
	}
	return header, body, err
}

// caused reports whether err stems from a fetch this recorder saw fail. A nil
// recorder saw none.
func (r *fetchRecorder) caused(err error) bool {
	if r == nil || err == nil {
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

func newCachingGetter(inner trust.HTTPSGetter) *cachingGetter {
	return &cachingGetter{inner: inner, now: time.Now, entries: map[string]collateralEntry{}}
}

func (g *cachingGetter) Get(url string) (map[string][]string, []byte, error) {
	return g.GetContext(context.Background(), url)
}

func (g *cachingGetter) GetContext(ctx context.Context, url string) (map[string][]string, []byte, error) {
	g.mu.Lock()
	entry, ok := g.entries[url]
	g.mu.Unlock()
	if ok && g.now().Sub(entry.fetched) < collateralTTL {
		return entry.header, entry.body, nil
	}
	header, body, err := trust.GetWith(ctx, g.inner, url)
	if err != nil {
		return nil, nil, err
	}
	g.mu.Lock()
	g.entries[url] = collateralEntry{header: header, body: body, fetched: g.now()}
	g.mu.Unlock()
	return header, body, nil
}
