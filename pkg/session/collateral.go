package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/go-tdx-guest/pcs"
	"github.com/google/go-tdx-guest/verify/trust"
)

// collateralTTL is how long one fetched Intel PCS response is reused. TCB info
// and CRLs are reissued on a scale of days and stay valid for thirty. An hour
// keeps the fetch, half a second and more, off nearly every verification, and
// a platform whose TCB Intel has just superseded is still seen within the
// hour.
const collateralTTL = time.Hour

// collateralRenewAfter is how old a document in use may get before the next
// one is fetched behind the verification that used it. A verifier that keeps
// verifying then never waits for Intel.
const collateralRenewAfter = 45 * time.Minute

// stapleWindow is how long after Intel signed a document a verifier takes it
// from somebody other than Intel. Intel signs its TCB info, its enclave
// identity and its PCK CRLs anew about once an hour, so the date it signs
// into each bounds its age whoever fetched it. A document a verifier fetched
// itself was signed up to an hour before and is reused for an hour, which is
// the same bound.
const stapleWindow = 2 * time.Hour

// minTCBEvaluation is the lowest TCB evaluation data number a TCB info or an
// enclave identity may carry: the one Intel's service answered with when this
// was written. Intel's service gives out no earlier one. Raise it with a
// release, to the number the service answers with by default and never to one
// it gives out only on request.
const minTCBEvaluation = 20

// maxCollateralFile bounds one cached response on disk: a document of
// maxCollateralBody, encoded, and its header.
const maxCollateralFile = 1 << 20

// flightTimeout bounds one fetch, whoever waits for it.
const flightTimeout = 45 * time.Second

// CollateralFinding is what a verdict on TDX evidence rests on besides the
// evidence: Intel's documents, and how this verifier came by them.
type CollateralFinding struct {
	// Fetched is when the oldest of Intel's documents behind this finding
	// left Intel: when this verifier fetched it or, for one somebody handed
	// over, when Intel signed it.
	Fetched time.Time `json:"fetched"`
	// Stapled: a document behind this finding was handed over by somebody
	// other than Intel, the guest's host for one. Intel signed each within
	// the two hours before.
	Stapled bool `json:"stapled,omitempty"`
	// RootCRLStapled: the root CA CRL was among them. Intel signs that one
	// once a year, so its dates do not show it is the last, and a newer one
	// that revokes a certificate under this finding would go unseen. The
	// engine rests only a verdict that releases nothing on it.
	RootCRLStapled bool `json:"root_crl_stapled,omitempty"`
	// RootCRLFetched is when this verifier had the root CA CRL from Intel:
	// the CRL's own dates do not say how old it is. A verdict stands no
	// longer than the reuse period after it: see stands. Zero when the CRL
	// was handed over.
	RootCRLFetched time.Time `json:"root_crl_fetched,omitzero"`
	// Stale: Intel could not be reached to renew a document past the reuse
	// period, and the finding rests on the one that was kept. Intel's own
	// date on it still held.
	Stale bool `json:"stale,omitempty"`
	// Expires is the earlier of Intel's next-update dates on the TCB info and
	// the quoting enclave identity: past it the finding has nothing under it.
	Expires time.Time `json:"expires"`
}

// CollateralDocument is one of Intel's documents as Intel's service answered
// for it: the URL asked, the body, and the response header that carries the
// chain the body is signed under. Intel signs each, so one is worth the same
// from whoever hands it over, and nothing in it is trusted until a
// verification has checked that signature.
type CollateralDocument struct {
	URL    string              `json:"url"`
	Header map[string][]string `json:"header,omitempty"`
	Body   []byte              `json:"body"`
}

// CollateralSource hands over Intel's documents as somebody other than Intel
// keeps them: a guest's host, for one. An engine asks it when a verification
// is short of a document, before it asks Intel.
type CollateralSource func(ctx context.Context) []CollateralDocument

type (
	collateralSourceKey struct{}
	stapledRootKey      struct{}
)

// WithCollateralSource returns a context under which an engine that is short
// of one of Intel's documents asks source for it first. What source hands
// over is held to Intel's signature like any other, to Intel's own date on
// it, and to the TCB evaluation the engine last had from Intel itself.
func WithCollateralSource(ctx context.Context, source CollateralSource) context.Context {
	return context.WithValue(ctx, collateralSourceKey{}, source)
}

// withStapledRoot marks a verification whose verdict releases nothing: it may
// rest on a root CA CRL from the context's source. Intel signs that one once
// a year, so its dates say nothing of whether a newer one is out, and a
// verdict that releases a secret needs one the verifier fetched itself.
func withStapledRoot(ctx context.Context) context.Context {
	return context.WithValue(ctx, stapledRootKey{}, true)
}

// collateralKind is which of Intel's documents a URL names.
type collateralKind int

const (
	// kindUndated is a document whose own dates do not bound its age: the
	// root CA CRL.
	kindUndated collateralKind = iota
	kindTCBInfo
	kindQEIdentity
	kindPCKCRL
)

func kindOf(url string) collateralKind {
	switch {
	case url == pcs.QeIdentityURL():
		return kindQEIdentity
	case strings.HasPrefix(url, pcs.TcbInfoURL("")):
		return kindTCBInfo
	case url == pcs.PckCrlURL("platform"), url == pcs.PckCrlURL("processor"):
		return kindPCKCRL
	}
	return kindUndated
}

// intelDocument reports whether url is where Intel's service keeps one of
// the documents a quote is judged against: one of the three under its API,
// or the CRL of the pinned root.
func intelDocument(url string) bool {
	if kindOf(url) != kindUndated {
		return true
	}
	root, err := rootCRLURL()
	return err == nil && url == root
}

// signedMember returns the member of a document that Intel's signature
// covers. The member and the signature must each appear once, under exactly
// their names, so that every reader of the document reads the one value that
// was signed.
func signedMember(body []byte, name string) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("the document is not a JSON object")
	}
	var member json.RawMessage
	signed := false
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := tok.(string)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		switch {
		case strings.EqualFold(key, name):
			if key != name || member != nil {
				return nil, fmt.Errorf("the document has more than one %q", name)
			}
			member = value
		case strings.EqualFold(key, "signature"):
			if key != "signature" || signed {
				return nil, errors.New("the document has more than one signature")
			}
			signed = true
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("the document is followed by more")
	}
	if member == nil || !signed {
		return nil, fmt.Errorf("the document has no signed %q", name)
	}
	return member, nil
}

// read returns what a document says of itself: when Intel signed it and, for
// the two that carry one, its TCB evaluation data number. None of it is
// authenticated here. The verification that is handed the same bytes checks
// Intel's signature over them.
func (k collateralKind) read(body []byte) (issued time.Time, evaluation int, err error) {
	name := ""
	switch k {
	case kindTCBInfo:
		name = "tcbInfo"
	case kindQEIdentity:
		name = "enclaveIdentity"
	case kindPCKCRL:
		crl, err := x509.ParseRevocationList(body)
		if err != nil {
			return time.Time{}, 0, err
		}
		return crl.ThisUpdate, 0, nil
	default:
		return time.Time{}, 0, nil
	}
	member, err := signedMember(body, name)
	if err != nil {
		return time.Time{}, 0, err
	}
	var signed struct {
		IssueDate  time.Time `json:"issueDate"`
		Evaluation int       `json:"tcbEvaluationDataNumber"`
	}
	if err := json.Unmarshal(member, &signed); err != nil {
		return time.Time{}, 0, err
	}
	return signed.IssueDate, signed.Evaluation, nil
}

// nextUpdate returns the date Intel signed into a TCB info or an enclave
// identity as the one by which it issues the next. Like read it
// authenticates nothing.
func (k collateralKind) nextUpdate(body []byte) (time.Time, error) {
	name := "tcbInfo"
	if k == kindQEIdentity {
		name = "enclaveIdentity"
	}
	member, err := signedMember(body, name)
	if err != nil {
		return time.Time{}, err
	}
	var signed struct {
		NextUpdate time.Time `json:"nextUpdate"`
	}
	if err := json.Unmarshal(member, &signed); err != nil {
		return time.Time{}, err
	}
	if signed.NextUpdate.IsZero() {
		return time.Time{}, errors.New("the document carries no next update")
	}
	return signed.NextUpdate, nil
}

// evaluated reports whether the kind carries a TCB evaluation data number.
func (k collateralKind) evaluated() bool { return k == kindTCBInfo || k == kindQEIdentity }

// collateralCache holds Intel PCS responses that carried a verification to
// success: for the life of an engine, and with a directory across processes.
// One attestation is verified twice, the serving certificate and then the
// fresh evidence, and a command-line client is a new process each time. All
// of them need the same TCB info, QE identity and CRLs.
//
// The directory saves the fetch and is trusted for nothing: every document is
// signed by Intel and verified again at each use. Whoever can write there can
// at most keep an authentic document in use until Intel's own date on it.
type collateralCache struct {
	now func() time.Time
	// dir, when set, is where entries are kept between processes.
	dir string

	mu sync.Mutex
	// entries are documents this verifier had from Intel itself.
	entries map[string]collateralEntry
	// stapled are documents somebody else handed over.
	stapled map[string]collateralEntry
	// arrived are documents fetched ahead of the verification that will use
	// them, which is what verifies them.
	arrived map[string]collateralEntry
	// flights are the fetches on their way, one for each URL.
	flights map[string]*flight
}

type collateralEntry struct {
	header map[string][]string
	body   []byte
	// fetched is when this verifier had the document from Intel. For a
	// stapled document it is Intel's date on it, the earliest anyone can
	// have had it.
	fetched time.Time
}

// collateralFile is one entry as a file holds it.
type collateralFile struct {
	URL     string              `json:"url"`
	Fetched time.Time           `json:"fetched"`
	Header  map[string][]string `json:"header"`
	Body    []byte              `json:"body"`
}

// flight is one fetch that everyone who wants its document waits for.
type flight struct {
	done  chan struct{}
	entry collateralEntry
	err   error
}

func newCollateralCache(dir string) *collateralCache {
	return &collateralCache{
		now: time.Now, dir: dir,
		entries: map[string]collateralEntry{}, stapled: map[string]collateralEntry{},
		arrived: map[string]collateralEntry{}, flights: map[string]*flight{},
	}
}

// lookup returns the document kept for url, if it is young enough to reuse
// without asking Intel.
func (c *collateralCache) lookup(url string) (collateralEntry, bool) {
	entry, ok := c.kept(url)
	if !ok || c.now().Sub(entry.fetched) >= collateralTTL {
		return collateralEntry{}, false
	}
	return entry, true
}

// kept returns the document this verifier had from Intel for url, however
// old.
func (c *collateralCache) kept(url string) (collateralEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[url]
	if !ok && c.dir != "" {
		if entry, ok = c.read(c.path(url), url); ok {
			c.entries[url] = entry
		}
	}
	// An entry from the future is a clock that moved, or a file that lies.
	if !ok || c.now().Sub(entry.fetched) < 0 {
		return collateralEntry{}, false
	}
	return entry, true
}

// ahead returns the document a fetch ahead of need brought for url, if it is
// young enough to use.
func (c *collateralCache) ahead(url string) (collateralEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.arrived[url]
	if age := c.now().Sub(entry.fetched); !ok || age < 0 || age >= collateralTTL {
		return collateralEntry{}, false
	}
	return entry, true
}

// handed returns the document somebody handed over for url, if Intel signed
// it within the staple window: see acceptable.
func (c *collateralCache) handed(url string) (collateralEntry, bool) {
	c.mu.Lock()
	entry, ok := c.stapled[url]
	if !ok && c.dir != "" {
		entry, ok = c.read(c.stapledPath(url), url)
	}
	c.mu.Unlock()
	if !ok {
		return collateralEntry{}, false
	}
	// A file's word for when Intel signed its document counts for nothing:
	// the document says.
	entry, err := c.acceptable(CollateralDocument{URL: url, Header: entry.header, Body: entry.body})
	if err != nil {
		return collateralEntry{}, false
	}
	c.mu.Lock()
	c.stapled[url] = entry
	c.mu.Unlock()
	return entry, true
}

// acceptable holds a document somebody handed over to what it says of itself:
// Intel signed it within the staple window, and its TCB evaluation is no
// older than the shipped floor and than the one this verifier last had from
// Intel. A document that carries no date of Intel's reads as signed at no
// time, and is never acceptable here.
func (c *collateralCache) acceptable(doc CollateralDocument) (collateralEntry, error) {
	kind := kindOf(doc.URL)
	if len(doc.Body) > maxCollateralBody {
		return collateralEntry{}, fmt.Errorf("the document is %d bytes", len(doc.Body))
	}
	issued, evaluation, err := kind.read(doc.Body)
	if err != nil {
		return collateralEntry{}, err
	}
	if age := c.now().Sub(issued); age >= stapleWindow {
		return collateralEntry{}, fmt.Errorf("the document was signed %s ago", age.Round(time.Second))
	}
	if kind.evaluated() {
		if floor := c.floor(doc.URL); evaluation < floor {
			return collateralEntry{}, fmt.Errorf("the document is of TCB evaluation %d, and %d is the oldest taken", evaluation, floor)
		}
	}
	return collateralEntry{header: doc.Header, body: doc.Body, fetched: issued}, nil
}

// floor is the oldest TCB evaluation taken from somebody other than Intel for
// url: the shipped one, or the one of the document this verifier last had
// from Intel for it, whichever is later. Only Intel's own answer raises it. A
// host can hand over a document Intel gives out ahead of its default, and a
// floor raised by that one would refuse Intel's default for months.
func (c *collateralCache) floor(url string) int {
	floor := minTCBEvaluation
	if entry, ok := c.kept(url); ok {
		if _, evaluation, err := kindOf(url).read(entry.body); err == nil && evaluation > floor {
			floor = evaluation
		}
	}
	return floor
}

func (c *collateralCache) store(url string, entry collateralEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[url] = entry
	// What a fetch ahead of need brought is this one, or older.
	delete(c.arrived, url)
	if c.dir != "" {
		c.write(c.path(url), url, entry)
	}
}

// storeStapled keeps a document somebody handed over, apart from what this
// verifier had from Intel: the two are reused by different rules.
func (c *collateralCache) storeStapled(url string, entry collateralEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stapled[url] = entry
	if c.dir != "" {
		c.write(c.stapledPath(url), url, entry)
	}
}

func (c *collateralCache) path(url string) string {
	sum := sha256.Sum256([]byte(url))
	return filepath.Join(c.dir, hex.EncodeToString(sum[:])+".json")
}

func (c *collateralCache) stapledPath(url string) string {
	sum := sha256.Sum256([]byte(url))
	return filepath.Join(c.dir, hex.EncodeToString(sum[:])+".stapled.json")
}

// read returns the entry the file at path holds for url. Anything else there
// is no entry.
func (c *collateralCache) read(path, url string) (collateralEntry, bool) {
	data, err := ReadBounded(path, maxCollateralFile)
	if err != nil {
		return collateralEntry{}, false
	}
	var file collateralFile
	if err := json.Unmarshal(data, &file); err != nil || file.URL != url || len(file.Body) == 0 {
		return collateralEntry{}, false
	}
	return collateralEntry{header: file.Header, body: file.Body, fetched: file.Fetched}, true
}

// write keeps an entry for other processes. A directory that cannot be
// written costs the next process a fetch and nothing else.
func (c *collateralCache) write(path, url string, entry collateralEntry) {
	data, err := json.Marshal(collateralFile{URL: url, Fetched: entry.fetched, Header: entry.header, Body: entry.body})
	if err != nil || os.MkdirAll(c.dir, 0o700) != nil {
		return
	}
	// A reader sees the old file or the new one, whole.
	tmp, err := os.CreateTemp(c.dir, ".entry-*")
	if err != nil {
		return
	}
	_, err = tmp.Write(data)
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
	}
}

// fly returns the fetch of url that is on its way, and starts one if none
// is. ahead keeps the answer for a verification that has not asked yet.
func (c *collateralCache) fly(ctx context.Context, getter trust.HTTPSGetter, url string, ahead bool) *flight {
	c.mu.Lock()
	defer c.mu.Unlock()
	if f, ok := c.flights[url]; ok {
		return f
	}
	f := &flight{done: make(chan struct{})}
	c.flights[url] = f
	// Whoever asked first may give up, and the others still want the answer.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), flightTimeout)
	go func() {
		defer cancel()
		header, body, err := trust.GetWith(ctx, getter, url)
		c.mu.Lock()
		f.entry, f.err = collateralEntry{header: header, body: body, fetched: c.now()}, err
		delete(c.flights, url)
		if err == nil && ahead {
			c.arrived[url] = f.entry
		}
		c.mu.Unlock()
		close(f.done)
	}()
	return f
}

// fetch asks Intel for url. Whoever asks while an answer is on its way waits
// for that one: a hundred verifications that start together cost one fetch.
func (c *collateralCache) fetch(ctx context.Context, getter trust.HTTPSGetter, url string) (collateralEntry, error) {
	f := c.fly(ctx, getter, url, false)
	select {
	case <-f.done:
		return f.entry, f.err
	case <-ctx.Done():
		return collateralEntry{}, ctx.Err()
	}
}

// keepAhead keeps entry for the next verification that wants url, as a fetch
// ahead of need would, unless one that came later is there.
func (c *collateralCache) keepAhead(url string, entry collateralEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.arrived[url]; !ok || entry.fetched.After(old.fetched) {
		c.arrived[url] = entry
	}
}

// prefetch starts a fetch of url behind the caller, unless this verifier has
// the document from Intel and it is young. The answer waits for the
// verification that wants it.
func (c *collateralCache) prefetch(getter trust.HTTPSGetter, url string) {
	if entry, ok := c.lookup(url); ok && c.now().Sub(entry.fetched) < collateralRenewAfter {
		return
	}
	if _, ok := c.ahead(url); ok {
		return
	}
	c.fly(context.Background(), getter, url, true)
}

// fetchRecorder serves one verification's collateral: from the cache when it
// can, from whoever hands documents over next, from Intel PCS otherwise. It
// notes which fetches failed, because go-tdx-guest flattens fetch errors into
// text and their type is gone by the time the verification error comes back.
// It holds what it was served until the verification succeeds, so a response
// that parsed badly is never kept.
type fetchRecorder struct {
	// ctx is the verification's: what a fetch on its behalf is bounded by.
	// Nil is no bound.
	ctx   context.Context //nolint:containedctx // one recorder serves one verification
	cache *collateralCache
	inner trust.HTTPSGetter
	// anew fetches everything, whatever the cache holds.
	anew bool
	// freshOnly makes a document Intel cannot be asked for anew a failed
	// fetch, where the recorder would go on with the one it kept.
	freshOnly bool
	// source, when set, is asked once for documents somebody else fetched.
	source CollateralSource
	// stapledRoot takes from source a document whose dates do not bound its
	// age too: see withStapledRoot.
	stapledRoot bool
	// only, when set, says which URLs this verification is served. Where the
	// root CA CRL is comes from a certificate in another document's header,
	// which whoever handed that document over wrote: without this a host
	// could have its guest's verifier fetch from anywhere.
	only func(url string) bool

	mu      sync.Mutex
	failed  []string
	fetched map[string]collateralEntry
	// taken are the stapled documents this verification was first to use.
	taken map[string]collateralEntry
	// offered is what source handed over, by URL.
	offered map[string]CollateralDocument
	asked   bool
	// docs is every document this verification was served.
	docs map[string]collateralEntry
	// reused counts the documents Intel was not asked for.
	reused int
	// oldest is when the oldest document served left Intel, as far as this
	// verifier can tell.
	oldest time.Time
	// stale: a kept document past the reuse period was served, because Intel
	// could not be asked for a new one.
	stale bool
	// stapled and rootStapled: a document from somebody other than Intel was
	// served, and one whose dates do not bound its age among them.
	stapled, rootStapled bool
}

// Get is how a verifier that passes no context asks: under the recorder's own.
func (r *fetchRecorder) Get(url string) (map[string][]string, []byte, error) {
	ctx := r.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return r.GetContext(ctx, url)
}

func (r *fetchRecorder) GetContext(ctx context.Context, url string) (map[string][]string, []byte, error) {
	if r.only != nil && !r.only(url) {
		// Nothing was asked, so this is no fetch that failed. A document that
		// was handed over named the URL, and Intel's own will not.
		return nil, nil, fmt.Errorf("%s is none of Intel's documents", url)
	}
	kind := kindOf(url)
	if !r.anew {
		if entry, ok := r.reuse(ctx, url, kind); ok {
			return entry.header, entry.body, nil
		}
	}
	entry, err := r.cache.fetch(ctx, r.inner, url)
	if err == nil {
		err = fromIntel(kind, entry.body)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		// Intel being out of reach is no reason to drop a document Intel
		// signed: it is verified like any other, Intel's own date on it
		// included, and the verdict says how old it is.
		if entry, ok := r.cache.kept(url); ok && !r.anew && !r.freshOnly && fromIntel(kind, entry.body) == nil {
			r.stale = true
			r.served(url, entry, true)
			return entry.header, entry.body, nil
		}
		// The URL makes the message specific enough to recognise later.
		err = fmt.Errorf("fetch %s: %w", url, err)
		r.failed = append(r.failed, err.Error())
		return nil, nil, err
	}
	if r.fetched == nil {
		r.fetched = map[string]collateralEntry{}
	}
	r.fetched[url] = entry
	r.served(url, entry, false)
	return entry.header, entry.body, nil
}

// fromIntel holds Intel's own answer to the shape a verification relies on
// and to the shipped TCB evaluation. Intel's service gives out nothing older,
// so an answer that is older did not come from it as it is today.
func fromIntel(kind collateralKind, body []byte) error {
	if !kind.evaluated() {
		return nil
	}
	_, evaluation, err := kind.read(body)
	if err != nil {
		return err
	}
	if evaluation < minTCBEvaluation {
		return fmt.Errorf("the answer is of TCB evaluation %d, and %d is the oldest taken", evaluation, minTCBEvaluation)
	}
	return nil
}

// reuse serves url without asking Intel, if it can: the document this
// verifier had from Intel within the hour, one a fetch ahead of need brought,
// or one somebody handed over. Of the first two, the later fetch.
func (r *fetchRecorder) reuse(ctx context.Context, url string, kind collateralKind) (collateralEntry, bool) {
	kept, ok := r.cache.lookup(url)
	ok = ok && fromIntel(kind, kept.body) == nil
	if entry, early := r.cache.ahead(url); early && fromIntel(kind, entry.body) == nil && (!ok || entry.fetched.After(kept.fetched)) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.fetched == nil {
			r.fetched = map[string]collateralEntry{}
		}
		// It is Intel's answer to this verifier, kept as one once it verified.
		r.fetched[url] = entry
		r.served(url, entry, true)
		return entry, true
	}
	if ok {
		if r.cache.now().Sub(kept.fetched) >= collateralRenewAfter {
			r.cache.prefetch(r.inner, url)
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		r.served(url, kept, true)
		return kept, true
	}
	return r.staple(ctx, url, kind)
}

// staple serves url from what somebody other than Intel handed over.
func (r *fetchRecorder) staple(ctx context.Context, url string, kind collateralKind) (collateralEntry, bool) {
	if entry, ok := r.cache.handed(url); ok {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.stapled = true
		r.served(url, entry, true)
		return entry, true
	}
	if r.source == nil || (kind == kindUndated && !r.stapledRoot) {
		return collateralEntry{}, false
	}
	doc, ok := r.ask(ctx)[url]
	if !ok {
		return collateralEntry{}, false
	}
	if kind == kindUndated {
		if len(doc.Body) > maxCollateralBody {
			return collateralEntry{}, false
		}
		// When it left Intel is not known, and the verdict says so.
		entry := collateralEntry{header: doc.Header, body: doc.Body}
		r.mu.Lock()
		defer r.mu.Unlock()
		r.stapled, r.rootStapled = true, true
		r.served(url, entry, true)
		return entry, true
	}
	entry, err := r.cache.acceptable(doc)
	if err != nil {
		return collateralEntry{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.taken == nil {
		r.taken = map[string]collateralEntry{}
	}
	r.taken[url] = entry
	r.stapled = true
	r.served(url, entry, true)
	return entry, true
}

// ask returns what the source hands over, asking it once.
func (r *fetchRecorder) ask(ctx context.Context) map[string]CollateralDocument {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.asked {
		r.asked = true
		r.offered = map[string]CollateralDocument{}
		for _, doc := range r.source(ctx) {
			r.offered[doc.URL] = doc
		}
	}
	return r.offered
}

// served notes a document this verification was handed. The caller holds mu.
func (r *fetchRecorder) served(url string, entry collateralEntry, reused bool) {
	if r.docs == nil {
		r.docs = map[string]collateralEntry{}
	}
	r.docs[url] = entry
	if reused {
		r.reused++
	}
	// A document with no time is one whose age nothing here bounds.
	if !entry.fetched.IsZero() && (r.oldest.IsZero() || entry.fetched.Before(r.oldest)) {
		r.oldest = entry.fetched
	}
}

// finding says what the verification this recorder served rests on: see
// CollateralFinding. The dates it reads are the ones in the documents the
// verification checked, and in no other copy the cache may hold.
func (r *fetchRecorder) finding() (*CollateralFinding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	finding := &CollateralFinding{Fetched: r.oldest, Stale: r.stale, Stapled: r.stapled, RootCRLStapled: r.rootStapled}
	for url, entry := range r.docs {
		kind := kindOf(url)
		if !kind.evaluated() {
			continue
		}
		next, err := kind.nextUpdate(entry.body)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", url, err)
		}
		if finding.Expires.IsZero() || next.Before(finding.Expires) {
			finding.Expires = next
		}
	}
	if finding.Expires.IsZero() {
		return nil, errors.New("the collateral was verified but its documents are not at hand")
	}
	if url, err := rootCRLURL(); err == nil {
		finding.RootCRLFetched = r.docs[url].fetched
	}
	return finding, nil
}

// fromCache reports whether any document of this verification came from
// anywhere but Intel, asked by this verification.
func (r *fetchRecorder) fromCache() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reused > 0
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

// commit publishes what this verification was served to the shared cache.
func (r *fetchRecorder) commit() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for url, entry := range r.fetched {
		r.cache.store(url, entry)
	}
	for url, entry := range r.taken {
		r.cache.storeStapled(url, entry)
	}
}
