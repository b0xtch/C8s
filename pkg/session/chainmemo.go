package session

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/go-tdx-guest/pcs"
	pb "github.com/google/go-tdx-guest/proto/tdx"
)

// What a verification of TDX evidence checks is of two kinds. One depends on
// the quote's body: the signature over it, the binding it carries, what it
// says of the TDX module and where its TCB stands. The other depends only on
// what every quote of one platform carries after that signature, which is
// the attestation key and how it is certified, and on Intel's documents:
// the PCK chain against Intel's root and its revocation lists, the quoting
// enclave's report under the PCK key and its binding of the attestation key,
// and the signatures and dates of the documents themselves.
//
// The second kind costs most of a verification and comes out the same for
// every guest of a host. An engine keeps its outcome, by platform, for a
// short while, and reaches it again only when the documents it is served
// have changed. Everything of the first kind is checked on every quote.

const (
	// tdQuoteCertificationStart is where, in a version 4 quote, the part
	// begins that one platform's quotes have in common: after the header,
	// the body, the length of the signed data and the signature over header
	// and body.
	tdQuoteCertificationStart = 0x30 + 0x248 + 4 + 0x40
	// chainMemoFor is how long an outcome stands in for the checks. They
	// hold every certificate and document to its dates at the time they
	// run, so a verdict that rests on a memo is at most this far behind
	// those dates.
	chainMemoFor = time.Minute
	// maxChainMemos bounds what an engine keeps: one entry a platform.
	maxChainMemos = 1024
)

// chainMemo is one platform's outcome: the checks passed under these
// documents, between from and until.
type chainMemo struct {
	from, until time.Time
	// documents is each document the checks were served, by its URL, as the
	// digest of its header and body.
	documents map[string][sha256.Size]byte
}

type chainMemos struct {
	mu         sync.Mutex
	byPlatform map[[sha256.Size]byte]chainMemo
	// hits counts the verifications a memo stood in for.
	hits atomic.Int64
}

// platformOfTDQuote names what a quote has in common with every other quote
// of its platform.
func platformOfTDQuote(raw []byte) (platform [sha256.Size]byte, ok bool) {
	if len(raw) <= tdQuoteCertificationStart {
		return platform, false
	}
	return sha256.Sum256(raw[tdQuoteCertificationStart:]), true
}

func documentDigest(entry collateralEntry) [sha256.Size]byte {
	h := sha256.New()
	names := make([]string, 0, len(entry.header))
	for name := range entry.header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(h, "%d:%s=%d", len(name), name, len(entry.header[name]))
		for _, value := range entry.header[name] {
			fmt.Fprintf(h, ":%d:%s", len(value), value)
		}
	}
	fmt.Fprintf(h, "|%d:", len(entry.body))
	h.Write(entry.body)
	return [sha256.Size]byte(h.Sum(nil))
}

// stands reports whether the platform's checks need not run again: they
// passed a short while ago, and asking for the documents they were served
// brings the same documents now. The recorder is served them either way, so
// what the verification rests on is recorded as if the checks had run.
func (m *chainMemos) stands(platform [sha256.Size]byte, now time.Time, fetches *fetchRecorder) bool {
	// A run that fetches everything anew is one that distrusts what was kept.
	if fetches.anew {
		return false
	}
	m.mu.Lock()
	memo, ok := m.byPlatform[platform]
	m.mu.Unlock()
	if !ok || now.Before(memo.from) || !now.Before(memo.until) {
		return false
	}
	urls := make([]string, 0, len(memo.documents))
	for url := range memo.documents {
		urls = append(urls, url)
	}
	sort.Strings(urls)
	for _, url := range urls {
		if _, _, err := fetches.Get(url); err != nil {
			return false
		}
	}
	if !sameDocuments(memo.documents, fetches.documents()) {
		return false
	}
	m.hits.Add(1)
	return true
}

// keep records that the platform's checks passed under what the recorder
// was served.
func (m *chainMemos) keep(platform [sha256.Size]byte, now time.Time, fetches *fetchRecorder) {
	documents := fetches.documents()
	if len(documents) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byPlatform == nil {
		m.byPlatform = map[[sha256.Size]byte]chainMemo{}
	}
	if _, known := m.byPlatform[platform]; !known && len(m.byPlatform) >= maxChainMemos {
		// Whatever goes is reached again by one full verification.
		for other, memo := range m.byPlatform {
			if !now.Before(memo.until) {
				delete(m.byPlatform, other)
			}
		}
		if len(m.byPlatform) >= maxChainMemos {
			clear(m.byPlatform)
		}
	}
	m.byPlatform[platform] = chainMemo{from: now, until: now.Add(chainMemoFor), documents: documents}
}

func sameDocuments(a, b map[string][sha256.Size]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for url, digest := range a {
		if other, ok := b[url]; !ok || other != digest {
			return false
		}
	}
	return true
}

// documents is every document this verification was served, by its URL, as
// the digest of its header and body.
func (r *fetchRecorder) documents() map[string][sha256.Size]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string][sha256.Size]byte, len(r.docs))
	for url, entry := range r.docs {
		out[url] = documentDigest(entry)
	}
	return out
}

// checkQuotingEnclave holds the quoting enclave's report to Intel's identity
// document for it: its signer, its product, and its MISCSELECT and
// attributes under the document's masks. go-tdx-guest makes this check last
// and skips it for a quote whose TCB status it has already faulted, so it is
// made here, for every quote.
func checkQuotingEnclave(report *pb.EnclaveReport, identity *pcs.EnclaveIdentity) error {
	if report == nil {
		return errors.New("the quote carries no quoting enclave report")
	}
	if !bytes.Equal(identity.Mrsigner.Bytes, report.GetMrSigner()) {
		return fmt.Errorf("the quoting enclave's signer (%x) is not the one Intel's identity document names (%x)", report.GetMrSigner(), identity.Mrsigner.Bytes)
	}
	if report.GetIsvProdId() != uint32(identity.IsvProdID) {
		return fmt.Errorf("the quoting enclave is product %d, and Intel's identity document names %d", report.GetIsvProdId(), identity.IsvProdID)
	}
	if len(identity.Miscselect.Bytes) != 4 || len(identity.MiscselectMask.Bytes) != 4 {
		return errors.New("the quoting enclave's identity document gives no four-byte MISCSELECT and mask")
	}
	if report.GetMiscSelect()&binary.LittleEndian.Uint32(identity.MiscselectMask.Bytes) != binary.LittleEndian.Uint32(identity.Miscselect.Bytes) {
		return fmt.Errorf("the quoting enclave's MISCSELECT (%#x) is not the one Intel's identity document names", report.GetMiscSelect())
	}
	attributes := report.GetAttributes()
	if len(identity.AttributesMask.Bytes) != len(attributes) {
		return fmt.Errorf("the quoting enclave's attributes are %d bytes, and the mask in Intel's identity document is %d", len(attributes), len(identity.AttributesMask.Bytes))
	}
	masked := make([]byte, len(attributes))
	for i := range attributes {
		masked[i] = attributes[i] & identity.AttributesMask.Bytes[i]
	}
	if !bytes.Equal(identity.Attributes.Bytes, masked) {
		return fmt.Errorf("the quoting enclave's attributes (%x under Intel's mask) are not the ones Intel's identity document names (%x)", masked, identity.Attributes.Bytes)
	}
	return nil
}

// checkTDXModule holds what a quote's body says of the TDX module to Intel's
// TCB info: the module's signer, and its attributes under the mask the TCB
// info gives. go-tdx-guest checks the same wherever it runs. Here it is
// checked on every quote, since it depends on the quote's body.
func checkTDXModule(body *pb.TDQuoteBody, info *pcs.TcbInfo) error {
	module := info.TdxModule
	if !bytes.Equal(module.Mrsigner.Bytes, body.GetMrSignerSeam()) {
		return fmt.Errorf("the TDX module's signer (%x) is not the one Intel's TCB info names (%x)", body.GetMrSignerSeam(), module.Mrsigner.Bytes)
	}
	attributes := body.GetSeamAttributes()
	if len(module.AttributesMask.Bytes) != len(attributes) {
		return fmt.Errorf("the TDX module's attributes are %d bytes, and the mask in Intel's TCB info is %d", len(attributes), len(module.AttributesMask.Bytes))
	}
	masked := make([]byte, len(attributes))
	for i := range attributes {
		masked[i] = attributes[i] & module.AttributesMask.Bytes[i]
	}
	if !bytes.Equal(module.Attributes.Bytes, masked) {
		return fmt.Errorf("the TDX module's attributes (%x under Intel's mask) are not the ones Intel's TCB info names (%x)", masked, module.Attributes.Bytes)
	}
	return nil
}
