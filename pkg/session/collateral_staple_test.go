package session

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/pcs"
)

// The fixture's documents by what they are, and Intel's dates on them.
const (
	fixtureFMSPC = "b0c06f000000"
)

var (
	fixtureTCBInfoURL    = pcs.TcbInfoURL(fixtureFMSPC)
	fixtureQEIdentityURL = pcs.QeIdentityURL()
	fixturePCKCRLURL     = pcs.PckCrlURL("platform")
	fixtureRootCRLURL    = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"

	fixtureQEIdentityIssued = time.Date(2026, 10, 2, 0, 8, 3, 0, time.UTC)
	fixturePCKCRLIssued     = time.Date(2026, 10, 2, 0, 25, 55, 0, time.UTC)
	fixtureTCBInfoIssued    = time.Date(2026, 10, 2, 0, 37, 13, 0, time.UTC)
)

// documents is the fixture as a guest's host would hand it over.
func (k *kept) documents() []CollateralDocument {
	var docs []CollateralDocument
	for _, file := range k.files {
		docs = append(docs, CollateralDocument{URL: file.URL, Header: file.Header, Body: file.Body})
	}
	return docs
}

// document is the fixture's document for url.
func (k *kept) document(t *testing.T, url string) CollateralDocument {
	t.Helper()
	for _, doc := range k.documents() {
		if doc.URL == url {
			return doc
		}
	}
	t.Fatalf("the fixture holds no %s", url)
	return CollateralDocument{}
}

// handing is a source that hands over docs and counts how often it is asked.
func handing(asked *int, docs ...CollateralDocument) CollateralSource {
	return func(context.Context) []CollateralDocument {
		*asked++
		return docs
	}
}

// cold is an engine with nothing kept, whose clock reads at.
func (k *kept) cold(t *testing.T, at time.Time, service *intel) *dcapEngine {
	t.Helper()
	engine := k.engineAt(at, service, false)
	engine.cache.dir = t.TempDir()
	return engine
}

// except is the documents with the one for url changed.
func except(docs []CollateralDocument, url string, change func(*CollateralDocument)) []CollateralDocument {
	out := slices.Clone(docs)
	for i := range out {
		if out[i].URL == url {
			change(&out[i])
		}
	}
	return out
}

// A verifier with nothing kept and no way to Intel reaches a verdict on
// documents the guest's host handed over, and the verdict says what it rests
// on. The root CA CRL among them carries it only where nothing is released.
func TestStapledCollateralCarriesAColdVerifier(t *testing.T) {
	env, reportData := fixture(t)
	k := keptCollateral(t)
	at := k.newest.Add(10 * time.Minute)

	t.Run("a verdict that releases nothing rests on all four", func(t *testing.T) {
		service, asked := k.intel(true), 0
		engine := k.cold(t, at, service)
		ctx := withStapledRoot(WithCollateralSource(lenient(), handing(&asked, k.documents()...)))
		res, err := engine.VerifyEvidence(ctx, env, reportData)
		if err != nil || service.calls != 0 || asked != 1 {
			t.Fatalf("%v, after %d fetches and %d questions to the source", err, service.calls, asked)
		}
		finding := CollateralOf(res)
		if !finding.Stapled || !finding.RootCRLStapled || finding.Stale {
			t.Fatalf("finding %+v", finding)
		}
		// As old as the oldest of Intel's dates, the earliest it can have left Intel.
		if !finding.Fetched.Equal(fixtureQEIdentityIssued) {
			t.Fatalf("collateral fetched %s, want Intel's oldest date %s", finding.Fetched, fixtureQEIdentityIssued)
		}
	})

	t.Run("one that releases something takes the root CA CRL from Intel alone", func(t *testing.T) {
		service, asked := k.intel(false), 0
		engine := k.cold(t, at, service)
		ctx := WithCollateralSource(lenient(), handing(&asked, k.documents()...))
		res, err := engine.VerifyEvidence(ctx, env, reportData)
		if err != nil || !slices.Equal(service.asked, []string{fixtureRootCRLURL}) {
			t.Fatalf("%v, after asking Intel for %v", err, service.asked)
		}
		if finding := CollateralOf(res); !finding.Stapled || finding.RootCRLStapled {
			t.Fatalf("finding %+v", finding)
		}

		down := k.intel(true)
		res, err = k.cold(t, at, down).VerifyEvidence(ctx, env, reportData)
		if !isOutage(err) || !slices.Contains(down.asked, fixtureRootCRLURL) {
			t.Fatalf("%+v, %v after asking Intel for %v: want an outage and no verdict", res, err, down.asked)
		}
	})

	t.Run("what was handed over is kept, apart from Intel's own answers", func(t *testing.T) {
		service, asked := k.intel(false), 0
		first := k.cold(t, at, service)
		ctx := WithCollateralSource(lenient(), handing(&asked, k.documents()...))
		if _, err := first.VerifyEvidence(ctx, env, reportData); err != nil {
			t.Fatal(err)
		}
		// Another process, the same directory, nobody to hand anything over.
		second := k.engineAt(at.Add(time.Minute), k.intel(true), false)
		second.cache.dir = first.cache.dir
		res, err := second.VerifyEvidence(lenient(), env, reportData)
		if err != nil || second.fetch.(*intel).calls != 0 {
			t.Fatalf("%v, after %d fetches", err, second.fetch.(*intel).calls)
		}
		if finding := CollateralOf(res); !finding.Stapled || finding.RootCRLStapled {
			t.Fatalf("finding %+v", finding)
		}
		// Intel's own answer for a document is what a floor is read from. A
		// document handed over never stands in its place.
		if _, ok := second.cache.kept(fixtureTCBInfoURL); ok {
			t.Fatal("a document that was handed over is kept as one Intel answered with")
		}
		if _, ok := second.cache.kept(fixtureRootCRLURL); !ok {
			t.Fatal("the root CA CRL this verifier fetched is not kept")
		}
	})

	t.Run("an engine told to take Intel's documents from Intel asks nobody else", func(t *testing.T) {
		service, asked := k.intel(false), 0
		engine := k.cold(t, at, service)
		engine.ownOnly = true
		ctx := withStapledRoot(WithCollateralSource(lenient(), handing(&asked, k.documents()...)))
		res, err := engine.VerifyEvidence(ctx, env, reportData)
		if err != nil || asked != 0 || service.calls != len(k.files) {
			t.Fatalf("%v, after %d fetches and %d questions to the source", err, service.calls, asked)
		}
		if finding := CollateralOf(res); finding.Stapled || finding.RootCRLStapled {
			t.Fatalf("finding %+v", finding)
		}
	})
}

// A document handed over is taken for two hours from Intel's own date on it,
// whatever anyone says about when it was fetched.
func TestStapleIsHeldToIntelsDate(t *testing.T) {
	env, reportData := fixture(t)
	k := keptCollateral(t)
	verify := func(t *testing.T, at time.Time) (*intel, error) {
		service, asked := k.intel(false), 0
		ctx := withStapledRoot(WithCollateralSource(lenient(), handing(&asked, k.documents()...)))
		_, err := k.cold(t, at, service).VerifyEvidence(ctx, env, reportData)
		return service, err
	}

	// The quoting enclave's identity is the oldest of the three.
	service, err := verify(t, fixtureQEIdentityIssued.Add(stapleWindow-time.Second))
	if err != nil || service.calls != 0 {
		t.Fatalf("a second inside the window: %v, after asking Intel for %v", err, service.asked)
	}
	service, err = verify(t, fixtureQEIdentityIssued.Add(stapleWindow))
	if err != nil || !slices.Equal(service.asked, []string{fixtureQEIdentityURL}) {
		t.Fatalf("at the window's end: %v, after asking Intel for %v, want the one document past it", err, service.asked)
	}
	service, err = verify(t, fixtureTCBInfoIssued.Add(stapleWindow))
	if err != nil || !slices.Equal(service.asked, []string{fixtureTCBInfoURL, fixtureQEIdentityURL, fixturePCKCRLURL}) {
		t.Fatalf("past every window: %v, after asking Intel for %v", err, service.asked)
	}

	// A file that calls an old document new is not believed: the document says.
	at := fixtureQEIdentityIssued.Add(stapleWindow)
	engine := k.cold(t, at, k.intel(false))
	old := k.document(t, fixtureQEIdentityURL)
	engine.cache.storeStapled(old.URL, collateralEntry{header: old.Header, body: old.Body, fetched: at})
	again := k.engineAt(at, k.intel(false), false)
	again.cache.dir = engine.cache.dir
	if _, ok := again.cache.handed(old.URL); ok {
		t.Fatal("a kept document past Intel's window was taken on its file's word")
	}
}

// What is handed over can be anything. A document that is not Intel's costs a
// fetch and no verdict, and one for another platform is not looked at.
func TestStapleThatIsNotIntelsIsFetchedAnew(t *testing.T) {
	env, reportData := fixture(t)
	k := keptCollateral(t)
	at := k.newest.Add(10 * time.Minute)
	bent := except(k.documents(), fixtureTCBInfoURL, func(doc *CollateralDocument) {
		// Inside the signed member, so that the signature no longer covers it.
		doc.Body = bytes.Replace(doc.Body, []byte(`"UpToDate"`), []byte(`"UpToDatE"`), 1)
	})
	for _, doc := range bent {
		if doc.URL == fixtureTCBInfoURL && bytes.Equal(doc.Body, k.document(t, fixtureTCBInfoURL).Body) {
			t.Fatal("fixture: nothing was changed")
		}
	}

	t.Run("it is fetched anew and that run decides", func(t *testing.T) {
		service, asked := k.intel(false), 0
		ctx := withStapledRoot(WithCollateralSource(lenient(), handing(&asked, bent...)))
		res, err := k.cold(t, at, service).VerifyEvidence(ctx, env, reportData)
		if err != nil || service.calls != len(k.files) {
			t.Fatalf("%v, after %d fetches", err, service.calls)
		}
		if finding := CollateralOf(res); finding.Stapled || finding.RootCRLStapled {
			t.Fatalf("finding %+v: the verdict rests on what Intel answered", finding)
		}
	})
	t.Run("with no way to Intel it is an outage, never a verdict", func(t *testing.T) {
		asked := 0
		ctx := withStapledRoot(WithCollateralSource(lenient(), handing(&asked, bent...)))
		res, err := k.cold(t, at, k.intel(true)).VerifyEvidence(ctx, env, reportData)
		if !isOutage(err) {
			t.Fatalf("%+v, %v: want an outage and no verdict", res, err)
		}
	})
	t.Run("a document under another name is not this one", func(t *testing.T) {
		service, asked := k.intel(false), 0
		moved := except(k.documents(), fixtureTCBInfoURL, func(doc *CollateralDocument) {
			doc.URL = pcs.TcbInfoURL("00906ed50000")
		})
		ctx := withStapledRoot(WithCollateralSource(lenient(), handing(&asked, moved...)))
		if _, err := k.cold(t, at, service).VerifyEvidence(ctx, env, reportData); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(service.asked, []string{fixtureTCBInfoURL}) {
			t.Fatalf("Intel was asked for %v, want the one document nobody handed over", service.asked)
		}
	})
	t.Run("a document too large to be one is not read", func(t *testing.T) {
		service, asked := k.intel(false), 0
		// Intel's own TCB info, signature and all, beside a member that makes
		// it larger than any document: it would verify.
		huge := except(k.documents(), fixtureTCBInfoURL, func(doc *CollateralDocument) {
			pad := `,"pad":"` + strings.Repeat("a", maxCollateralBody) + `"}`
			doc.Body = append(bytes.TrimSuffix(slices.Clone(doc.Body), []byte("}")), pad...)
		})
		huge = except(huge, fixtureRootCRLURL, func(doc *CollateralDocument) {
			doc.Body = make([]byte, maxCollateralBody+1)
		})
		ctx := withStapledRoot(WithCollateralSource(lenient(), handing(&asked, huge...)))
		if _, err := k.cold(t, at, service).VerifyEvidence(ctx, env, reportData); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(service.asked, []string{fixtureTCBInfoURL, fixtureRootCRLURL}) {
			t.Fatalf("Intel was asked for %v, want the two documents that were too large", service.asked)
		}
		// One byte less than too large is read.
		service = k.intel(false)
		largest := except(k.documents(), fixtureTCBInfoURL, func(doc *CollateralDocument) {
			pad := `,"pad":""}`
			pad = `,"pad":"` + strings.Repeat("a", maxCollateralBody-len(doc.Body)+1-len(pad)) + `"}`
			doc.Body = append(bytes.TrimSuffix(slices.Clone(doc.Body), []byte("}")), pad...)
			if len(doc.Body) != maxCollateralBody {
				t.Fatalf("fixture: the document is %d bytes", len(doc.Body))
			}
		})
		ctx = withStapledRoot(WithCollateralSource(lenient(), handing(&asked, largest...)))
		if _, err := k.cold(t, at, service).VerifyEvidence(ctx, env, reportData); err != nil || service.calls != 0 {
			t.Fatalf("the largest document: %v, after asking Intel for %v", err, service.asked)
		}
	})
}

// forgedFirst is a document with a member of the forger's put before Intel's
// under the same name. Intel's signature still verifies: it is checked over
// the last occurrence.
func forgedFirst(t *testing.T, body []byte, name, forged string) []byte {
	t.Helper()
	prefix := `{"` + name + `":`
	if !bytes.HasPrefix(body, []byte(prefix)) {
		t.Fatalf("fixture: the document does not begin with %s", prefix)
	}
	return append([]byte(`{"`+name+`":`+forged+`,`), body[1:]...)
}

// Go decodes a member that appears twice into one value, field by field and
// slice element by slice element, and the signature is checked over the last
// occurrence alone. A verifier that judged such a document would judge
// fields Intel never signed: here, an advisory on the quoting enclave's level.
func TestRepeatedMemberIsNoDocument(t *testing.T) {
	env, reportData := fixture(t)
	k := keptCollateral(t)
	at := k.newest.Add(10 * time.Minute)
	const forgedAdvisory = "INTEL-SA-FORGED"
	identity := k.document(t, fixtureQEIdentityURL)
	forged := forgedFirst(t, identity.Body, "enclaveIdentity", `{"tcbLevels":[{"advisoryIDs":["`+forgedAdvisory+`"]}]}`)

	// What makes it worth refusing: the decoder this package and its verifier
	// library use does read the forged field into what they judge.
	var merged pcs.QeIdentity
	if err := json.Unmarshal(forged, &merged); err != nil {
		t.Fatal(err)
	}
	if levels := merged.EnclaveIdentity.TcbLevels; len(levels) != 1 || !slices.Contains(levels[0].AdvisoryIDs, forgedAdvisory) {
		t.Fatalf("fixture: the decoder no longer merges a repeated member: %+v", levels)
	}

	advisories := func(t *testing.T, ctx context.Context, engine *dcapEngine) []string {
		t.Helper()
		res, err := engine.VerifyEvidence(ctx, env, reportData)
		if err != nil {
			t.Fatal(err)
		}
		return CollateralOf(res).Advisories
	}
	t.Run("handed over", func(t *testing.T) {
		service, asked := k.intel(false), 0
		docs := except(k.documents(), fixtureQEIdentityURL, func(doc *CollateralDocument) { doc.Body = forged })
		ctx := withStapledRoot(WithCollateralSource(lenient(), handing(&asked, docs...)))
		got := advisories(t, ctx, k.cold(t, at, service))
		if slices.Contains(got, forgedAdvisory) || !slices.Equal(service.asked, []string{fixtureQEIdentityURL}) {
			t.Fatalf("advisories %v after asking Intel for %v", got, service.asked)
		}
	})
	t.Run("in the directory", func(t *testing.T) {
		k := keptCollateral(t)
		k.write(t, func(file *collateralFile) {
			if file.URL == fixtureQEIdentityURL {
				file.Body = forged
			}
		})
		service := k.intel(false)
		got := advisories(t, lenient(), k.engineAt(at, service, false))
		if slices.Contains(got, forgedAdvisory) || !slices.Equal(service.asked, []string{fixtureQEIdentityURL}) {
			t.Fatalf("advisories %v after asking Intel for %v", got, service.asked)
		}
	})
	t.Run("in the directory, past the hour, with Intel out of reach", func(t *testing.T) {
		k := keptCollateral(t)
		k.write(t, func(file *collateralFile) {
			if file.URL == fixtureQEIdentityURL {
				file.Body = forged
			}
		})
		// A kept document carries a verdict past the hour when Intel cannot
		// be asked. This one is no document.
		res, err := k.engineAt(k.newest.Add(2*time.Hour), k.intel(true), false).VerifyEvidence(lenient(), env, reportData)
		if !isOutage(err) {
			t.Fatalf("%+v, %v: want an outage and no verdict", res, err)
		}
	})
	t.Run("fetched ahead of need", func(t *testing.T) {
		k := keptCollateral(t)
		service := k.intel(false)
		authentic := service.documents[fixtureQEIdentityURL]
		answer := authentic
		answer.Body = forged
		service.documents[fixtureQEIdentityURL] = answer
		now := k.newest.Add(collateralRenewAfter)
		engine := k.engineAt(now, service, false)
		engine.cache.now = func() time.Time { return now }
		// This verification is served what was kept, and renews it behind itself.
		if got := advisories(t, lenient(), engine); slices.Contains(got, forgedAdvisory) {
			t.Fatalf("advisories %v", got)
		}
		awaitAhead(t, engine.cache, fixtureQEIdentityURL)
		settle(t, engine.cache)
		service.mu.Lock()
		service.documents[fixtureQEIdentityURL], service.asked = authentic, nil
		service.mu.Unlock()
		now = k.newest.Add(collateralTTL + time.Minute)
		got := advisories(t, lenient(), engine)
		if slices.Contains(got, forgedAdvisory) || !slices.Equal(service.asked, []string{fixtureQEIdentityURL}) {
			t.Fatalf("advisories %v after asking Intel for %v", got, service.asked)
		}
	})
	t.Run("as Intel's own answer it is an outage", func(t *testing.T) {
		service := k.intel(false)
		answer := service.documents[fixtureQEIdentityURL]
		answer.Body = forged
		service.documents[fixtureQEIdentityURL] = answer
		res, err := k.cold(t, at, service).VerifyEvidence(lenient(), env, reportData)
		if !isOutage(err) {
			t.Fatalf("%+v, %v: want an outage and no verdict", res, err)
		}
	})

	inner := `{"issueDate":"2026-10-02T00:00:00Z","tcbEvaluationDataNumber":20}`
	for name, tc := range map[string]struct {
		body string
		ok   bool
	}{
		"control":                     {`{"tcbInfo":` + inner + `,"signature":"ab"}`, true},
		"signature first":             {`{"signature":"ab","tcbInfo":` + inner + `}`, true},
		"a member of another name":    {`{"tcbInfo":` + inner + `,"signature":"ab","note":1}`, true},
		"the member twice":            {`{"tcbInfo":{},"tcbInfo":` + inner + `,"signature":"ab"}`, false},
		"the member in another case":  {`{"TCBINFO":{},"tcbInfo":` + inner + `,"signature":"ab"}`, false},
		"only in another case":        {`{"TcbInfo":` + inner + `,"signature":"ab"}`, false},
		"the signature twice":         {`{"tcbInfo":` + inner + `,"signature":"cd","signature":"ab"}`, false},
		"a signature in another case": {`{"tcbInfo":` + inner + `,"Signature":"cd","signature":"ab"}`, false},
		// The long s folds to s for Go's decoder, as it does here.
		"a signature in another letter":    {`{"tcbInfo":` + inner + `,"ſignature":"cd","signature":"ab"}`, false},
		"a signature only in another case": {`{"tcbInfo":` + inner + `,"Signature":"ab"}`, false},
		"no signature":                     {`{"tcbInfo":` + inner + `}`, false},
		"an array of names and values":     {`["tcbInfo",` + inner + `,"signature","ab"]`, false},
		"no member":                        {`{"signature":"ab"}`, false},
		"followed by more":                 {`{"tcbInfo":` + inner + `,"signature":"ab"}{}`, false},
		"an array":                         {`[{"tcbInfo":` + inner + `,"signature":"ab"}]`, false},
		"not closed":                       {`{"tcbInfo":` + inner + `,"signature":"ab"`, false},
		"nothing":                          {``, false},
	} {
		t.Run(name, func(t *testing.T) {
			member, err := signedMember([]byte(tc.body), "tcbInfo")
			if (err == nil) != tc.ok || (tc.ok && string(member) != inner) {
				t.Fatalf("signedMember = %s, %v, want a member: %v", member, err, tc.ok)
			}
			issued, evaluation, err := kindTCBInfo.read([]byte(tc.body))
			if (err == nil) != tc.ok || (tc.ok && (evaluation != 20 || !issued.Equal(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)))) {
				t.Fatalf("read = %s, %d, %v", issued, evaluation, err)
			}
		})
	}
}

// evaluated is a document that says it is of another TCB evaluation. Intel's
// signature no longer covers it, which is beside the point here: the number
// is read before anything else is.
func evaluated(t *testing.T, doc CollateralDocument, number string) CollateralDocument {
	t.Helper()
	body := bytes.Replace(doc.Body, []byte(`"tcbEvaluationDataNumber":20`), []byte(`"tcbEvaluationDataNumber":`+number), 1)
	if bytes.Equal(body, doc.Body) {
		t.Fatal("fixture: the document carries no TCB evaluation 20")
	}
	doc.Body = body
	return doc
}

// A document Intel signed an hour ago can still be of a TCB evaluation Intel
// has retired since. None older than the shipped one is taken from anybody,
// and none handed over that is older than Intel's last answer to this
// verifier. Intel's answer alone raises that floor.
func TestTCBEvaluationFloor(t *testing.T) {
	env, reportData := fixture(t)
	at := keptCollateral(t).newest.Add(10 * time.Minute)
	if minTCBEvaluation != 20 {
		t.Fatalf("the fixture's documents are of evaluation 20, and the shipped floor is %d", minTCBEvaluation)
	}

	t.Run("handed over below the shipped floor", func(t *testing.T) {
		for _, url := range []string{fixtureTCBInfoURL, fixtureQEIdentityURL} {
			k := keptCollateral(t)
			service, asked := k.intel(false), 0
			docs := except(k.documents(), url, func(doc *CollateralDocument) { *doc = evaluated(t, *doc, "19") })
			ctx := withStapledRoot(WithCollateralSource(lenient(), handing(&asked, docs...)))
			// Not looked at, so Intel is asked for this one alone. A document
			// taken and then found unsigned would have all four fetched anew.
			if _, err := k.cold(t, at, service).VerifyEvidence(ctx, env, reportData); err != nil || !slices.Equal(service.asked, []string{url}) {
				t.Fatalf("%v, after asking Intel for %v, want %s alone", err, service.asked, url)
			}
		}
	})
	t.Run("from Intel below the shipped floor", func(t *testing.T) {
		k := keptCollateral(t)
		service := k.intel(false)
		answer := service.documents[fixtureTCBInfoURL]
		answer.Body = evaluated(t, k.document(t, fixtureTCBInfoURL), "19").Body
		service.documents[fixtureTCBInfoURL] = answer
		res, err := k.cold(t, at, service).VerifyEvidence(lenient(), env, reportData)
		if !isOutage(err) || !strings.Contains(err.Error(), "TCB evaluation 19") {
			t.Fatalf("%+v, %v: want an outage that names the evaluation", res, err)
		}
	})
	t.Run("handed over below Intel's last answer to this verifier", func(t *testing.T) {
		k := keptCollateral(t)
		// Long ago this verifier had evaluation 21 from Intel for the TCB info.
		k.write(t, func(file *collateralFile) {
			file.Fetched = at.Add(-48 * time.Hour)
			if file.URL == fixtureTCBInfoURL {
				file.Body = evaluated(t, CollateralDocument{Body: file.Body}, "21").Body
			}
		})
		service, asked := k.intel(false), 0
		engine := k.engineAt(at, service, false)
		ctx := withStapledRoot(WithCollateralSource(lenient(), handing(&asked, k.documents()...)))
		if _, err := engine.VerifyEvidence(ctx, env, reportData); err != nil {
			t.Fatal(err)
		}
		// The identity's floor is its own document's, which is the shipped one.
		if !slices.Equal(service.asked, []string{fixtureTCBInfoURL}) {
			t.Fatalf("Intel was asked for %v, want the TCB info alone", service.asked)
		}
	})
	t.Run("a document handed over raises no floor", func(t *testing.T) {
		k := keptCollateral(t)
		cache := newCollateralCache(t.TempDir())
		cache.now = func() time.Time { return at }
		early := evaluated(t, k.document(t, fixtureTCBInfoURL), "22")
		entry, err := cache.acceptable(early)
		if err != nil {
			t.Fatalf("a later evaluation than the verifier's own is refused: %v", err)
		}
		cache.storeStapled(early.URL, entry)
		if floor := cache.floor(fixtureTCBInfoURL); floor != minTCBEvaluation {
			t.Fatalf("the floor is %d after a document of evaluation 22 was handed over", floor)
		}
		if _, err := cache.acceptable(k.document(t, fixtureTCBInfoURL)); err != nil {
			t.Fatalf("Intel's default is refused after it: %v", err)
		}
	})
}

// gate is a getter that holds every fetch until it is opened.
type gate struct {
	mu      sync.Mutex
	calls   int
	open    chan struct{}
	arrived chan struct{}
}

func newGate() *gate { return &gate{open: make(chan struct{}), arrived: make(chan struct{}, 64)} }

func (g *gate) Get(string) (map[string][]string, []byte, error) {
	g.mu.Lock()
	g.calls++
	open := g.open
	g.mu.Unlock()
	g.arrived <- struct{}{}
	<-open
	return map[string][]string{"X": {"1"}}, []byte("body"), nil
}

func (g *gate) asked() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls
}

// Verifications that start together and want the same document cost Intel
// one request, and one that gives up does not take the others' answer along.
func TestOneFetchForAllWhoWait(t *testing.T) {
	const url = "https://pcs.example/tcb"
	getter := newGate()
	cache := newCollateralCache("")
	ctx := lenient()

	first := cache.fly(ctx, getter, url, false)
	<-getter.arrived
	for range 15 {
		if cache.fly(ctx, getter, url, false) != first {
			t.Fatal("a second fetch of a document was started while one was on its way")
		}
	}
	if other := cache.fly(ctx, getter, url+"/other", false); other == first {
		t.Fatal("two documents share one fetch")
	}
	<-getter.arrived

	// Whoever gives up does not wait, and does not take the answer along.
	gone, leave := context.WithCancel(ctx)
	leave()
	if _, err := cache.fetch(gone, getter, url); !errors.Is(err, context.Canceled) {
		t.Fatalf("the one who gave up got %v", err)
	}
	close(getter.open)
	<-first.done
	if first.err != nil || string(first.entry.body) != "body" {
		t.Fatalf("those who waited got %q, %v", first.entry.body, first.err)
	}
	settle(t, cache)
	if calls := getter.asked(); calls != 2 {
		t.Fatalf("Intel was asked %d times for two documents", calls)
	}
	// Nobody kept the answer for later: a fetch is kept by the verification
	// it carried, once that succeeded.
	if _, ok := cache.lookup(url); ok {
		t.Fatal("a fetch was kept before any verification succeeded with it")
	}
	if _, ok := cache.ahead(url); ok {
		t.Fatal("a fetch somebody waited for was kept as one made ahead of need")
	}
	// The flight is over: the next to ask starts one.
	if _, err := cache.fetch(ctx, getter, url); err != nil || getter.asked() != 3 {
		t.Fatalf("after the flight: %v, %d fetches", err, getter.asked())
	}
}

// awaitAhead waits for a fetch ahead of need to land.
func awaitAhead(t *testing.T, cache *collateralCache, url string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := cache.ahead(url); ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no fetch ahead of need brought %s", url)
		}
		time.Sleep(time.Millisecond)
	}
}

// settle waits for every fetch on its way to land.
func settle(t *testing.T, cache *collateralCache) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		cache.mu.Lock()
		flights := len(cache.flights)
		cache.mu.Unlock()
		if flights == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d fetches are still on their way", flights)
		}
		time.Sleep(time.Millisecond)
	}
}

// The root CA CRL is the one document nobody can hand over for a verdict
// that releases something, and the one a verifier can name before it has seen
// evidence. Fetched when the verifier starts, it is there when that verdict
// is due.
func TestPrefetchBringsTheRootCRL(t *testing.T) {
	env, reportData := fixture(t)
	k := keptCollateral(t)
	at := k.newest.Add(10 * time.Minute)
	url, err := rootCRLURL()
	if err != nil || url != fixtureRootCRLURL {
		t.Fatalf("the pinned root names %q, %v; a real verification asked for %s", url, err, fixtureRootCRLURL)
	}

	service, asked := k.intel(false), 0
	engine := k.cold(t, at, service)
	Prefetch(engine)
	awaitAhead(t, engine.cache, url)
	if !slices.Equal(service.asked, []string{url}) {
		t.Fatalf("a prefetch asked Intel for %v", service.asked)
	}
	// Asked again before anything used it: there is one already.
	Prefetch(engine)
	settle(t, engine.cache)
	ctx := WithCollateralSource(lenient(), handing(&asked, k.documents()...))
	res, err := engine.VerifyEvidence(ctx, env, reportData)
	if err != nil || len(service.asked) != 1 {
		t.Fatalf("%v, after asking Intel for %v", err, service.asked)
	}
	if finding := CollateralOf(res); finding.RootCRLStapled || !finding.Stapled {
		t.Fatalf("finding %+v", finding)
	}
	// It verified, so it is kept as Intel's answer, and nothing is fetched
	// ahead again while it is young.
	if _, ok := engine.cache.lookup(url); !ok {
		t.Fatal("the prefetched document was not kept once it verified")
	}
	Prefetch(engine)
	settle(t, engine.cache)
	if _, err := engine.VerifyEvidence(lenient(), env, reportData); err != nil || len(service.asked) != 1 {
		t.Fatalf("%v, after asking Intel for %v", err, service.asked)
	}

	// A fetch ahead of need that failed brought nothing.
	down := k.cold(t, at, k.intel(true))
	Prefetch(down)
	settle(t, down.cache)
	if entry, ok := down.cache.ahead(url); ok {
		t.Fatalf("a failed fetch left a document of %d bytes", len(entry.body))
	}

	// One that nothing used within its hour is not used after it, nor is one
	// from after now: a clock that moved.
	now := at
	unused := k.cold(t, at, service)
	unused.cache.now = func() time.Time { return now }
	Prefetch(unused)
	awaitAhead(t, unused.cache, url)
	now = at.Add(collateralTTL - time.Second)
	if _, ok := unused.cache.ahead(url); !ok {
		t.Fatal("a document fetched ahead is not used within its hour")
	}
	for _, moved := range []time.Duration{collateralTTL, -time.Second} {
		now = at.Add(moved)
		if _, ok := unused.cache.ahead(url); ok {
			t.Fatalf("a document fetched ahead is used %s after it came", moved)
		}
	}
	service.mu.Lock()
	service.asked = service.asked[:1]
	service.mu.Unlock()

	// An engine that fetches nothing is asked for nothing.
	Prefetch(fakeEngine{})
	if len(service.asked) != 1 {
		t.Fatalf("an engine that fetches nothing had Intel asked for %v", service.asked)
	}
}

type fakeEngine struct{ Engine }

// A verifier that keeps verifying fetches each document again before its
// hour is over, behind the verification that used it, and never waits.
func TestCollateralIsRenewedAheadOfTheHour(t *testing.T) {
	env, reportData := fixture(t)
	k := keptCollateral(t)
	service := k.intel(false)
	now := k.newest.Add(collateralRenewAfter - time.Minute)
	engine := k.engineAt(now, service, false)
	engine.cache.now = func() time.Time { return now }
	ctx := lenient()

	if _, err := engine.VerifyEvidence(ctx, env, reportData); err != nil || service.calls != 0 {
		t.Fatalf("young documents: %v, after %d fetches", err, service.calls)
	}
	// Every document is past the renewal age and inside the hour.
	now = k.newest.Add(collateralRenewAfter)
	if now.Sub(k.oldest) >= collateralTTL {
		t.Fatal("fixture: the documents were fetched too far apart for one moment to be past renewal and inside the hour for all")
	}
	res, err := engine.VerifyEvidence(ctx, env, reportData)
	if err != nil {
		t.Fatal(err)
	}
	// It was served what it kept, and did not wait.
	if finding := CollateralOf(res); !finding.Fetched.Equal(k.oldest) {
		t.Fatalf("collateral fetched %s, want the kept documents' %s", finding.Fetched, k.oldest)
	}
	for _, file := range k.files {
		awaitAhead(t, engine.cache, file.URL)
	}
	if service.calls != len(k.files) {
		t.Fatalf("%d fetches behind the verification, want %d", service.calls, len(k.files))
	}
	// Past the hour the renewed documents carry the next one, with no fetch.
	renewed := now
	now = k.newest.Add(collateralTTL + time.Minute)
	res, err = engine.VerifyEvidence(ctx, env, reportData)
	if err != nil || service.calls != len(k.files) {
		t.Fatalf("%v, after %d fetches", err, service.calls)
	}
	if finding := CollateralOf(res); !finding.Fetched.Equal(renewed) || finding.Stale {
		t.Fatalf("collateral fetched %s (stale: %v), want %s", finding.Fetched, finding.Stale, renewed)
	}
	if oldest, newest := k.fetchedOnDisk(t); !oldest.Equal(renewed) || !newest.Equal(renewed) {
		t.Fatalf("the directory says %s to %s, want %s", oldest, newest, renewed)
	}
	// And they are renewed in their turn.
	settle(t, engine.cache)
	now = renewed.Add(collateralRenewAfter)
	if _, err := engine.VerifyEvidence(ctx, env, reportData); err != nil {
		t.Fatal(err)
	}
	settle(t, engine.cache)
	if service.calls != 2*len(k.files) {
		t.Fatalf("%d fetches after a second renewal, want %d", service.calls, 2*len(k.files))
	}
}

func TestKindOfDocument(t *testing.T) {
	k := keptCollateral(t)
	for url, want := range map[string]struct {
		kind   collateralKind
		issued time.Time
		number int
	}{
		fixtureTCBInfoURL:    {kindTCBInfo, fixtureTCBInfoIssued, 20},
		fixtureQEIdentityURL: {kindQEIdentity, fixtureQEIdentityIssued, 20},
		fixturePCKCRLURL:     {kindPCKCRL, fixturePCKCRLIssued, 0},
		fixtureRootCRLURL:    {kindUndated, time.Time{}, 0},
	} {
		kind := kindOf(url)
		issued, number, err := kind.read(k.document(t, url).Body)
		if kind != want.kind || err != nil || !issued.Equal(want.issued) || number != want.number {
			t.Errorf("%s: kind %d, issued %s, evaluation %d, %v", url, kind, issued, number, err)
		}
	}
	for _, url := range []string{
		pcs.PckCrlURL("processor"),
	} {
		if kindOf(url) != kindPCKCRL {
			t.Errorf("%s is no PCK CRL", url)
		}
	}
	for _, url := range []string{
		"https://pcs.example/tcb", pcs.PckCrlURL("other"), pcs.QeIdentityURL() + "?update=early",
		strings.Replace(fixtureTCBInfoURL, "/tdx/", "/sgx/", 1),
	} {
		if kindOf(url) != kindUndated {
			t.Errorf("%s is taken for a document whose date bounds its age", url)
		}
	}
	// Each kind reads only its own.
	if _, _, err := kindTCBInfo.read(k.document(t, fixtureQEIdentityURL).Body); err == nil {
		t.Error("an enclave identity was read as a TCB info")
	}
	if _, _, err := kindPCKCRL.read(k.document(t, fixtureTCBInfoURL).Body); err == nil {
		t.Error("a TCB info was read as a CRL")
	}
}

// What a guest tells its host of its platform comes from its own quote, and
// the documents the host fetches for it are the ones a verifier asks for.
func TestCollateralPlatform(t *testing.T) {
	env, _ := fixture(t)
	k := keptCollateral(t)
	platform, err := CollateralPlatformOf(env)
	if err != nil || *platform != (CollateralPlatform{FMSPC: fixtureFMSPC, CA: "platform"}) {
		t.Fatalf("platform %+v, %v", platform, err)
	}
	urls, err := platform.URLs()
	if err != nil {
		t.Fatal(err)
	}
	var asked []string
	for _, file := range k.files {
		asked = append(asked, file.URL)
	}
	slices.Sort(asked)
	sorted := slices.Clone(urls)
	slices.Sort(sorted)
	if !slices.Equal(sorted, asked) {
		t.Fatalf("the platform's URLs are %v, and a real verification asked for %v", urls, asked)
	}
	for _, bad := range []CollateralPlatform{
		{FMSPC: "", CA: "platform"},
		{FMSPC: "B0C06F000000", CA: "platform"},
		{FMSPC: "b0c06f00000", CA: "platform"},
		{FMSPC: "b0c06f000000&x=1", CA: "platform"},
		{FMSPC: "../../../x", CA: "platform"},
		{FMSPC: fixtureFMSPC, CA: ""},
		{FMSPC: fixtureFMSPC, CA: "platform&encoding=pem"},
		{FMSPC: fixtureFMSPC, CA: "Platform"},
	} {
		if urls, err := bad.URLs(); err == nil {
			t.Errorf("%+v gave %v", bad, urls)
		}
	}
	other := env
	other.Platform = "snp"
	if platform, err := CollateralPlatformOf(other); err == nil {
		t.Errorf("evidence of another TEE named %+v", platform)
	}
	other = env
	other.Evidence = []byte(`{"quote":"AAAA"}`)
	if platform, err := CollateralPlatformOf(other); err == nil {
		t.Errorf("evidence with no quote in it named %+v", platform)
	}

	// The host keeps of each answer the body and the one header a verifier reads.
	served := &fetching{k: k}
	docs, err := fetchCollateral(lenient(), served, *platform)
	if err != nil || len(docs) != 4 {
		t.Fatalf("%d documents, %v", len(docs), err)
	}
	for i, doc := range docs {
		want := k.document(t, urls[i])
		if doc.URL != urls[i] || !bytes.Equal(doc.Body, want.Body) {
			t.Errorf("document %d is %s", i, doc.URL)
		}
		chain := kindOf(doc.URL).issuerChainHeader()
		switch {
		case chain == "" && doc.Header != nil:
			t.Errorf("%s keeps header %v", doc.URL, doc.Header)
		case chain != "" && (len(doc.Header) != 1 || doc.Header[chain][0] != want.Header[chain][0]):
			t.Errorf("%s keeps header %v", doc.URL, doc.Header)
		}
	}
	// What it fetched carries a verifier that has nothing.
	questions := 0
	ctx := withStapledRoot(WithCollateralSource(lenient(), handing(&questions, docs...)))
	env2, reportData := fixture(t)
	if _, err := k.cold(t, k.newest.Add(time.Minute), k.intel(true)).VerifyEvidence(ctx, env2, reportData); err != nil {
		t.Fatalf("with what the host fetched: %v", err)
	}
	served.down = true
	if docs, err := fetchCollateral(lenient(), served, *platform); err == nil {
		t.Fatalf("with Intel out of reach the host has %d documents", len(docs))
	}
}

// fetching answers a host's fetch with the fixture's documents.
type fetching struct {
	k    *kept
	down bool
}

func (f *fetching) GetContext(_ context.Context, url string) (map[string][]string, []byte, error) {
	if f.down {
		return nil, nil, errors.New("no route to Intel's service")
	}
	for _, file := range f.k.files {
		if file.URL == url {
			header := map[string][]string{"Date": {"now"}, "Request-Id": {"1"}}
			for name, values := range file.Header {
				header[name] = values
			}
			return header, file.Body, nil
		}
	}
	return nil, nil, errors.New("not found")
}

// The fetcher takes an answer only from where it asked, bounded, and never
// an empty one, which Intel's service gives a request it will not serve.
func TestPCSGetter(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/document", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Tcb-Info-Issuer-Chain", "chain")
		_, _ = w.Write([]byte("body"))
	})
	mux.HandleFunc("/elsewhere", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/document", http.StatusFound)
	})
	mux.HandleFunc("/nothing", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("/gone", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusGone) })
	mux.HandleFunc("/partial", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNonAuthoritativeInfo)
		_, _ = w.Write([]byte("body"))
	})
	mux.HandleFunc("/huge", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, maxCollateralBody+1))
	})
	mux.HandleFunc("/largest", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, maxCollateralBody))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	header, body, err := pcsGetter{}.Get(srv.URL + "/document")
	if err != nil || string(body) != "body" || header["Tcb-Info-Issuer-Chain"][0] != "chain" {
		t.Fatalf("a document: %q %v, %v", body, header, err)
	}
	if _, body, err := (pcsGetter{}).Get(srv.URL + "/largest"); err != nil || len(body) != maxCollateralBody {
		t.Fatalf("the largest document: %d bytes, %v", len(body), err)
	}
	for _, path := range []string{"/elsewhere", "/nothing", "/gone", "/partial", "/huge", "/missing"} {
		if _, body, err := (pcsGetter{}).Get(srv.URL + path); err == nil {
			t.Errorf("%s was taken as a document of %d bytes", path, len(body))
		}
	}
	ctx, cancel := context.WithCancel(lenient())
	cancel()
	if _, _, err := (pcsGetter{}).GetContext(ctx, srv.URL+"/document"); !errors.Is(err, context.Canceled) {
		t.Errorf("a fetch nobody waits for: %v", err)
	}
}

// The documents a verification is served are the bytes it checked: a copy
// the cache holds under the same name is not read in their place.
func TestTheDocumentJudgedIsTheOneServed(t *testing.T) {
	env, reportData := fixture(t)
	k := keptCollateral(t)
	at := k.newest.Add(10 * time.Minute)
	// Long ago this verifier had another TCB info from Intel: one that calls
	// every level of the platform revoked.
	k.write(t, func(file *collateralFile) {
		file.Fetched = at.Add(-48 * time.Hour)
		if file.URL == fixtureTCBInfoURL {
			file.Body = bytes.ReplaceAll(file.Body, []byte(`"OutOfDate"`), []byte(`"Revoked"`))
		}
	})
	asked := 0
	engine := k.engineAt(at, k.intel(true), false)
	engine.freshOnly = true
	ctx := withStapledRoot(WithCollateralSource(lenient(), handing(&asked, k.documents()...)))
	res, err := engine.VerifyEvidence(ctx, env, reportData)
	if err != nil {
		t.Fatalf("judged on a copy it was not served: %v", err)
	}
	if finding := CollateralOf(res); finding.Platform != "OutOfDate" {
		t.Fatalf("finding %+v", finding)
	}
}

// elsewhere is the fixture's enclave identity with its signing chain's root
// replaced by a certificate of the same name that says its CRL is at url.
func elsewhere(t *testing.T, doc CollateralDocument, url string) CollateralDocument {
	t.Helper()
	const name = "Sgx-Enclave-Identity-Issuer-Chain"
	chain, err := neturl.QueryUnescape(doc.Header[name][0])
	if err != nil {
		t.Fatal(err)
	}
	signing, rest := pem.Decode([]byte(chain))
	if signing == nil || len(rest) == 0 {
		t.Fatal("fixture: the header holds no chain of two")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Intel SGX Root CA"},
		NotBefore: time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2049, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		CRLDistributionPoints: []string{url},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	forged := string(pem.EncodeToMemory(signing)) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	doc.Header = map[string][]string{name: {neturl.QueryEscape(forged)}}
	return doc
}

// Where the root CA CRL is comes from a certificate in the header of another
// document, and a document that is handed over comes with a header of its
// host's writing. A verifier asks only Intel's own addresses, so a host
// cannot have it fetch from anywhere else, and such a document costs a fetch
// from Intel and no verdict.
func TestVerifierFetchesFromIntelAlone(t *testing.T) {
	env, reportData := fixture(t)
	k := keptCollateral(t)
	at := k.newest.Add(10 * time.Minute)
	const far = "http://169.254.169.254/latest/meta-data/"
	docs := except(k.documents(), fixtureQEIdentityURL, func(doc *CollateralDocument) { *doc = elsewhere(t, *doc, far) })
	// The root CA CRL is left out: the verifier goes by what the header says.
	docs = slices.DeleteFunc(docs, func(doc CollateralDocument) bool { return doc.URL == fixtureRootCRLURL })

	service, asked := k.intel(false), 0
	ctx := withStapledRoot(WithCollateralSource(lenient(), handing(&asked, docs...)))
	res, err := k.cold(t, at, service).VerifyEvidence(ctx, env, reportData)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(service.asked, far) {
		t.Fatalf("the verifier fetched from where a handed-over document pointed: %v", service.asked)
	}
	if finding := CollateralOf(res); len(service.asked) != len(k.files) || finding.Stapled {
		t.Fatalf("finding %+v after asking Intel for %v: want Intel's own four", finding, service.asked)
	}

	// Nor does it when the header is one Intel's service answered with, on
	// the run that asks Intel for everything anew.
	again := keptCollateral(t)
	again.write(t, func(file *collateralFile) {
		if file.URL == fixtureTCBInfoURL {
			file.Body = bytes.Replace(file.Body, []byte(`"UpToDate"`), []byte(`"UpToDatE"`), 1)
		}
	})
	service = again.intel(false)
	answer := service.documents[fixtureQEIdentityURL]
	answer.Header = elsewhere(t, k.document(t, fixtureQEIdentityURL), far).Header
	service.documents[fixtureQEIdentityURL] = answer
	if res, err := again.engineAt(at, service, false).VerifyEvidence(lenient(), env, reportData); err == nil {
		t.Fatalf("verified on a chain that is not Intel's: %+v", res)
	}
	if !slices.Contains(service.asked, fixtureQEIdentityURL) || slices.Contains(service.asked, far) {
		t.Fatalf("the verifier asked for %v", service.asked)
	}

	for url, want := range map[string]bool{
		fixtureTCBInfoURL: true, fixtureQEIdentityURL: true, fixturePCKCRLURL: true, pcs.PckCrlURL("processor"): true,
		fixtureRootCRLURL: true,
		far:               false,
		"https://certificates.trustedservices.intel.com/IntelSGXRootCA.der?x":                 false,
		"https://certificates.trustedservices.intel.com/Other.der":                            false,
		"https://api.trustedservices.intel.com/":                                              false,
		"https://api.trustedservices.intel.com.evil.example/tdx/certification/v4/qe/identity": false,
		"http://api.trustedservices.intel.com/tdx/certification/v4/qe/identity":               false,
		"": false,
	} {
		if got := intelDocument(url); got != want {
			t.Errorf("%q: one of Intel's documents: %v", url, got)
		}
	}
}

// An engine counts the vendor's documents it comes to hold, from the vendor
// or from whoever handed one over, and counts a document it already holds no
// second time. While the count stands, a verdict made earlier rests on the
// newest documents the engine has: a binder keeps its verdicts on ready
// guests by it.
func TestEngineCountsTheDocumentsItComesToHold(t *testing.T) {
	env, reportData := fixture(t)
	k := keptCollateral(t)
	at := k.newest.Add(10 * time.Minute)
	service, asked := k.intel(false), 0
	engine := k.cold(t, at, service)
	var counter DocumentCounter = engine
	if counter.Documents() != 0 {
		t.Fatalf("an engine that holds nothing counts %d documents", counter.Documents())
	}
	// A first verdict takes the four in: three that were handed over, and
	// the root CA CRL from Intel, since the verdict lets a secret go.
	ctx := WithCollateralSource(lenient(), handing(&asked, k.documents()...))
	if _, err := engine.VerifyEvidence(ctx, env, reportData); err != nil {
		t.Fatal(err)
	}
	first := counter.Documents()
	if first != uint64(len(k.files)) {
		t.Fatalf("after its first verdict the engine counts %d documents, and it judged by %d", first, len(k.files))
	}
	// A second verdict on the same documents takes none in.
	if _, err := engine.VerifyEvidence(ctx, env, reportData); err != nil {
		t.Fatal(err)
	}
	if got := counter.Documents(); got != first {
		t.Fatalf("a verdict on documents the engine held moved its count from %d to %d", first, got)
	}
	// The same document again, from Intel this time or handed over once
	// more, is no new document for the URL it is kept under.
	crl, ok := engine.cache.kept(fixtureRootCRLURL)
	if !ok {
		t.Fatal("the engine keeps no root CA CRL")
	}
	engine.cache.store(fixtureRootCRLURL, collateralEntry{header: crl.header, body: crl.body, fetched: at})
	handed := k.document(t, fixtureTCBInfoURL)
	engine.cache.storeStapled(fixtureTCBInfoURL, collateralEntry{header: handed.Header, body: handed.Body, fetched: at})
	if got := counter.Documents(); got != first {
		t.Fatalf("documents the engine already held moved its count from %d to %d", first, got)
	}
	// Another document under a URL is one: Intel's own answer for what was
	// handed over before, and a newer body in place of an older.
	engine.cache.store(fixtureTCBInfoURL, collateralEntry{header: handed.Header, body: handed.Body, fetched: at})
	if got := counter.Documents(); got != first+1 {
		t.Fatalf("Intel's own answer for a document that was handed over: the count went from %d to %d", first, got)
	}
	engine.cache.store(fixtureRootCRLURL, collateralEntry{header: crl.header, body: append([]byte("newer "), crl.body...), fetched: at})
	if got := counter.Documents(); got != first+2 {
		t.Fatalf("a newer root CA CRL: the count went from %d to %d", first+1, got)
	}
	// Another process over the same directory comes to hold what it reads
	// there, and counts it.
	second := k.engineAt(at.Add(time.Minute), k.intel(true), false)
	second.cache.dir = engine.cache.dir
	if second.Documents() != 0 {
		t.Fatal("an engine counts documents it has not read")
	}
	if _, ok := second.cache.kept(fixtureRootCRLURL); !ok || second.Documents() != 1 {
		t.Fatalf("an engine that read one kept document counts %d", second.Documents())
	}
}
