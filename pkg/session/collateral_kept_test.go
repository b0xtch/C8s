package session

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Intel's documents for the fixture's platform, as a verification kept them
// on 2026-10-02: TestCollateralDirectoryAgainstIntelPCS writes them when
// C8S_TEST_COLLATERAL_OUT names this directory. Intel dates them until
// 2026-11-01.
//
//go:embed testdata/collateral
var keptFixture embed.FS

// kept is those documents in a directory of the test's.
type kept struct {
	dir string
	// oldest and newest are when the first and the last of them were fetched.
	oldest, newest time.Time
	files          map[string]collateralFile
}

func keptCollateral(t testing.TB) *kept {
	t.Helper()
	k := &kept{dir: t.TempDir(), files: map[string]collateralFile{}}
	entries, err := keptFixture.ReadDir("testdata/collateral")
	if err != nil || len(entries) != 4 {
		t.Fatalf("the fixture holds %d documents, %v", len(entries), err)
	}
	for _, entry := range entries {
		data, err := keptFixture.ReadFile("testdata/collateral/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		var file collateralFile
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatal(err)
		}
		k.files[entry.Name()] = file
		if k.oldest.IsZero() || file.Fetched.Before(k.oldest) {
			k.oldest = file.Fetched
		}
		if file.Fetched.After(k.newest) {
			k.newest = file.Fetched
		}
	}
	if !k.oldest.Before(k.newest) {
		t.Fatal("fixture: the documents must differ in when they were fetched")
	}
	k.write(t, func(*collateralFile) {})
	return k
}

// write puts the documents into the directory, each changed by change.
func (k *kept) write(t testing.TB, change func(*collateralFile)) {
	t.Helper()
	for name, file := range k.files {
		change(&file)
		data, err := json.Marshal(file)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(k.dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// fetchedOnDisk is when the directory says its documents were fetched.
func (k *kept) fetchedOnDisk(t *testing.T) (oldest, newest time.Time) {
	t.Helper()
	for name := range k.files {
		data, err := os.ReadFile(filepath.Join(k.dir, name))
		if err != nil {
			t.Fatal(err)
		}
		var file collateralFile
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatal(err)
		}
		if oldest.IsZero() || file.Fetched.Before(oldest) {
			oldest = file.Fetched
		}
		if file.Fetched.After(newest) {
			newest = file.Fetched
		}
	}
	return oldest, newest
}

// intel serves the fixture's documents as Intel's service did, or nothing.
type intel struct {
	documents map[string]collateralFile
	down      bool
	// mu guards what follows: fetches ahead of need run side by side.
	mu    sync.Mutex
	calls int
	// asked is every URL it was asked for, in order.
	asked []string
}

func (k *kept) intel(down bool) *intel {
	served := &intel{documents: map[string]collateralFile{}, down: down}
	for _, file := range k.files {
		served.documents[file.URL] = file
	}
	return served
}

func (i *intel) Get(url string) (map[string][]string, []byte, error) {
	i.mu.Lock()
	i.calls++
	i.asked = append(i.asked, url)
	i.mu.Unlock()
	file, ok := i.documents[url]
	if i.down || !ok {
		return nil, nil, errors.New("no route to Intel's service")
	}
	return file.Header, file.Body, nil
}

// engineAt is an engine whose clock reads at, for the age of what it keeps
// and for Intel's dates alike.
func (k *kept) engineAt(at time.Time, service *intel, freshOnly bool) *dcapEngine {
	cache := newCollateralCache(k.dir)
	cache.now = func() time.Time { return at }
	return &dcapEngine{cache: cache, fetch: service, freshOnly: freshOnly}
}

// lenient is a context under which the fixture verifies: the captured
// platform's TCB has been superseded since.
func lenient() context.Context {
	return WithAcceptedTCB(context.Background(), acceptableTCBStatuses)
}

func isOutage(err error) bool {
	var verdict *VerificationError
	return err != nil && !errors.As(err, &verdict) && strings.Contains(err.Error(), "collateral unavailable")
}

// Real evidence judged against Intel's real documents, with no network: what
// the engine keeps, for how long, what it does when Intel cannot be asked,
// and what the verdict says about it.
func TestVerdictOnKeptCollateral(t *testing.T) {
	env, reportData := fixture(t)
	ctx := lenient()

	t.Run("within the hour nothing is fetched", func(t *testing.T) {
		k := keptCollateral(t)
		service := k.intel(true)
		res, err := k.engineAt(k.newest.Add(10*time.Minute), service, false).VerifyEvidence(ctx, env, reportData)
		if err != nil || !res.CollateralVerified || service.calls != 0 {
			t.Fatalf("%v, after %d fetches", err, service.calls)
		}
		finding := CollateralOf(res)
		if finding == nil || finding.Platform == "" || finding.QuotingEnclave == "" {
			t.Fatalf("finding %+v", finding)
		}
		// The verdict is as old as the oldest document under it.
		if !finding.Fetched.Equal(k.oldest) || finding.Stale {
			t.Fatalf("collateral fetched %s (stale: %v), want %s", finding.Fetched, finding.Stale, k.oldest)
		}
	})

	t.Run("past the hour it is fetched again and kept", func(t *testing.T) {
		k := keptCollateral(t)
		service, at := k.intel(false), k.newest.Add(2*time.Hour)
		res, err := k.engineAt(at, service, false).VerifyEvidence(ctx, env, reportData)
		if err != nil || service.calls != len(k.files) {
			t.Fatalf("%v, after %d fetches", err, service.calls)
		}
		if finding := CollateralOf(res); !finding.Fetched.Equal(at) || finding.Stale {
			t.Fatalf("collateral fetched %s (stale: %v), want %s", finding.Fetched, finding.Stale, at)
		}
		if oldest, newest := k.fetchedOnDisk(t); !oldest.Equal(at) || !newest.Equal(at) {
			t.Fatalf("the directory says %s to %s, want %s", oldest, newest, at)
		}
	})

	t.Run("past the hour with Intel out of reach the kept copy is used, and the verdict says so", func(t *testing.T) {
		k := keptCollateral(t)
		service := k.intel(true)
		res, err := k.engineAt(k.newest.Add(2*time.Hour), service, false).VerifyEvidence(ctx, env, reportData)
		if err != nil || service.calls == 0 {
			t.Fatalf("%v, after %d fetches: Intel must be asked first", err, service.calls)
		}
		if finding := CollateralOf(res); !finding.Fetched.Equal(k.oldest) || !finding.Stale {
			t.Fatalf("collateral fetched %s (stale: %v), want %s and stale", finding.Fetched, finding.Stale, k.oldest)
		}
		// Nothing new was learned, so nothing is written as if it had been.
		if oldest, newest := k.fetchedOnDisk(t); !oldest.Equal(k.oldest) || !newest.Equal(k.newest) {
			t.Fatalf("the directory now says %s to %s", oldest, newest)
		}
	})

	t.Run("a policy that wants fresh collateral gets an outage instead", func(t *testing.T) {
		k := keptCollateral(t)
		res, err := k.engineAt(k.newest.Add(2*time.Hour), k.intel(true), true).VerifyEvidence(ctx, env, reportData)
		if !isOutage(err) {
			t.Fatalf("%+v, %v: want an outage and no verdict", res, err)
		}
		// Within the hour that policy is served from the directory like any other.
		if _, err := k.engineAt(k.newest.Add(10*time.Minute), k.intel(true), true).VerifyEvidence(ctx, env, reportData); err != nil {
			t.Fatal(err)
		}
	})

	// Intel dates these documents until 2026-11-01. Past that no kept copy
	// carries a verdict, however it came to be used, and that it does not
	// says nothing about the evidence.
	expired := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	t.Run("past Intel's own date a kept copy is not used", func(t *testing.T) {
		k := keptCollateral(t)
		service := k.intel(true)
		res, err := k.engineAt(expired, service, false).VerifyEvidence(ctx, env, reportData)
		if !isOutage(err) || service.calls == 0 {
			t.Fatalf("%+v, %v after %d fetches: want an outage and no verdict", res, err, service.calls)
		}
	})
	t.Run("nor is one whose file calls it new", func(t *testing.T) {
		k := keptCollateral(t)
		k.write(t, func(file *collateralFile) { file.Fetched = expired.Add(-time.Minute) })
		service := k.intel(true)
		res, err := k.engineAt(expired, service, false).VerifyEvidence(ctx, env, reportData)
		if !isOutage(err) || service.calls == 0 {
			t.Fatalf("%+v, %v after %d fetches: want an outage and no verdict", res, err, service.calls)
		}
	})
	t.Run("nor one from the future", func(t *testing.T) {
		k := keptCollateral(t)
		res, err := k.engineAt(k.oldest.Add(-time.Minute), k.intel(true), false).VerifyEvidence(ctx, env, reportData)
		if !isOutage(err) {
			t.Fatalf("%+v, %v: a document fetched after now is no document", res, err)
		}
	})
}

// The root CA CRL's own dates do not say how old it is, so the finding says
// when this verifier had it from Intel. A CRL fetched anew on request is the
// one the next verification takes, in place of the older one it kept.
func TestFindingSaysWhenTheRootCRLCameFromIntel(t *testing.T) {
	env, reportData := fixture(t)
	ctx := lenient()
	k := keptCollateral(t)
	var root time.Time
	for _, file := range k.files {
		if file.URL == fixtureRootCRLURL {
			root = file.Fetched
		}
	}
	if root.IsZero() {
		t.Fatal("fixture: no root CA CRL among the documents")
	}
	at := k.newest.Add(10 * time.Minute)
	res, err := k.engineAt(at, k.intel(true), false).VerifyEvidence(ctx, env, reportData)
	if err != nil {
		t.Fatal(err)
	}
	if finding := CollateralOf(res); !finding.RootCRLFetched.Equal(root) {
		t.Fatalf("root CA CRL fetched %s, want the kept one's %s", finding.RootCRLFetched, root)
	}

	service := k.intel(false)
	engine := k.engineAt(at, service, false)
	if err := engine.Refetch(ctx); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(service.asked, []string{fixtureRootCRLURL}) {
		t.Fatalf("a refetch asked Intel for %v", service.asked)
	}
	res, err = engine.VerifyEvidence(ctx, env, reportData)
	if err != nil || service.calls != 1 {
		t.Fatalf("%v, after %d fetches", err, service.calls)
	}
	if finding := CollateralOf(res); !finding.RootCRLFetched.Equal(at) {
		t.Fatalf("root CA CRL fetched %s, want the refetch at %s", finding.RootCRLFetched, at)
	}

	// With Intel out of reach a refetch fails and the kept CRL stays in use.
	down := k.engineAt(at, k.intel(true), false)
	if err := down.Refetch(ctx); err == nil {
		t.Fatal("a refetch with Intel out of reach succeeded")
	}
	if res, err := down.VerifyEvidence(ctx, env, reportData); err != nil || !CollateralOf(res).RootCRLFetched.Equal(at) {
		t.Fatalf("%v: after a failed refetch the verdict rests on the CRL of %s", err, CollateralOf(res).RootCRLFetched)
	}
}

// The platform, its TDX module and its quoting enclave are judged one by
// one against Intel's documents. A level that is behind is refused by name
// under a policy that accepts nothing but UpToDate, passes under one that
// names its status, and is in the finding either way. Revoked passes under
// no policy.
func TestPlatformBehindIntelsLevelNeedsItsStatusNamed(t *testing.T) {
	env, reportData := fixture(t)
	k := keptCollateral(t)
	at := k.newest.Add(10 * time.Minute)

	res, err := k.engineAt(at, k.intel(true), false).VerifyEvidence(context.Background(), env, reportData)
	var verdict *VerificationError
	if !errors.As(err, &verdict) || res != nil {
		t.Fatalf("under a policy that names no status: %+v, %v", res, err)
	}
	if !strings.Contains(err.Error(), "TCB status is OutOfDate, which this policy does not accept") {
		t.Fatalf("the refusal does not name the status: %v", err)
	}
	// A refusal for the platform's level keeps nothing and asks Intel for
	// nothing more: the documents were Intel's.
	service := k.intel(false)
	if _, err := k.engineAt(at, service, false).VerifyEvidence(context.Background(), env, reportData); err == nil || service.calls != 0 {
		t.Fatalf("%v, after %d fetches", err, service.calls)
	}

	// Another status than the platform's opens nothing.
	other := WithAcceptedTCB(context.Background(), []string{"SWHardeningNeeded"})
	if _, err := k.engineAt(at, k.intel(true), false).VerifyEvidence(other, env, reportData); !errors.As(err, &verdict) {
		t.Fatalf("under a policy that names another status: %v", err)
	}
	// Nor does naming Revoked, or a status Intel does not have.
	odd := WithAcceptedTCB(context.Background(), []string{TCBRevoked, "Fine"})
	if _, err := k.engineAt(at, k.intel(true), false).VerifyEvidence(odd, env, reportData); !errors.As(err, &verdict) {
		t.Fatalf("under a policy that names Revoked: %v", err)
	}

	named := WithAcceptedTCB(context.Background(), []string{"OutOfDate"})
	res, err = k.engineAt(at, k.intel(true), false).VerifyEvidence(named, env, reportData)
	if err != nil {
		t.Fatal(err)
	}
	finding := CollateralOf(res)
	if finding == nil || finding.UpToDate() || finding.QuotingEnclave == "" || finding.Platform == "" {
		t.Fatalf("finding %+v", finding)
	}
	behind := 0
	for _, c := range finding.components() {
		if c.status == "OutOfDate" {
			behind++
		} else if c.status != TCBUpToDate {
			t.Errorf("%s is %s", c.name, c.status)
		}
	}
	if behind == 0 || len(finding.Advisories) == 0 {
		t.Fatalf("finding %+v: want a level behind, with its advisories", finding)
	}
}

func TestJudgeTCB(t *testing.T) {
	current := TCBFinding{Platform: TCBUpToDate, Module: TCBUpToDate, QuotingEnclave: TCBUpToDate}
	if err := current.judge(nil); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		finding  TCBFinding
		accepted []string
		want     string
	}{
		"the platform behind":            {TCBFinding{Platform: "OutOfDate", Module: TCBUpToDate, QuotingEnclave: TCBUpToDate}, nil, "platform TCB status is OutOfDate"},
		"the module behind":              {TCBFinding{Platform: TCBUpToDate, Module: "OutOfDate", QuotingEnclave: TCBUpToDate}, nil, "TDX module TCB status is OutOfDate"},
		"the quoting enclave behind":     {TCBFinding{Platform: TCBUpToDate, QuotingEnclave: "OutOfDate"}, nil, "quoting enclave TCB status is OutOfDate"},
		"another status named":           {TCBFinding{Platform: "OutOfDate", QuotingEnclave: TCBUpToDate}, []string{"SWHardeningNeeded"}, "platform TCB status is OutOfDate"},
		"one of two named":               {TCBFinding{Platform: "OutOfDate", Module: "SWHardeningNeeded", QuotingEnclave: TCBUpToDate}, []string{"OutOfDate"}, "TDX module TCB status is SWHardeningNeeded"},
		"revoked, though named":          {TCBFinding{Platform: TCBRevoked, QuotingEnclave: TCBUpToDate}, []string{TCBRevoked}, "platform TCB level is revoked"},
		"a revoked quoting enclave":      {TCBFinding{Platform: TCBUpToDate, QuotingEnclave: TCBRevoked}, acceptableTCBStatuses, "quoting enclave TCB level is revoked"},
		"a status Intel does not have":   {TCBFinding{Platform: "Fine", QuotingEnclave: TCBUpToDate}, acceptableTCBStatuses, "platform TCB status is Fine"},
		"no status at all for the level": {TCBFinding{Platform: "", QuotingEnclave: TCBUpToDate}, acceptableTCBStatuses, "platform TCB status is "},
	} {
		err := tc.finding.judge(tc.accepted)
		var verdict *VerificationError
		if !errors.As(err, &verdict) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want a refusal naming %q", name, err, tc.want)
		}
	}
	both := TCBFinding{Platform: "OutOfDate", Module: "SWHardeningNeeded", QuotingEnclave: "OutOfDateConfigurationNeeded"}
	if err := both.judge(acceptableTCBStatuses); err != nil {
		t.Fatalf("every status named: %v", err)
	}
}

// A list of accepted statuses has one form: Intel's names that can be
// accepted, sorted, each once.
func TestValidateTCBStatuses(t *testing.T) {
	for _, ok := range [][]string{nil, {"OutOfDate"}, {"OutOfDate", "SWHardeningNeeded"}, {"ConfigurationAndSWHardeningNeeded", "ConfigurationNeeded", "OutOfDate", "OutOfDateConfigurationNeeded", "SWHardeningNeeded"}} {
		if err := ValidateTCBStatuses(ok); err != nil {
			t.Errorf("%v: %v", ok, err)
		}
	}
	for name, bad := range map[string][]string{
		"Revoked":    {"Revoked"},
		"UpToDate":   {"UpToDate"},
		"made up":    {"Fine"},
		"empty":      {""},
		"unsorted":   {"SWHardeningNeeded", "OutOfDate"},
		"twice":      {"OutOfDate", "OutOfDate"},
		"lower case": {"outofdate"},
	} {
		if err := ValidateTCBStatuses(bad); err == nil {
			t.Errorf("%s: %v was taken", name, bad)
		}
	}
	policy := Policy{AcceptTCBStatus: []string{"Revoked"}}
	if err := policy.validate(); err == nil {
		t.Error("a policy that accepts Revoked was taken")
	}
}

// A fetch a verification started keeps nothing ahead of need, so a refetch
// that waited on one keeps its answer itself, unless a later one is there.
func TestKeepAheadKeepsTheLaterFetch(t *testing.T) {
	cache := newCollateralCache("")
	url := fixtureRootCRLURL
	at := time.Now()
	cache.now = func() time.Time { return at }
	f := cache.fly(context.Background(), &countingGetter{}, url, false)
	<-f.done
	if _, ok := cache.ahead(url); ok {
		t.Fatal("a verification's fetch was kept ahead of need")
	}
	cache.keepAhead(url, f.entry)
	if entry, ok := cache.ahead(url); !ok || !entry.fetched.Equal(at) {
		t.Fatalf("kept ahead: %v, fetched %s", ok, entry.fetched)
	}
	older := f.entry
	older.fetched = at.Add(-time.Minute)
	cache.keepAhead(url, older)
	if entry, _ := cache.ahead(url); !entry.fetched.Equal(at) {
		t.Fatalf("an older fetch replaced a later one: fetched %s", entry.fetched)
	}
}

// Each option reaches the engine that judges.
func TestCollateralOptions(t *testing.T) {
	for _, set := range []bool{false, true} {
		engine := NewEngine(EngineOptions{FreshCollateralOnly: set})
		if got := engine.(*dcapEngine); got.freshOnly != set || got.ownOnly {
			t.Errorf("FreshCollateralOnly %v made an engine with fresh only %v, own only %v", set, got.freshOnly, got.ownOnly)
		}
		engine = NewEngine(EngineOptions{OwnCollateralOnly: set})
		if got := engine.(*dcapEngine); got.ownOnly != set || got.freshOnly {
			t.Errorf("OwnCollateralOnly %v made an engine with own only %v, fresh only %v", set, got.ownOnly, got.freshOnly)
		}
	}
}

// Every date a verification checks is checked at one time: a field the
// verifier's library adds later must not fall back to the wall clock.
func TestAllAtSetsEveryTime(t *testing.T) {
	now := time.Date(2026, 10, 2, 1, 9, 18, 0, time.UTC)
	set := reflect.ValueOf(*allAt(now))
	for i := 0; i < set.NumField(); i++ {
		if at, ok := set.Field(i).Interface().(time.Time); !ok || !at.Equal(now) {
			t.Errorf("%s is %v", set.Type().Field(i).Name, set.Field(i).Interface())
		}
	}
}
