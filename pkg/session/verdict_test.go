package session_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// stepLog collects what a client reports of its way to the guest.
type stepLog struct {
	mu    sync.Mutex
	steps []string
}

func (l *stepLog) option() session.ClientOption {
	return session.Timed(func(step string, _ time.Duration) {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.steps = append(l.steps, step)
	})
}

func (l *stepLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.steps, ", ")
}

// quotes is how many fresh quotes the client asked the guest for.
func (l *stepLog) quotes() int {
	return strings.Count(l.String(), "request "+session.PathAttest)
}

// attested is the verdict of a first client that attested s, and the moment
// it was reached.
func attested(t *testing.T, s *served) (*session.Verdict, time.Time) {
	t.Helper()
	first, now := clientFor(t, "https://"+s.addr, s, sessiontest.Engine{})
	if _, err := first.Attest(within(t)); err != nil {
		t.Fatal(err)
	}
	v, ok := first.Verdict()
	if !ok {
		t.Fatal("a client that attested its guest has no verdict to keep")
	}
	return v, now.Now()
}

// next is a client of the owner's next process: a new one, given kept.
func next(t *testing.T, s *served, engine session.Engine, kept *session.Verdict, at time.Time) (*session.Client, *stepLog, *clock) {
	t.Helper()
	log := &stepLog{}
	client, err := session.NewClient("https://"+s.addr, s.policy, engine, s.signer, session.Kept(kept), log.option())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	now := &clock{now: at}
	client.SetNow(now.Now)
	return client, log, now
}

// The owner's next process takes the guest by its key: one dial, one
// handshake, the command. No quote is asked for and nothing is judged.
func TestKeptVerdictSparesTheQuoteAndTheJudgment(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	kept, at := attested(t, s)
	if want := at.Add(session.ServingVerdictTTL); !kept.Until.Equal(want) {
		t.Fatalf("the verdict stands until %s, want %s", kept.Until, want)
	}

	dir := t.TempDir()
	if err := session.WriteVerdict(dir, kept); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(dir, session.VerdictFile)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the kept verdict: %v, %v", info, err)
	}
	loaded, err := session.LoadVerdict(dir)
	if err != nil || !reflect.DeepEqual(loaded, kept) {
		t.Fatalf("read back %+v, %v; kept %+v", loaded, err, kept)
	}

	engine := &judging{}
	client, log, _ := next(t, s, engine, loaded, at)
	if !client.Pinned() {
		t.Fatal("a client given a verdict of its scope did not pin the key")
	}
	run(t, client)
	if got, want := log.String(), "dial, handshake, request /v1/exec"; got != want {
		t.Fatalf("steps: %s\n want: %s", got, want)
	}
	if n := engine.calls.Load(); n != 0 {
		t.Fatalf("the engine was asked %d times", n)
	}
	if client.AnotherKey() {
		t.Fatal("the client says its guest presented another key")
	}
	// Its own verdict is the one it was given: it judged nothing.
	if v, ok := client.Verdict(); !ok || !reflect.DeepEqual(v, kept) {
		t.Fatalf("its verdict is %+v, %v", v, ok)
	}
}

// A verdict names one key. A guest that presents another is refused in the
// handshake, before any request.
func TestKeptVerdictOfAnotherKeyRefusesTheGuest(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	// A policy that pins the bind takes a verdict only for the key the bind
	// names. This one pins the session, and takes the verdict's word.
	s.policy.Bind, s.policy.Tenant, s.policy.Session = nil, "acme", "sbx-1"
	kept, at := attested(t, s)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if kept.InstanceKey, err = x509.MarshalPKIXPublicKey(&other.PublicKey); err != nil {
		t.Fatal(err)
	}
	client, log, _ := next(t, s, &judging{}, kept, at)
	marker := session.ExecRequest{Argv: []string{"sh", "-c", `echo here > "$HOME/marker"`}}
	if _, err := client.Exec(within(t), marker); !isVerdict(err) {
		t.Fatalf("a guest with another key than the verdict's: %v", err)
	}
	if got := log.String(); got != "dial" {
		t.Fatalf("steps: %s", got)
	}
	if _, err := os.Stat(filepath.Join(s.home, "marker")); err == nil {
		t.Fatal("the command ran")
	}
	if !client.AnotherKey() {
		t.Fatal("the client does not say that its guest presented another key")
	}
	// A fresh attestation does not talk it round: the pin stays.
	if _, err := client.Attest(within(t)); !isVerdict(err) {
		t.Fatalf("attesting a guest with another key than the verdict's: %v", err)
	}
}

// bare is an engine that does not say what it requires.
type bare struct{ inner sessiontest.Engine }

func (e bare) VerifyEvidence(ctx context.Context, env teetypes.AttestationEvidence, reportData []byte) (*teetypes.VerificationResult, error) {
	return e.inner.VerifyEvidence(ctx, env, reportData)
}

// stricter requires something the engine that reached the verdict did not.
type stricter struct{ sessiontest.Engine }

func (stricter) Requirements() string { return "sessiontest, and more" }

// A verdict is taken only by a client that would have reached it the same
// way. Any other attests the guest itself, as if it had been given none.
func TestKeptVerdictIsTakenOnlyInItsScope(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	kept, at := attested(t, s)
	cases := []struct {
		name   string
		change func(v *session.Verdict, s *served) session.Engine
	}{
		{"a policy that also names the tenant", func(_ *session.Verdict, s *served) session.Engine {
			s.policy.Tenant = "acme"
			return sessiontest.Engine{}
		}},
		{"a policy that also names the session", func(_ *session.Verdict, s *served) session.Engine {
			s.policy.Session = "sbx-1"
			return sessiontest.Engine{}
		}},
		{"a policy that takes a guest whose sandbox does not run yet", func(_ *session.Verdict, s *served) session.Engine {
			s.policy.AllowBound = true
			return sessiontest.Engine{}
		}},
		{"a policy that takes any bind of the authority for the session", func(_ *session.Verdict, s *served) session.Engine {
			s.policy.Bind, s.policy.Tenant, s.policy.Session = nil, "acme", "sbx-1"
			return sessiontest.Engine{}
		}},
		{"an engine that requires more", func(*session.Verdict, *served) session.Engine { return stricter{} }},
		{"an engine that does not say what it requires", func(*session.Verdict, *served) session.Engine { return bare{} }},
		{"no scope, for an engine that does not say what it requires", func(v *session.Verdict, _ *served) session.Engine {
			v.Scope = ""
			return bare{}
		}},
		{"another schema", func(v *session.Verdict, _ *served) session.Engine {
			v.SchemaVersion = "c8s-session-verdict/v0"
			return sessiontest.Engine{}
		}},
		{"no time", func(v *session.Verdict, _ *served) session.Engine {
			v.Until = time.Time{}
			return sessiontest.Engine{}
		}},
		{"a key that is none", func(v *session.Verdict, _ *served) session.Engine {
			v.InstanceKey = []byte("not a key")
			return sessiontest.Engine{}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, changed := *kept, *s
			engine := tc.change(&v, &changed)
			client, log, _ := next(t, &changed, engine, &v, at)
			if client.Pinned() {
				t.Fatal("the client pinned the verdict's key")
			}
			run(t, client)
			if got, want := log.String(), "dial, serving_verdict, handshake, request /v1/attest, judgment, request /v1/exec"; got != want {
				t.Fatalf("steps: %s\n want: %s", got, want)
			}
		})
	}
	t.Run("none", func(t *testing.T) {
		client, log, _ := next(t, s, sessiontest.Engine{}, nil, at)
		run(t, client)
		if log.quotes() != 1 {
			t.Fatalf("steps: %s", log)
		}
	})
}

// Past its time a verdict still names the guest's key, and no longer vouches
// for its evidence: the next handshake judges the certificate again, as a
// client that stayed up would, and the verdict to keep is the new one.
func TestKeptVerdictPastItsTimeJudgesTheCertificateAgain(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	kept, at := attested(t, s)
	engine := &judging{}
	client, log, now := next(t, s, engine, kept, at)

	now.advance(session.ServingVerdictTTL - time.Second)
	run(t, client)
	if n := engine.calls.Load(); n != 0 {
		t.Fatalf("a second before its time the verdict was not taken: %d judgments", n)
	}
	client.Close()
	now.advance(time.Second)
	run(t, client)
	if got, want := log.String(), "dial, handshake, request /v1/exec, dial, serving_verdict, handshake, request /v1/exec"; got != want {
		t.Fatalf("steps: %s\n want: %s", got, want)
	}
	if n := engine.calls.Load(); n != 1 {
		t.Fatalf("at its time the certificate was judged %d times, want 1", n)
	}
	v, ok := client.Verdict()
	if !ok || !v.Until.After(kept.Until) {
		t.Fatalf("after the new judgment the verdict stands until %v, the kept one until %s", v, kept.Until)
	}
	if want := now.Now().Add(session.ServingVerdictTTL); v.Until.After(want) {
		t.Fatalf("the new verdict stands until %s, later than %s", v.Until, want)
	}

	// An engine that now refuses the evidence ends it there.
	engine.refuse.Store(true)
	client.Close()
	now.advance(2 * session.ServingVerdictTTL)
	if _, err := client.Exec(within(t), session.ExecRequest{Argv: []string{"true"}}); !isVerdict(err) {
		t.Fatalf("a certificate the engine refuses, behind a verdict past its time: %v", err)
	}
}

// A client has a verdict to keep once it has judged its guest, and only if
// its engine says what it requires.
func TestVerdictOnlyAfterAJudgment(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	client, _ := clientFor(t, "https://"+s.addr, s, sessiontest.Engine{})
	if v, ok := client.Verdict(); ok {
		t.Fatalf("a client that judged nothing has the verdict %+v", v)
	}
	if _, err := client.FetchEvidence(within(t)); err != nil {
		t.Fatal(err)
	}
	if v, ok := client.Verdict(); ok {
		t.Fatalf("a client that fetched evidence and judged none has the verdict %+v", v)
	}
	if client.Pinned() {
		t.Fatal("a client that judged nothing pinned a key")
	}

	silent, _ := clientFor(t, "https://"+s.addr, s, bare{})
	if _, err := silent.Attest(within(t)); err != nil {
		t.Fatal(err)
	}
	if v, ok := silent.Verdict(); ok {
		t.Fatalf("a client whose engine does not say what it requires has the verdict %+v", v)
	}
}

// One hand-over is several credentials. They leave on one attestation of
// this client's own, while it is fresh, and never on a kept verdict.
func TestCredentialsLeaveOnThisClientsOwnAttestation(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), func(o *session.BindOptions) {
		o.Policy.Credentials = []session.Credential{{Name: "first"}, {Name: "second"}}
	})
	put := func(t *testing.T, client *session.Client, name string) {
		t.Helper()
		if _, err := client.PutCredential(within(t), name, []byte("s3cret")); err != nil {
			t.Fatalf("credential %s: %v", name, err)
		}
	}

	kept, at := attested(t, s)
	client, log, now := next(t, s, sessiontest.Engine{}, nil, at)
	if _, err := client.Attest(within(t)); err != nil {
		t.Fatal(err)
	}
	put(t, client, "first")
	put(t, client, "second")
	if n := log.quotes(); n != 1 {
		t.Fatalf("an attestation and two credentials asked for %d quotes, want 1: %s", n, log)
	}
	now.advance(session.CredentialFreshness - time.Second)
	put(t, client, "first")
	if n := log.quotes(); n != 1 {
		t.Fatalf("a second before the attestation is too old it was made again: %s", log)
	}
	now.advance(time.Second)
	put(t, client, "first")
	if n := log.quotes(); n != 2 {
		t.Fatalf("a credential on an attestation %s old asked for %d quotes in all, want 2: %s", session.CredentialFreshness, n, log)
	}

	owner, log, _ := next(t, s, sessiontest.Engine{}, kept, at)
	if !owner.Pinned() {
		t.Fatal("the client did not take the verdict")
	}
	put(t, owner, "first")
	if got, want := log.String(), "dial, handshake, request /v1/attest, judgment, request /v1/credentials/first"; got != want {
		t.Fatalf("a credential on a kept verdict, steps: %s\n want: %s", got, want)
	}
}

// A file that is no verdict is an error, and a directory with none is not.
func TestLoadVerdict(t *testing.T) {
	dir := t.TempDir()
	if v, err := session.LoadVerdict(dir); v != nil || err != nil {
		t.Fatalf("a directory with no verdict: %+v, %v", v, err)
	}
	for name, content := range map[string]string{
		"not JSON":       "verdict",
		"another schema": `{"schemaVersion":"c8s-session-verdict/v0","instanceKey":"AA==","scope":"sha256:00","until":"2026-01-01T00:00:00Z"}`,
		"a field more":   `{"schemaVersion":"c8s-session-verdict/v1","instanceKey":"AA==","scope":"sha256:00","until":"2026-01-01T00:00:00Z","phase":"running"}`,
		"too large":      `{"schemaVersion":"c8s-session-verdict/v1","scope":"` + strings.Repeat("a", 5000) + `"}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, session.VerdictFile), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if v, err := session.LoadVerdict(dir); err == nil {
			t.Errorf("%s was read as %+v", name, v)
		}
	}
	// Writing replaces what is there and leaves nothing else behind.
	v := &session.Verdict{SchemaVersion: session.VerdictSchema, InstanceKey: []byte{1}, Scope: "sha256:00", Until: time.Unix(1_800_000_000, 0).UTC()}
	if err := session.WriteVerdict(dir, v); err != nil {
		t.Fatal(err)
	}
	if got, err := session.LoadVerdict(dir); err != nil || !reflect.DeepEqual(got, v) {
		t.Fatalf("read back %+v, %v", got, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("the directory holds %d files, %v", len(entries), err)
	}
}

// Every part of a policy, and what the engine requires, is in the scope: a
// change to any one of them is another scope.
func TestScopeCoversThePolicyAndTheEngine(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	other := sessiontest.NewTD()
	identity := func(td *sessiontest.TD) runtimemeasure.ImageIdentity {
		id, err := runtimemeasure.LoadImageManifest(td.WriteManifest(t))
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	base := session.Policy{
		Image: s.policy.Image, LaunchKey: []byte("launch key"), Launch: []byte("launch"), Authority: []byte("authority"),
		Bind: []byte("bind"), Tenant: "tenant", Session: "session",
	}
	scope := session.ScopeOf(base, sessiontest.Engine{})
	if !strings.HasPrefix(scope, "sha256:") || len(scope) != len("sha256:")+64 {
		t.Fatalf("scope = %q", scope)
	}
	if again := session.ScopeOf(base, sessiontest.Engine{}); again != scope {
		t.Fatalf("the same policy and engine gave %s and %s", scope, again)
	}
	// like is a TD of the same image as s's, for one change.
	like := func() *sessiontest.TD {
		td := sessiontest.NewTD()
		td.MRTD, td.RTMR[0], td.RTMR[1], td.RTMR[2] = s.td.MRTD, s.td.RTMR[0], s.td.RTMR[1], s.td.RTMR[2]
		return td
	}
	same, registers, launch := like(), like(), like()
	registers.RTMR[1][0] ^= 1
	launch.MRTD[0] ^= 1
	if got := session.ScopeOf(session.Policy{Image: identity(same)}, sessiontest.Engine{}); got != session.ScopeOf(session.Policy{Image: s.policy.Image}, sessiontest.Engine{}) {
		t.Fatal("two readings of one image have two scopes")
	}
	changes := map[string]func(p *session.Policy){
		"another image":             func(p *session.Policy) { p.Image = identity(other) },
		"another launch digest":     func(p *session.Policy) { p.Image = identity(launch) },
		"another register":          func(p *session.Policy) { p.Image = identity(registers) },
		"another launch key":        func(p *session.Policy) { p.LaunchKey = []byte("launch kez") },
		"another launch document":   func(p *session.Policy) { p.Launch = []byte("launcg") },
		"no launch document":        func(p *session.Policy) { p.Launch = nil },
		"another authority":         func(p *session.Policy) { p.Authority = []byte("authoritz") },
		"another bind":              func(p *session.Policy) { p.Bind = []byte("bine") },
		"another tenant":            func(p *session.Policy) { p.Tenant = "tenanu" },
		"another session":           func(p *session.Policy) { p.Session = "sandboy" },
		"a staged guest allowed":    func(p *session.Policy) { p.AllowBound = true },
		"an unbound guest allowed":  func(p *session.Policy) { p.AllowReady = true },
		"a pinned machine required": func(p *session.Policy) { p.RequireMachine = true },
		// Two fields that would read alike if they ran into one another.
		"the tenant's end in the session": func(p *session.Policy) { p.Tenant, p.Session = "tenan", "tsandbox" },
	}
	seen := map[string]string{scope: "the policy itself"}
	for name, change := range changes {
		p := base
		change(&p)
		got := session.ScopeOf(p, sessiontest.Engine{})
		if before, dup := seen[got]; dup {
			t.Errorf("%s has the scope of %s", name, before)
		}
		seen[got] = name
	}
	if got := session.ScopeOf(base, stricter{}); seen[got] != "" {
		t.Errorf("an engine that requires more has the scope of %s", seen[got])
	}
	if got := session.ScopeOf(base, bare{}); got != "" {
		t.Errorf("an engine that does not say what it requires has the scope %s", got)
	}
}

// What decides a verdict of the hardware engine is in its requirements, and
// where it keeps Intel's documents is not.
func TestEngineRequirements(t *testing.T) {
	requirements := func(opts session.EngineOptions) string {
		return session.NewEngine(opts).(session.Described).Requirements()
	}
	want := requirements(session.EngineOptions{})
	if got := requirements(session.EngineOptions{CollateralCacheDir: t.TempDir()}); got != want {
		t.Errorf("the same requirements read %q and %q", want, got)
	}
	for name, opts := range map[string]session.EngineOptions{
		"fresh collateral only":               {FreshCollateralOnly: true},
		"Intel's collateral from Intel alone": {OwnCollateralOnly: true},
	} {
		if got := requirements(opts); got == want {
			t.Errorf("%s reads like the base: %q", name, got)
		}
	}
}

// expiring is the test engine with a finding whose collateral ends.
type expiring struct {
	sessiontest.Engine
	at time.Time
}

func (e expiring) VerifyEvidence(ctx context.Context, env teetypes.AttestationEvidence, reportData []byte) (*teetypes.VerificationResult, error) {
	res, err := e.Engine.VerifyEvidence(ctx, env, reportData)
	if err != nil {
		return nil, err
	}
	if res.Claims.PlatformData == nil {
		res.Claims.PlatformData = map[string]any{}
	}
	res.Claims.PlatformData[session.CollateralClaim] = &session.CollateralFinding{Expires: e.at}
	return res, nil
}

// A verdict stands for the hour its collateral is reused, and never past the
// end of the certificate that carried the key or of the collateral under it.
func TestVerdictStandsNoLongerThanWhatItRestsOn(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	leaf := dialUnverified(t, s.addr).ConnectionState().PeerCertificates[0]
	until := func(t *testing.T, client *session.Client) time.Time {
		t.Helper()
		v, ok := client.Verdict()
		if !ok {
			t.Fatal("no verdict")
		}
		return v.Until
	}

	t.Run("the certificate's end, by an attestation", func(t *testing.T) {
		client, now := clientFor(t, "https://"+s.addr, s, sessiontest.Engine{})
		now.advance(leaf.NotAfter.Sub(now.Now()) - 10*time.Minute)
		if _, err := client.Attest(within(t)); err != nil {
			t.Fatal(err)
		}
		if got := until(t, client); !got.Equal(leaf.NotAfter) {
			t.Fatalf("the verdict stands until %s, the certificate ends %s", got, leaf.NotAfter)
		}
	})
	t.Run("the certificate's end, by the certificate's judgment", func(t *testing.T) {
		kept, at := attested(t, s)
		client, _, now := next(t, s, sessiontest.Engine{}, kept, at)
		now.advance(leaf.NotAfter.Sub(at) - 10*time.Minute)
		run(t, client)
		if got := until(t, client); !got.Equal(leaf.NotAfter) {
			t.Fatalf("the verdict stands until %s, the certificate ends %s", got, leaf.NotAfter)
		}
	})
	t.Run("the collateral's end, by an attestation", func(t *testing.T) {
		at := time.Now().Add(20 * time.Minute).UTC().Round(0)
		client, _ := clientFor(t, "https://"+s.addr, s, expiring{at: at})
		if _, err := client.Attest(within(t)); err != nil {
			t.Fatal(err)
		}
		if got := until(t, client); !got.Equal(at) {
			t.Fatalf("the verdict stands until %s, the collateral ends %s", got, at)
		}
	})
	t.Run("the collateral's end, by the certificate's judgment", func(t *testing.T) {
		kept, at := attested(t, s)
		ends := at.Add(session.ServingVerdictTTL + 20*time.Minute).UTC().Round(0)
		client, _, now := next(t, s, expiring{at: ends}, kept, at)
		now.advance(session.ServingVerdictTTL)
		run(t, client)
		if got := until(t, client); !got.Equal(ends) {
			t.Fatalf("the verdict stands until %s, the collateral ends %s", got, ends)
		}
	})
	for name, at := range map[string]time.Time{
		"collateral that ends later than the hour": time.Now().Add(30 * 24 * time.Hour),
		"a finding that says no end":               {},
	} {
		t.Run(name, func(t *testing.T) {
			client, now := clientFor(t, "https://"+s.addr, s, expiring{at: at})
			if _, err := client.Attest(within(t)); err != nil {
				t.Fatal(err)
			}
			if got, want := until(t, client), now.Now().Add(session.ServingVerdictTTL); !got.Equal(want) {
				t.Fatalf("the verdict stands until %s, want %s", got, want)
			}
		})
	}
}

// The scope of one fixed policy and engine, to the bit. A change here voids
// every verdict that was kept before it, which costs each binding one
// attestation and is otherwise harmless: change the value with the rule.
func TestScopeOfAFixedPolicy(t *testing.T) {
	td := sessiontest.NewTD()
	for i := range td.MRTD {
		td.MRTD[i], td.RTMR[0][i], td.RTMR[1][i], td.RTMR[2][i] = 0x11, 0x22, 0x33, 0x44
	}
	identity, err := runtimemeasure.LoadImageManifest(td.WriteManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	policy := session.Policy{
		Image: identity, LaunchKey: []byte("launch key"), Launch: []byte("launch"), Authority: []byte("authority"),
		Bind: []byte("bind"), Tenant: "tenant", Session: "session",
	}
	const want = "sha256:ffcbb228e723051c927fc15acea285deb0de63c5c8c18c9b5ccbcaaceb176f05"
	if got := session.ScopeOf(policy, sessiontest.Engine{}); got != want {
		t.Fatalf("scope = %s, want %s", got, want)
	}
	// A verdict reached under an allowance is of another scope, so that a
	// policy that accepts less never takes it.
	lenient := policy
	lenient.AcceptTCBStatus = []string{"OutOfDate"}
	if got := session.ScopeOf(lenient, sessiontest.Engine{}); got == want || got == "" {
		t.Fatalf("a policy that accepts OutOfDate has scope %s", got)
	}
}

// A verdict file is held to a key's file mode: one that its group or anyone
// else could have written is not read.
func TestLoadVerdictRefusesAFileOthersCouldWrite(t *testing.T) {
	dir := t.TempDir()
	v := &session.Verdict{SchemaVersion: session.VerdictSchema, InstanceKey: []byte{1}, Scope: "sha256:00", Until: time.Unix(1_800_000_000, 0).UTC()}
	if err := session.WriteVerdict(dir, v); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, session.VerdictFile)
	for mode, readable := range map[os.FileMode]bool{0o600: true, 0o400: true, 0o644: true, 0o620: false, 0o602: false, 0o666: false} {
		if err := os.Chmod(file, mode); err != nil {
			t.Fatal(err)
		}
		got, err := session.LoadVerdict(dir)
		if readable && (err != nil || !reflect.DeepEqual(got, v)) {
			t.Errorf("mode %s: read %+v, %v", mode, got, err)
		}
		if !readable && err == nil {
			t.Errorf("mode %s: the verdict was read", mode)
		}
	}
}

// A verdict file another user owns is not read, whatever its mode: whoever
// could write it could have put any key in it.
func TestLoadVerdictRefusesAnotherUsersFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the file has to be given to another user")
	}
	dir := t.TempDir()
	v := &session.Verdict{SchemaVersion: session.VerdictSchema, InstanceKey: []byte{1}, Scope: "sha256:00", Until: time.Unix(1_800_000_000, 0).UTC()}
	if err := session.WriteVerdict(dir, v); err != nil {
		t.Fatal(err)
	}
	if got, err := session.LoadVerdict(dir); err != nil || !reflect.DeepEqual(got, v) {
		t.Fatalf("this user's own verdict: read %+v, %v", got, err)
	}
	if err := os.Chown(filepath.Join(dir, session.VerdictFile), 12345, 12345); err != nil {
		t.Fatal(err)
	}
	if got, err := session.LoadVerdict(dir); err == nil {
		t.Fatalf("another user's verdict was read: %+v", got)
	}
}

// closing counts how often a connection is closed.
type closing struct {
	net.Conn
	closed *atomic.Int32
}

func (c closing) Close() error {
	c.closed.Add(1)
	return c.Conn.Close()
}

// Reach leaves one connection waiting for the client's next request. A
// second call finds it and opens no other. One that waited past its time is
// closed when Reach puts a new one in its place.
func TestReachClosesTheConnectionItReplaces(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	kept, at := attested(t, s)
	client, _, now := next(t, s, sessiontest.Engine{}, kept, at)
	var mu sync.Mutex
	var dialed []*atomic.Int32
	client.SetDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		closed := new(atomic.Int32)
		mu.Lock()
		dialed = append(dialed, closed)
		mu.Unlock()
		return closing{conn, closed}, nil
	})
	closes := func() []int32 {
		mu.Lock()
		defer mu.Unlock()
		var n []int32
		for _, closed := range dialed {
			n = append(n, closed.Load())
		}
		return n
	}

	for range 2 {
		if err := client.Reach(within(t)); err != nil {
			t.Fatal(err)
		}
	}
	if got := closes(); !reflect.DeepEqual(got, []int32{0}) {
		t.Fatalf("after two calls, closes by connection: %v; want one connection, waiting", got)
	}
	now.advance(session.ConnIdle)
	if err := client.Reach(within(t)); err != nil {
		t.Fatal(err)
	}
	if got := closes(); len(got) != 2 || got[0] == 0 || got[1] != 0 {
		t.Fatalf("after its time, closes by connection: %v; want the first closed and a second waiting", got)
	}
}

// Under a policy that pins a bind, a verdict is taken only for the
// key that document names. A bind that cannot be read names none.
func TestKeptVerdictUnderABindThatCannotBeRead(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	kept, _ := attested(t, s)
	policy := s.policy
	policy.Authority = []byte(keyPEM(t, newKey(t)))
	policy.Bind = []byte("not a bind")
	v := *kept
	v.Scope = session.ScopeOf(policy, sessiontest.Engine{})
	client, err := session.NewClient("https://"+s.addr, policy, sessiontest.Engine{}, s.signer, session.Kept(&v))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if client.Pinned() {
		t.Fatal("a verdict was taken under a bind that names no key")
	}
	// The same verdict under the same policy without the bind is taken: it
	// was the bind that refused it.
	policy.Bind, policy.Tenant, policy.Session = nil, "acme", "sbx-1"
	v.Scope = session.ScopeOf(policy, sessiontest.Engine{})
	open, err := session.NewClient("https://"+s.addr, policy, sessiontest.Engine{}, s.signer, session.Kept(&v))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(open.Close)
	if !open.Pinned() {
		t.Fatal("the verdict was not taken under the policy without the bind")
	}
}
