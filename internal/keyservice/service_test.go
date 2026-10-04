package keyservice_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	agratls "github.com/confidential-dot-ai/attestation-go/ratls"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/keyservice/keyservicetest"
	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	api "github.com/confidential-dot-ai/c8s/pkg/session/keyservice"
	"github.com/confidential-dot-ai/c8s/pkg/session/sessionsim"
)

func within(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// owner is a tenant's authority: its key, and a signer of requests under it.
type owner struct {
	key    *ecdsa.PrivateKey
	pub    []byte
	signer *operatorauth.Signer
}

func newOwner(t *testing.T) *owner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	o := &owner{key: key}
	if o.pub, err = session.PublicKeyPEM(&key.PublicKey); err != nil {
		t.Fatal(err)
	}
	if o.signer, err = operatorauth.NewSignerFromKeyPEM(private); err != nil {
		t.Fatal(err)
	}
	return o
}

// client is an owner's client of the key service: it presents no certificate.
func client(t *testing.T, pin *session.KeyService) *api.Client {
	t.Helper()
	c, err := api.NewClient(api.Options{Pin: pin, Engine: sessiontest.Engine{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func status(err error) int {
	var answer *api.StatusError
	if errors.As(err, &answer) {
		return answer.Status
	}
	return 0
}

// guest is a guest of a pool as the key service meets it: an instance key,
// evidence of it, and the pool's launch document. It is made by hand here so
// that a test can ask the key service for what no agent would.
type guest struct {
	t         *testing.T
	td        *sessiontest.TD
	key       *ecdsa.PrivateKey
	launch    []byte
	signature string
	client    *api.Client
	sealing   *api.EncryptionKey
	keyDigest string
}

// newGuest boots a guest of pool by hand: its registers hold the pool's
// image, the launch key's seed and the launch document.
func newGuest(t *testing.T, pool *sessionsim.Pool, ks *keyservicetest.Sim) *guest {
	t.Helper()
	// A real guest of the pool, for its documents and its image.
	model := pool.Boot(t, nil, ks.Pin)
	td := sessiontest.NewTD()
	identity, err := runtimemeasure.LoadImageManifest(model.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	td.MRTD = identity.LaunchDigests()[0].Digest
	td.RTMR[1], td.RTMR[2] = identity.RTMRs()[1], identity.RTMRs()[2]
	read := func(path string) []byte {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	dir := strings.TrimSuffix(model.LaunchKeyPath, session.PubkeyFile)
	g := &guest{t: t, td: td, launch: read(dir + session.DocumentFile), signature: strings.TrimSpace(string(read(dir + session.SignatureFile)))}
	td.SeedLaunchKey(read(model.LaunchKeyPath))
	event := runtimemeasure.Event(session.DocumentDigest(g.launch))
	if err := td.Extend(event[:]); err != nil {
		t.Fatal(err)
	}
	if g.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if g.keyDigest, err = session.InstanceKeyDigest(&g.key.PublicKey); err != nil {
		t.Fatal(err)
	}
	if g.sealing, err = api.NewEncryptionKey(); err != nil {
		t.Fatal(err)
	}
	g.client, err = api.NewClient(api.Options{
		Pin: ks.Pin, Engine: sessiontest.Engine{},
		Certificate: func() (*tls.Certificate, error) { return g.certificate(), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.client.Close)
	return g
}

// certificate is the guest's attested certificate over its registers as
// they are now.
func (g *guest) certificate() *tls.Certificate {
	g.t.Helper()
	rd, err := ratls.ReportDataForKey(&g.key.PublicKey, nil)
	if err != nil {
		g.t.Fatal(err)
	}
	att, err := agratls.NewAttestation(g.td.Evidence(rd[:48]))
	if err != nil {
		g.t.Fatal(err)
	}
	der, err := ratls.CreateAttestedCert(g.key, att, &ratls.CertOptions{Subject: pkix.Name{CommonName: "c8s session"}, TTL: time.Hour})
	if err != nil {
		g.t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		g.t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: g.key, Leaf: leaf}
}

func (g *guest) open() error { return g.client.Open(within(g.t), g.launch, g.signature) }

// bind is a bind for the guest under o's authority, with one stored
// credential declared. mutate may change it before it is signed.
func (g *guest) bind(o *owner, ks *keyservicetest.Sim, mutate func(*session.BindOptions)) *session.SignedBind {
	g.t.Helper()
	opts := session.BindOptions{
		Authority: o.key, InstanceKey: &g.key.PublicKey, Tenant: "acme", Session: "s1", NotAfter: time.Now().Add(time.Minute),
		KeyService: ks.Pin,
		Policy: session.BindPolicy{
			Access: session.Access{Exec: []string{string(o.pub)}, Credentials: []string{string(o.pub)}},
			Credentials: []session.Credential{
				{Name: "token", MaxBytes: 64, Source: session.SourceKeyService},
				{Name: "handed", MaxBytes: 64},
			},
		},
	}
	if mutate != nil {
		mutate(&opts)
	}
	bind, err := session.NewBind(opts)
	if err != nil {
		g.t.Fatal(err)
	}
	return bind
}

func (g *guest) acquire(bind *session.SignedBind, names ...string) (*api.AcquireResponse, error) {
	g.t.Helper()
	signature, err := api.SignEncryptionKey(g.key, g.sealing.Public())
	if err != nil {
		g.t.Fatal(err)
	}
	return g.client.Acquire(within(g.t), &api.AcquireRequest{
		Bind: bind.Raw, BindSignature: bind.Signature,
		EncryptionKey: g.sealing.Public(), EncryptionKeySignature: signature, Credentials: names,
	})
}

// world is a pool, the key service that serves it, and a tenant that has
// registered its authority and stored one credential.
type world struct {
	pool  *sessionsim.Pool
	ks    *keyservicetest.Sim
	owner *owner
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{pool: sessionsim.NewPool(t), owner: newOwner(t)}
	w.ks = keyservicetest.New(t, w.pool)
	c := client(t, w.ks.Pin)
	if err := c.RegisterAuthority(within(t), "acme", w.owner.pub, w.owner.signer); err != nil {
		t.Fatalf("register the tenant's authority: %v", err)
	}
	if err := c.PutCredential(within(t), "acme", "token", []byte("s3cret"), w.owner.signer); err != nil {
		t.Fatalf("store a credential: %v", err)
	}
	return w
}

// start makes g the tenant's session s1, under a bind that declares the
// stored credential, and returns the client of a key the bind grants.
func (w *world) start(t *testing.T, g *sessionsim.Guest) (*session.Client, error) {
	t.Helper()
	access := newOwner(t)
	identity, err := runtimemeasure.LoadImageManifest(g.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	launchKey, err := os.ReadFile(g.LaunchKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	binder, err := session.NewClient(g.URL, session.Policy{Image: identity, LaunchKey: launchKey, Authority: w.owner.pub, AllowReady: true}, sessiontest.Engine{}, access.signer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(binder.Close)
	ready, err := binder.Ready(within(t))
	if err != nil {
		t.Fatal(err)
	}
	if ready.Document.KeyService == nil || !ready.Document.KeyService.Equal(w.ks.Pin) {
		t.Fatal("the pool's launch document does not pin the key service")
	}
	bind, err := session.NewBind(session.BindOptions{
		Authority: w.owner.key, InstanceKey: ready.InstanceKey, Tenant: "acme", Session: "s1", NotAfter: time.Now().Add(time.Minute),
		KeyService: w.ks.Pin,
		Policy: session.BindPolicy{
			Access:      session.Access{Exec: []string{string(access.pub)}, Credentials: []string{string(access.pub)}},
			Credentials: []session.Credential{{Name: "token", MaxBytes: 64, Source: session.SourceKeyService}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	binding := session.Binding{LaunchKey: launchKey, Launch: ready.Launch, Bind: bind}
	_, _, err = binder.BindAttested(within(t), bind, binding.Policy(identity))
	return binder, err
}

// road is the way a pool's guests reach their key service, which a test
// opens when it chooses.
type road struct{ open atomic.Bool }

func (r *road) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if !r.open.Load() {
		return nil, errors.New("no road to the key service yet")
	}
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

// offered reports what a guest tells its host: whether it may be given to a
// session.
func offered(t *testing.T, g *sessionsim.Guest) bool {
	t.Helper()
	// The state is public, and nothing here relies on it.
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // an unjudged look at public state
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(within(t), http.MethodGet, g.URL+session.PathState, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var state session.StateResponse
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		t.Fatal(err)
	}
	return state.Phase == session.PhaseReady && state.Prepared
}

// A guest whose pool has a key service is offered to a session once the key
// service has judged it, and not before: a host that waits for that gives a
// session a guest whose bind costs one round trip to the key service.
func TestGuestIsOfferedOnceItsKeyServiceSessionIsOpen(t *testing.T) {
	w := newWorld(t)
	way := &road{}
	w.pool.KeyServiceDial = way.dial
	g := w.pool.Boot(t, nil, w.ks.Pin)
	for range 6 {
		if offered(t, g) {
			t.Fatal("a guest the key service has not judged says it may be given to a session")
		}
		time.Sleep(50 * time.Millisecond)
	}
	way.open.Store(true)
	for deadline := time.Now().Add(10 * time.Second); !offered(t, g); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the guest never said it may be given to a session")
		}
	}
	// A pool with no key service waits for none.
	if bare := sessionsim.NewPool(t).Boot(t, nil, nil); !offered(t, bare) {
		t.Fatal("a guest of a pool with no key service is not offered")
	}
}

// A bind that reaches a guest before its key service has judged it is refused
// on its headers: the guest reads none of it and stays as it was booted. The
// sender sends it again, and it is taken once the guest is ready.
func TestBindBeforeTheKeyServiceHasJudgedTheGuest(t *testing.T) {
	w := newWorld(t)
	way := &road{}
	w.pool.KeyServiceDial = way.dial
	g := w.pool.Boot(t, nil, w.ks.Pin)

	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // the refusal is read, not relied on
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(within(t), http.MethodPost, g.URL+session.PathBind, strings.NewReader(`{"bind":"e30=","signature":"c2ln"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var refusal struct{ Error string }
	_ = json.NewDecoder(resp.Body).Decode(&refusal)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || refusal.Error != "not_ready" || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("a bind before the guest is ready: %d %q, retry after %q", resp.StatusCode, refusal.Error, resp.Header.Get("Retry-After"))
	}

	type started struct {
		binder *session.Client
		err    error
	}
	done := make(chan started, 1)
	go func() {
		binder, err := w.start(t, g)
		done <- started{binder, err}
	}()
	select {
	case early := <-done:
		t.Fatalf("the bind was answered with no road to the key service: %v", early.err)
	case <-time.After(300 * time.Millisecond):
	}
	way.open.Store(true)
	select {
	case s := <-done:
		// The guest read neither bind it refused: it is still there to take
		// this one.
		if s.err != nil {
			t.Fatalf("bind: %v", s.err)
		}
		result, err := s.binder.Exec(within(t), session.ExecRequest{Argv: []string{"sh", "-c", `cat "$C8S_CREDENTIALS_DIR/token"`}})
		if err != nil || string(result.Stdout) != "s3cret" {
			t.Fatalf("the sandbox read %q, %v", result.Stdout, err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the bind never returned once the road was open")
	}
}

// The whole of milestone 1's path with a key service: the owner stores a
// credential, a pooled guest opens its session before it is anybody's, and
// the bind that makes it the owner's brings the credential into the sandbox.
func TestStoredCredentialReachesABoundGuest(t *testing.T) {
	w := newWorld(t)
	g := w.pool.Boot(t, nil, w.ks.Pin)
	binder, err := w.start(t, g)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	result, err := binder.Exec(within(t), session.ExecRequest{Argv: []string{"sh", "-c", `cat "$C8S_CREDENTIALS_DIR/token"`}})
	if err != nil || string(result.Stdout) != "s3cret" {
		t.Fatalf("the sandbox read %q, %v", result.Stdout, err)
	}
	// What the key service holds for the session is the key service's to
	// hand over, and nobody else's.
	if _, err := binder.PutCredential(within(t), "token", []byte("another")); err == nil {
		t.Fatal("an access key replaced a credential that comes from the key service")
	}
}

// A guest whose pool's launch document pins a key service takes no bind that
// trusts another one.
func TestGuestRefusesABindForAnotherKeyService(t *testing.T) {
	w := newWorld(t)
	other := keyservicetest.New(t, w.pool)
	g := w.pool.Boot(t, nil, w.ks.Pin)
	identity, err := runtimemeasure.LoadImageManifest(g.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	launchKey, err := os.ReadFile(g.LaunchKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	binder, err := session.NewClient(g.URL, session.Policy{Image: identity, LaunchKey: launchKey, Authority: w.owner.pub, AllowReady: true}, sessiontest.Engine{}, w.owner.signer)
	if err != nil {
		t.Fatal(err)
	}
	defer binder.Close()
	ready, err := binder.Ready(within(t))
	if err != nil {
		t.Fatal(err)
	}
	bind, err := session.NewBind(session.BindOptions{
		Authority: w.owner.key, InstanceKey: ready.InstanceKey, Tenant: "acme", Session: "s1", KeyService: other.Pin,
		Policy: session.BindPolicy{Access: session.Access{Exec: []string{string(w.owner.pub)}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := binder.Bind(within(t), bind); err == nil || !strings.Contains(err.Error(), "does not pin") {
		t.Fatalf("a bind that trusts another key service: %v", err)
	}
}

// The release rule, a condition at a time, asked by a guest made by hand.
func TestReleaseRule(t *testing.T) {
	w := newWorld(t)
	g := newGuest(t, w.pool, w.ks)
	bind := g.bind(w.owner, w.ks, nil)

	// No open session: the key service has judged no evidence of this key.
	if _, err := g.acquire(bind, "token"); status(err) != 409 {
		t.Fatalf("acquire before open: %v", err)
	}
	if err := g.open(); err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := g.open(); err != nil {
		t.Fatalf("open again: %v", err)
	}

	stranger := newOwner(t)
	other := newGuest(t, w.pool, w.ks)
	for name, tc := range map[string]struct {
		bind  *session.SignedBind
		names []string
		want  int
	}{
		"a bind for another guest":             {other.bind(w.owner, w.ks, nil), []string{"token"}, 403},
		"a bind signed by another authority":   {g.bind(stranger, w.ks, nil), []string{"token"}, 403},
		"a bind of a tenant nobody registered": {g.bind(w.owner, w.ks, func(o *session.BindOptions) { o.Tenant = "nobody" }), []string{"token"}, 403},
		"a bind that names no key service": {g.bind(w.owner, w.ks, func(o *session.BindOptions) {
			o.KeyService = nil
			o.Policy.Credentials = o.Policy.Credentials[1:]
		}), nil, 403},
		"a bind past its time":                      {g.bind(w.owner, w.ks, func(o *session.BindOptions) { o.NotAfter = time.Now().Add(-time.Minute) }), []string{"token"}, 403},
		"a credential the bind does not declare":    {bind, []string{"other"}, 403},
		"a credential the bind has a key hand over": {bind, []string{"handed"}, 403},
		"a credential larger than the bind allows": {g.bind(w.owner, w.ks, func(o *session.BindOptions) {
			o.Policy.Credentials[0].MaxBytes = 3
		}), []string{"token"}, 403},
		"a credential the tenant has not stored": {g.bind(w.owner, w.ks, func(o *session.BindOptions) {
			o.Policy.Credentials = append(o.Policy.Credentials, session.Credential{Name: "absent", Source: session.SourceKeyService})
		}), []string{"absent"}, 404},
	} {
		if _, err := g.acquire(tc.bind, tc.names...); status(err) != tc.want {
			t.Errorf("%s: %v, want HTTP %d", name, err, tc.want)
		}
	}

	// An encryption key the instance key did not sign.
	forged, err := api.NewEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := api.SignEncryptionKey(stranger.key, forged.Public())
	if err != nil {
		t.Fatal(err)
	}
	_, err = g.client.Acquire(within(t), &api.AcquireRequest{
		Bind: bind.Raw, BindSignature: bind.Signature, EncryptionKey: forged.Public(), EncryptionKeySignature: signature, Credentials: []string{"token"},
	})
	if status(err) != 400 {
		t.Fatalf("an encryption key somebody else signed: %v", err)
	}

	// None of the refusals above counted as the guest's bind.
	answer, err := g.acquire(bind, "token")
	if err != nil || len(answer.Credentials) != 1 {
		t.Fatalf("acquire: %v, %v", answer, err)
	}
	digest := session.DocumentDigest(bind.Raw)
	value, err := g.sealing.Open(g.keyDigest, digest, "token", answer.Credentials[0].Ciphertext)
	if err != nil || string(value) != "s3cret" {
		t.Fatalf("the release opens to %q, %v", value, err)
	}
	// It opens for this guest, this bind and this name, and for nothing else.
	for name, open := range map[string]func() ([]byte, error){
		"another name": func() ([]byte, error) {
			return g.sealing.Open(g.keyDigest, digest, "other", answer.Credentials[0].Ciphertext)
		},
		"another bind": func() ([]byte, error) {
			return g.sealing.Open(g.keyDigest, "sha256:"+strings.Repeat("0", 64), "token", answer.Credentials[0].Ciphertext)
		},
		"another guest": func() ([]byte, error) {
			return g.sealing.Open(other.keyDigest, digest, "token", answer.Credentials[0].Ciphertext)
		},
		"another key": func() ([]byte, error) {
			return other.sealing.Open(g.keyDigest, digest, "token", answer.Credentials[0].Ciphertext)
		},
	} {
		if _, err := open(); err == nil {
			t.Errorf("the release opened for %s", name)
		}
	}

	// The same bind again is answered as before. Another bind for the same
	// instance key is refused: rule 6.
	if again, err := g.acquire(bind, "token"); err != nil || len(again.Credentials) != 1 {
		t.Fatalf("the same bind again: %v", err)
	}
	if _, err := g.acquire(g.bind(w.owner, w.ks, func(o *session.BindOptions) { o.Session = "s2" }), "token"); status(err) != 403 {
		t.Fatalf("a second bind for the instance key: %v", err)
	}
}

// A guest of no pool the key service serves is told nothing and given
// nothing, and so is one that has already measured more than its launch
// document.
func TestOnlyServedPoolsOpenASession(t *testing.T) {
	w := newWorld(t)
	elsewhere := sessionsim.NewPool(t)
	otherService := keyservicetest.New(t, elsewhere)

	// A guest of another pool, which pins this key service all the same.
	stranger := newGuest(t, elsewhere, otherService)
	stranger.client.Close()
	var err error
	stranger.client, err = api.NewClient(api.Options{
		Pin: w.ks.Pin, Engine: sessiontest.Engine{},
		Certificate: func() (*tls.Certificate, error) { return stranger.certificate(), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stranger.client.Close)
	if err := stranger.open(); status(err) != 403 {
		t.Fatalf("a guest of another pool: %v", err)
	}

	// A guest of the pool whose register holds an event after its launch
	// document: it is somebody's already, or something else ran in it.
	late := newGuest(t, w.pool, w.ks)
	event := runtimemeasure.Event("sha256:" + strings.Repeat("9", 64))
	if err := late.td.Extend(event[:]); err != nil {
		t.Fatal(err)
	}
	if err := late.open(); status(err) != 403 {
		t.Fatalf("a guest that measured more than its launch document: %v", err)
	}

	// A caller with no certificate is no guest.
	if err := client(t, w.ks.Pin).Open(within(t), late.launch, late.signature); status(err) != 401 {
		t.Fatalf("an open with no certificate: %v", err)
	}
	// A debug guest's evidence is refused before any policy is asked.
	debug := newGuest(t, w.pool, w.ks)
	debug.td.Debug = true
	if err := debug.open(); status(err) != 403 {
		t.Fatalf("a debug guest: %v", err)
	}
}

// accepting is the test engine that notes which TCB statuses each judgment
// was asked to accept.
type accepting struct {
	sessiontest.Engine
	mu   sync.Mutex
	seen [][]string
}

func (e *accepting) VerifyEvidence(ctx context.Context, env teetypes.AttestationEvidence, reportData []byte) (*teetypes.VerificationResult, error) {
	e.mu.Lock()
	e.seen = append(e.seen, session.AcceptedTCB(ctx))
	e.mu.Unlock()
	return e.Engine.VerifyEvidence(ctx, env, reportData)
}

// A key service judges a pool's guests by what its launch document accepts
// of them, and by nothing more: a document that names no status has its
// engine accept only UpToDate.
func TestKeyServiceJudgesGuestsByItsDocumentsTCBStatuses(t *testing.T) {
	for name, accepted := range map[string][]string{"two statuses": {"OutOfDate", "SWHardeningNeeded"}, "none": nil} {
		pool := sessionsim.NewPool(t)
		engine := &accepting{}
		ks := keyservicetest.NewWith(t, keyservicetest.Options{Engine: engine, AcceptTCBStatus: accepted}, pool)
		if err := newGuest(t, pool, ks).open(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		engine.mu.Lock()
		seen := slices.Clone(engine.seen)
		engine.mu.Unlock()
		if len(seen) == 0 {
			t.Fatalf("%s: the key service judged nothing", name)
		}
		for i, got := range seen {
			if !slices.Equal(got, accepted) {
				t.Errorf("%s: judgment %d was asked to accept %v", name, i, got)
			}
		}
	}
}

// A tenant's authority is registered once, by whoever holds it, and only it
// stores the tenant's credentials.
func TestOwnersAreHeldToTheirAuthority(t *testing.T) {
	w := newWorld(t)
	c := client(t, w.ks.Pin)
	if err := c.RegisterAuthority(within(t), "acme", w.owner.pub, w.owner.signer); err != nil {
		t.Fatalf("the same registration again: %v", err)
	}
	usurper := newOwner(t)
	if err := c.RegisterAuthority(within(t), "acme", usurper.pub, usurper.signer); status(err) != 409 {
		t.Fatalf("another authority for a tenant that has one: %v", err)
	}
	// A registration is signed by the key it registers.
	if err := c.RegisterAuthority(within(t), "globex", usurper.pub, w.owner.signer); status(err) != 401 {
		t.Fatalf("a registration somebody else signed: %v", err)
	}
	if err := c.RegisterAuthority(within(t), "Not A Name", usurper.pub, usurper.signer); status(err) != 400 {
		t.Fatalf("a tenant with no usable name: %v", err)
	}
	for name, put := range map[string]func() error{
		"a credential under another key":        func() error { return c.PutCredential(within(t), "acme", "token", []byte("x"), usurper.signer) },
		"a credential of a tenant nobody knows": func() error { return c.PutCredential(within(t), "nobody", "token", []byte("x"), usurper.signer) },
	} {
		if err := put(); status(err) != 401 {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := c.PutCredential(within(t), "acme", "Token", []byte("x"), w.owner.signer); status(err) != 400 {
		t.Fatalf("a credential with no usable name: %v", err)
	}
	if err := c.PutCredential(within(t), "acme", "empty", nil, w.owner.signer); status(err) != 400 {
		t.Fatalf("an empty credential: %v", err)
	}
	// A token is for one key service: sent to another, it is no authority.
	second := keyservicetest.New(t, w.pool)
	if err := client(t, second.Pin).RegisterAuthority(within(t), "acme", w.owner.pub, w.owner.signer); err != nil {
		t.Fatal(err)
	}
	// The value was replaced by its owner, and only there.
	if err := c.PutCredential(within(t), "acme", "token", []byte("rotated"), w.owner.signer); err != nil {
		t.Fatal(err)
	}
	g := newGuest(t, w.pool, w.ks)
	if err := g.open(); err != nil {
		t.Fatal(err)
	}
	bind := g.bind(w.owner, w.ks, nil)
	answer, err := g.acquire(bind, "token")
	if err != nil {
		t.Fatal(err)
	}
	value, err := g.sealing.Open(g.keyDigest, session.DocumentDigest(bind.Raw), "token", answer.Credentials[0].Ciphertext)
	if err != nil || string(value) != "rotated" {
		t.Fatalf("the replaced credential reads %q, %v", value, err)
	}
}

// Whoever talks to a key service holds it to a pin first. One that is another
// image, or was launched under another key, is sent nothing.
func TestClientRefusesAKeyServiceItDidNotPin(t *testing.T) {
	w := newWorld(t)
	other := keyservicetest.New(t, w.pool)
	for name, mutate := range map[string]func(pin *session.KeyService){
		"another image":      func(pin *session.KeyService) { pin.Image = other.Pin.Image },
		"another launch key": func(pin *session.KeyService) { pin.LaunchKey = other.Pin.LaunchKey },
	} {
		pin := *w.ks.Pin
		mutate(&pin)
		c := client(t, &pin)
		err := c.PutCredential(within(t), "acme", "leaked", []byte("to the wrong service"), w.owner.signer)
		var refused *session.VerificationError
		if !errors.As(err, &refused) {
			t.Errorf("a key service of %s was sent a credential: %v", name, err)
		}
	}
	// Nothing arrived: a guest allowed that name finds it absent.
	g := newGuest(t, w.pool, w.ks)
	if err := g.open(); err != nil {
		t.Fatal(err)
	}
	bind := g.bind(w.owner, w.ks, func(o *session.BindOptions) {
		o.Policy.Credentials = append(o.Policy.Credentials, session.Credential{Name: "leaked", Source: session.SourceKeyService})
	})
	if _, err := g.acquire(bind, "leaked"); status(err) != 404 {
		t.Fatalf("the credential sent to a key service that was not pinned: %v", err)
	}
}
