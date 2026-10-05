package keyservice_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
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
	t   *testing.T
	td  *sessiontest.TD
	key *ecdsa.PrivateKey
	// once is the one-time signing key, which a real guest erases as it
	// signs its receipt, and oneTime the keys its certificate carries. A
	// test clears oneTime for a guest that makes none.
	once      ed25519.PrivateKey
	oneTime   *session.OneTimeKeys
	launch    []byte
	signature string
	client    *api.Client
	sealing   *api.EncryptionKey
	keyDigest string
	// ttl is how long each certificate the guest presents lasts.
	ttl time.Duration
}

// newGuest boots a guest of pool by hand: its registers hold the pool's
// image, the launch key's seed and the launch document.
func newGuest(t *testing.T, pool *sessionsim.Pool, ks *keyservicetest.Sim) *guest {
	t.Helper()
	// A real guest of the pool, for its documents and its image. It opens a
	// session of its own, or has tried to, before this one asks anything:
	// what a test counts at the key service is then this guest's.
	model := pool.Boot(t, nil, ks.Pin)
	for deadline := time.Now().Add(10 * time.Second); model.Logged("opened a session with the key service") == 0 && model.Logged("the key service is not reached yet") == 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the pool's guest never tried to open its session with the key service")
		}
	}
	td := sessiontest.NewTD()
	identity, err := runtimemeasure.LoadImageManifest(model.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	td.MRTD = identity.LaunchDigests()[0].Digest
	td.RTMR[1], td.RTMR[2] = identity.RTMRs()[1], identity.RTMRs()[2]
	// The machine the pool's launch document lists.
	td.RTMR[0] = model.Machine()
	read := func(path string) []byte {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	dir := strings.TrimSuffix(model.LaunchKeyPath, session.PubkeyFile)
	g := &guest{t: t, td: td, ttl: time.Hour, launch: read(dir + session.DocumentFile), signature: strings.TrimSpace(string(read(dir + session.SignatureFile)))}
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
	g.once, g.oneTime = newOneTime(t)
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

// newOneTime makes a guest's one-time keys.
func newOneTime(t *testing.T) (ed25519.PrivateKey, *session.OneTimeKeys) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kem, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return private, &session.OneTimeKeys{Signing: public, KEM: kem.PublicKey().Bytes()}
}

// certificate is the guest's attested certificate over its registers as
// they are now, with its one-time keys in it and bound by its quote.
func (g *guest) certificate() *tls.Certificate {
	g.t.Helper()
	rd, err := session.CertificateReportData(&g.key.PublicKey, g.oneTime)
	if err != nil {
		g.t.Fatal(err)
	}
	att, err := agratls.NewAttestation(g.td.Evidence(rd))
	if err != nil {
		g.t.Fatal(err)
	}
	opts := &ratls.CertOptions{Subject: pkix.Name{CommonName: "c8s session"}, TTL: g.ttl}
	if g.oneTime != nil {
		ext, err := g.oneTime.Extension()
		if err != nil {
			g.t.Fatal(err)
		}
		opts.Extensions = []pkix.Extension{ext}
	}
	der, err := ratls.CreateAttestedCert(g.key, att, opts)
	if err != nil {
		g.t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		g.t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: g.key, Leaf: leaf}
}

func (g *guest) open() error {
	_, err := g.client.Open(within(g.t), g.launch, g.signature)
	return err
}

// bind is a bind for the guest under o's authority, with one stored
// credential declared. mutate may change it before it is signed.
func (g *guest) bind(o *owner, ks *keyservicetest.Sim, mutate func(*session.BindOptions)) *session.SignedBind {
	g.t.Helper()
	opts := session.BindOptions{
		Authority: o.key, InstanceKey: &g.key.PublicKey, Tenant: "acme", Session: "s1", NotAfter: time.Now().Add(time.Minute),
		KeyService: ks.Pin, Members: ks.Members,
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

// receipt is the guest's receipt for bind, signed under key: its own
// one-time key, or one a test hands it.
func (g *guest) receipt(bind *session.SignedBind, key ed25519.PrivateKey) *session.SignedReceipt {
	g.t.Helper()
	events, err := session.ExpectedEvents(nil, bind, session.PhaseRunning)
	if err != nil {
		g.t.Fatal(err)
	}
	receipt, err := session.NewBindReceipt(func(message []byte) ([]byte, error) { return ed25519.Sign(key, message), nil },
		bind, events[1:], session.PhaseRunning)
	if err != nil {
		g.t.Fatal(err)
	}
	return receipt
}

// acquire asks as the guest's agent does: with the bind, and its receipt for
// it under its one-time key.
func (g *guest) acquire(bind *session.SignedBind, names ...string) (*api.AcquireResponse, error) {
	g.t.Helper()
	return g.acquireWith(bind, g.receipt(bind, g.once), names...)
}

func (g *guest) acquireWith(bind *session.SignedBind, receipt *session.SignedReceipt, names ...string) (*api.AcquireResponse, error) {
	g.t.Helper()
	signature, err := api.SignEncryptionKey(g.key, g.sealing.Public())
	if err != nil {
		g.t.Fatal(err)
	}
	return g.client.Acquire(within(g.t), &api.AcquireRequest{
		Bind: bind.Raw, BindSignature: bind.Signature, Receipt: receipt,
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
	binder, _, err := w.startNaming(t, g, w.ks.Members)
	return binder, err
}

// startNaming is start under a bind that names these replicas of the key
// service. It also returns the guest's instance key, as a bind names one.
func (w *world) startNaming(t *testing.T, g *sessionsim.Guest, members []string) (*session.Client, string, error) {
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
		KeyService: w.ks.Pin, Members: members,
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
	return binder, bind.Doc.InstanceKey, err
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
		Authority: w.owner.key, InstanceKey: ready.InstanceKey, Tenant: "acme", Session: "s1", KeyService: other.Pin, Members: other.Members,
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
			o.KeyService, o.Members = nil, nil
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
		Bind: bind.Raw, BindSignature: bind.Signature, Receipt: g.receipt(bind, g.once),
		EncryptionKey: forged.Public(), EncryptionKeySignature: signature, Credentials: []string{"token"},
	})
	if status(err) != 400 {
		t.Fatalf("an encryption key somebody else signed: %v", err)
	}

	// Rule 3's other half: the guest's receipt for the bind, under the
	// one-time key its evidence bound. What a session could sign that read
	// its guest's instance key, or that made a key of its own, is none.
	strangers, _ := newOneTime(t)
	elsewhere := g.bind(w.owner, w.ks, func(o *session.BindOptions) { o.Session = "s2" })
	byInstance, err := operatorauth.SignDetached(g.key, append([]byte(session.BindReceiptSchema+" signature\x00"), g.receipt(bind, g.once).Receipt...))
	if err != nil {
		t.Fatal(err)
	}
	for name, receipt := range map[string]*session.SignedReceipt{
		"no receipt":       nil,
		"an empty receipt": {},
		"a receipt under a key the guest did not bind": g.receipt(bind, strangers),
		"a receipt the instance key signed":            {Receipt: g.receipt(bind, g.once).Receipt, Signature: byInstance},
		"the guest's receipt for another bind":         g.receipt(elsewhere, g.once),
	} {
		if answer, err := g.acquireWith(bind, receipt, "token"); status(err) != 403 {
			t.Errorf("%s released %+v: %v, want HTTP 403", name, answer, err)
		}
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
	if _, err := client(t, w.ks.Pin).Open(within(t), late.launch, late.signature); status(err) != 401 {
		t.Fatalf("an open with no certificate: %v", err)
	}
	// A debug guest's evidence is refused before any policy is asked.
	debug := newGuest(t, w.pool, w.ks)
	debug.td.Debug = true
	if err := debug.open(); status(err) != 403 {
		t.Fatalf("a debug guest: %v", err)
	}
	// A guest whose evidence binds no one-time keys could show no receipt
	// that only its agent signed.
	keyless := newGuest(t, w.pool, w.ks)
	keyless.oneTime = nil
	if err := keyless.open(); status(err) != 403 {
		t.Fatalf("a guest with no one-time keys: %v", err)
	}
	// One whose certificate carries keys its quote does not bind.
	swapped := newGuest(t, w.pool, w.ks)
	genuine := swapped.certificate()
	_, swapped.oneTime = newOneTime(t)
	forged := swapped.certificate()
	// The quote of the first certificate, under the keys of the second.
	if bytes.Equal(genuine.Certificate[0], forged.Certificate[0]) {
		t.Fatal("the two certificates are one")
	}
	replay := replayQuote(t, swapped, genuine.Leaf)
	swapped.client.Close()
	swapped.client, err = api.NewClient(api.Options{
		Pin: w.ks.Pin, Engine: sessiontest.Engine{},
		Certificate: func() (*tls.Certificate, error) { return replay, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(swapped.client.Close)
	if err := swapped.open(); status(err) != 403 {
		t.Fatalf("a certificate with keys its quote does not bind: %v", err)
	}
}

// replayQuote is a certificate g's instance key signs now, which carries g's
// present one-time keys beside the quote of an earlier certificate: what a
// session holds that read its guest's instance key and has its host's copy
// of the guest's first evidence.
func replayQuote(t *testing.T, g *guest, earlier *x509.Certificate) *tls.Certificate {
	t.Helper()
	att, err := ratls.ExtractAttestation(earlier)
	if err != nil {
		t.Fatal(err)
	}
	ext, err := g.oneTime.Extension()
	if err != nil {
		t.Fatal(err)
	}
	der, err := ratls.CreateAttestedCert(g.key, att, &ratls.CertOptions{
		Subject: pkix.Name{CommonName: "c8s session"}, TTL: time.Hour, Extensions: []pkix.Extension{ext},
	})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: g.key, Leaf: leaf}
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

// A key service's launch document lists the machines a replica may be. A
// replica whose document lists none keeps nothing and releases nothing, and
// nobody sends it anything. Only whoever reads its machine, to list it, takes
// its evidence.
func TestKeyServiceWithNoMachineListedServesOnlyItsState(t *testing.T) {
	pool := sessionsim.NewPool(t)
	ks := keyservicetest.NewWith(t, keyservicetest.Options{Unpinned: true}, pool)
	if !ks.Service.Unpinned() {
		t.Fatal("a replica whose document lists no machine is taken for a pinned one")
	}
	o := newOwner(t)
	c := client(t, ks.Pin)
	var refused *session.VerificationError
	if err := c.RegisterAuthority(within(t), "acme", o.pub, o.signer); !errors.As(err, &refused) || !strings.Contains(err.Error(), "lists no machine") {
		t.Fatalf("an owner's registration: %v", err)
	}
	g := newGuest(t, pool, ks)
	if err := g.open(); !errors.As(err, &refused) || !strings.Contains(err.Error(), "lists no machine") {
		t.Fatalf("a guest's open: %v", err)
	}
	// Its machine is read from its evidence, and reading it does not make
	// the client take its word afterwards.
	machine, err := c.Machine(within(t))
	if err != nil || !bytes.Equal(machine, ks.Machine[:]) {
		t.Fatalf("the machine read is %x, %v, and the replica's is %x", machine, err, ks.Machine)
	}
	if err := c.Verify(within(t)); !errors.As(err, &refused) {
		t.Fatalf("after its machine was read, the replica verified: %v", err)
	}

	// A caller that skips the check gets nothing from the replica either.
	handler := ks.Service.Handler()
	for name, req := range map[string]*http.Request{
		"a registration": httptest.NewRequest(http.MethodPut, api.AuthorityPath("acme"), strings.NewReader("{}")),
		"a credential":   httptest.NewRequest(http.MethodPut, api.CredentialPath("acme", "token"), strings.NewReader("{}")),
		"an open":        httptest.NewRequest(http.MethodPost, api.PathOpen, strings.NewReader("{}")),
		"an acquire":     httptest.NewRequest(http.MethodPost, api.PathAcquire, strings.NewReader("{}")),
	} {
		answer := httptest.NewRecorder()
		handler.ServeHTTP(answer, req)
		if answer.Code != http.StatusConflict || !strings.Contains(answer.Body.String(), "lists no machine") {
			t.Errorf("%s: HTTP %d %s", name, answer.Code, answer.Body.String())
		}
	}
	answer := httptest.NewRecorder()
	handler.ServeHTTP(answer, httptest.NewRequest(http.MethodGet, api.PathState, nil))
	if answer.Code != http.StatusOK {
		t.Fatalf("its state: HTTP %d", answer.Code)
	}
}

// A replica on a machine its document does not list is one its host built
// otherwise than the document's signer recorded. The real one ends before it
// serves. Whoever reaches one that did not is told so by its evidence, and
// sends it nothing.
func TestClientHoldsAKeyServiceToItsDocumentsMachines(t *testing.T) {
	pool := sessionsim.NewPool(t)
	ks := keyservicetest.NewWith(t, keyservicetest.Options{Machines: []string{strings.Repeat("0", 96)}}, pool)
	o := newOwner(t)
	var refused *session.VerificationError
	if err := client(t, ks.Pin).RegisterAuthority(within(t), "acme", o.pub, o.signer); !errors.As(err, &refused) || !strings.Contains(err.Error(), "is none of the 1 its launch document lists") {
		t.Fatalf("an owner's registration: %v", err)
	}
	if err := newGuest(t, pool, ks).open(); !errors.As(err, &refused) || !strings.Contains(err.Error(), "is none of the 1 its launch document lists") {
		t.Fatalf("a guest's open: %v", err)
	}
	// One on the machine its document lists is taken, and says the same
	// value to whoever reads it.
	good := keyservicetest.New(t, pool)
	c := client(t, good.Pin)
	if err := c.RegisterAuthority(within(t), "acme", o.pub, o.signer); err != nil {
		t.Fatal(err)
	}
	if machine, err := c.Machine(within(t)); err != nil || !bytes.Equal(machine, good.Machine[:]) {
		t.Fatalf("the machine read is %x, %v", machine, err)
	}
	// The read closed the connection it was made on, and the next call
	// holds the replica to its list again.
	if err := c.PutCredential(within(t), "acme", "token", []byte("value"), o.signer); err != nil {
		t.Fatalf("a call after the machine was read: %v", err)
	}
}

// vendor is an engine whose verdicts rest on the vendor's documents as it
// says it fetched them, which counts what it is asked, and which a test has
// refuse the evidence or fail to judge it.
type vendor struct {
	sessiontest.Engine
	// now is the replica's clock, and the engine's.
	now func() time.Time

	mu sync.Mutex
	// fetched is when the oldest document under a verdict was fetched.
	fetched   time.Time
	documents uint64
	asked     int
	renewed   int
	// down is what a renewal fails with, and what a judgment fails with once
	// its documents are an hour old.
	down error
	// revoked refuses every guest.
	revoked bool
	// taking is how many of the next judgments each take a document in
	// while they run.
	taking int
}

func (e *vendor) VerifyEvidence(ctx context.Context, env teetypes.AttestationEvidence, reportData []byte) (*teetypes.VerificationResult, error) {
	e.mu.Lock()
	e.asked++
	if e.taking > 0 {
		e.taking--
		e.documents++
	}
	fetched, revoked := e.fetched, e.revoked
	e.mu.Unlock()
	res, err := e.Engine.VerifyEvidence(ctx, env, reportData)
	switch {
	case err != nil:
		return nil, err
	case revoked:
		return nil, &session.VerificationError{Err: errors.New("the platform's key is revoked")}
	case !e.now().Before(fetched.Add(time.Hour)):
		// What the engine of a verifier that may send a secret does with
		// documents past their hour: it asks the vendor, which is down.
		return nil, session.ErrStaleDocuments
	}
	if res.Claims.PlatformData == nil {
		res.Claims.PlatformData = map[string]any{}
	}
	res.Claims.PlatformData[session.CollateralClaim] = &session.CollateralFinding{Fetched: fetched, Expires: fetched.Add(30 * 24 * time.Hour)}
	return res, nil
}

func (e *vendor) Renew(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.renewed++
	if e.down != nil {
		return e.down
	}
	// Three quarters of an hour is when a document is due.
	if now := e.now(); now.Sub(e.fetched) >= 45*time.Minute {
		e.fetched = now
		e.documents++
	}
	return nil
}

func (e *vendor) Documents() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.documents
}

func (e *vendor) set(change func(*vendor)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	change(e)
}

func (e *vendor) judged() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.asked
}

// dated is a world whose key service judges by a vendor engine, on a clock
// the test moves.
type dated struct {
	*world
	engine *vendor
	mu     sync.Mutex
	now    time.Time
}

func (d *dated) clock() time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.now
}

func (d *dated) advance(by time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.now = d.now.Add(by)
}

// newDated is a world at this moment, whose key service fetched the
// vendor's documents age ago.
func newDated(t *testing.T, age time.Duration) *dated {
	t.Helper()
	d := &dated{world: &world{pool: sessionsim.NewPool(t), owner: newOwner(t)}, now: time.Now()}
	d.engine = &vendor{now: d.clock, fetched: d.now.Add(-age)}
	d.ks = keyservicetest.NewWith(t, keyservicetest.Options{Engine: d.engine, Now: d.clock}, d.pool)
	c := client(t, d.ks.Pin)
	if err := c.RegisterAuthority(within(t), "acme", d.owner.pub, d.owner.signer); err != nil {
		t.Fatalf("register the tenant's authority: %v", err)
	}
	if err := c.PutCredential(within(t), "acme", "token", []byte("s3cret"), d.owner.signer); err != nil {
		t.Fatalf("store a credential: %v", err)
	}
	return d
}

// lasting is a bind for g that the key service takes whatever its clock
// reads in these tests.
func (d *dated) lasting(g *guest) *session.SignedBind {
	return g.bind(d.owner, d.ks, func(o *session.BindOptions) { o.NotAfter = time.Now().Add(6 * time.Hour) })
}

// until is when the key service's verdict on g ends.
func (d *dated) until(t *testing.T, g *guest) time.Time {
	t.Helper()
	_, until, _, ok := d.ks.Service.Verdict(g.keyDigest)
	if !ok {
		t.Fatal("the key service holds no verdict on the guest")
	}
	return until
}

// opened is a guest of the world's pool with an open session, whose
// certificates last a day. The guest the pool's documents are read from has
// one too: a Rejudge that finds verdicts due finds that one's among them.
func (d *dated) opened(t *testing.T) *guest {
	t.Helper()
	g := newGuest(t, d.pool, d.ks)
	g.ttl = 24 * time.Hour
	if err := g.open(); err != nil {
		t.Fatalf("open: %v", err)
	}
	return g
}

// Rule 1 of the release rule holds at the moment of a release, and not only
// when the guest opened its session: the verdict on its evidence rests on
// the vendor's documents as the key service fetched them within the hour,
// the newest it holds. A guest that waits in its pool past a revocation, or
// while the vendor cannot be asked, is released nothing.
func TestReleaseRestsOnDocumentsFetchedWithinTheHour(t *testing.T) {
	t.Run("the verdict ran out and the vendor cannot be asked", func(t *testing.T) {
		d := newDated(t, 30*time.Minute)
		g := d.opened(t)
		bind := d.lasting(g)
		d.engine.set(func(e *vendor) { e.down = errors.New("no route to the vendor") })
		// A second before the documents' hour is over the verdict stands,
		// and a release judges nothing.
		d.advance(30*time.Minute - time.Second)
		if until := d.until(t, g); !until.Equal(d.engine.fetched.Add(time.Hour)) {
			t.Fatalf("the verdict stands until %s, want an hour after the documents were fetched", until)
		}
		before := d.engine.judged()
		if _, err := g.acquire(d.lasting(g), "absent"); status(err) != 403 || d.engine.judged() != before {
			t.Fatalf("a request within the verdict's hour: %v, judged %d times", err, d.engine.judged()-before)
		}
		d.advance(time.Second)
		answer, err := g.acquire(bind, "token")
		if status(err) != 503 || answer != nil {
			t.Fatalf("a release on documents an hour old: %+v, %v, want HTTP 503", answer, err)
		}
		if d.engine.judged() == before {
			t.Fatal("the key service refused without judging the evidence again")
		}
		// Nothing was said of the guest: once the documents are here it is
		// judged on them, on the path, and released to.
		d.engine.set(func(e *vendor) { e.fetched, e.down = d.clock(), nil })
		if answer, err := g.acquire(bind, "token"); err != nil || len(answer.Credentials) != 1 {
			t.Fatalf("a release once the documents are fetched anew: %v", err)
		}
	})

	t.Run("judged again off the path, the verdict stands past its first hour", func(t *testing.T) {
		d := newDated(t, 0)
		g := d.opened(t)
		bind := d.lasting(g)
		first := d.until(t, g)
		// The documents are not due, and neither is the verdict.
		d.advance(44 * time.Minute)
		if judged, err := d.ks.Service.Rejudge(within(t)); err != nil || judged != 0 || !d.until(t, g).Equal(first) {
			t.Fatalf("before anything is due: %d judged, %v", judged, err)
		}
		// The documents are due: the engine fetches them, and the pool's
		// guests are judged on the new ones.
		d.advance(time.Minute)
		if judged, err := d.ks.Service.Rejudge(within(t)); err != nil || judged != 2 {
			t.Fatalf("with newer documents: %d judged, %v, want both guests of the pool", judged, err)
		}
		if until := d.until(t, g); !until.Equal(d.clock().Add(time.Hour)) {
			t.Fatalf("the verdict made anew stands until %s, want an hour from now", until)
		}
		// Past the first verdict's hour a release judges nothing on the path.
		d.advance(40 * time.Minute)
		before := d.engine.judged()
		if answer, err := g.acquire(bind, "token"); err != nil || len(answer.Credentials) != 1 {
			t.Fatalf("a release eighty-five minutes after the guest opened: %v", err)
		}
		if d.engine.judged() != before {
			t.Fatal("a guest that was judged off the path was judged again on it")
		}
	})

	t.Run("a verdict near its end is made anew though no document changed", func(t *testing.T) {
		d := newDated(t, 0)
		g := d.opened(t)
		d.engine.set(func(e *vendor) { e.down = errors.New("no route to the vendor") })
		d.advance(55*time.Minute - time.Second)
		before := d.engine.judged()
		if judged, _ := d.ks.Service.Rejudge(within(t)); judged != 0 || d.engine.judged() != before {
			t.Fatalf("more than five minutes before its end: %d judged", judged)
		}
		d.advance(time.Second)
		// The vendor is down, so the judgment rests on the same documents
		// and the verdict ends when it did.
		judged, err := d.ks.Service.Rejudge(within(t))
		if err == nil || judged != 2 || d.engine.judged() != before+2 {
			t.Fatalf("five minutes before its end, the vendor down: %d judged, %v", judged, err)
		}
		if until := d.until(t, g); !until.Equal(d.engine.fetched.Add(time.Hour)) {
			t.Fatalf("the verdict stands until %s", until)
		}
		// Past its end the guest still cannot be judged: its verdict is
		// kept, and stands for nothing, until the vendor answers.
		d.advance(5 * time.Minute)
		if judged, err := d.ks.Service.Rejudge(within(t)); err == nil || judged != 0 {
			t.Fatalf("past its end, the vendor down: %d judged, %v", judged, err)
		}
		if _, err := g.acquire(d.lasting(g), "token"); status(err) != 503 {
			t.Fatalf("a release past the verdict's end: %v, want HTTP 503", err)
		}
		d.engine.set(func(e *vendor) { e.down = nil })
		if judged, err := d.ks.Service.Rejudge(within(t)); err != nil || judged != 2 {
			t.Fatalf("once the vendor answers: %d judged, %v", judged, err)
		}
		if _, err := g.acquire(d.lasting(g), "token"); err != nil {
			t.Fatalf("a release once the vendor answers: %v", err)
		}
	})

	t.Run("a newer document shows before the key service has judged on it", func(t *testing.T) {
		d := newDated(t, 0)
		g := d.opened(t)
		bind := d.lasting(g)
		d.engine.set(func(e *vendor) { e.documents++ })
		before := d.engine.judged()
		if answer, err := g.acquire(bind, "token"); err != nil || len(answer.Credentials) != 1 {
			t.Fatalf("a release after a newer document came: %v", err)
		}
		if d.engine.judged() != before+1 {
			t.Fatalf("the evidence was judged %d times on the newer document, want once", d.engine.judged()-before)
		}
		// On that verdict, the next judges nothing.
		if _, err := g.acquire(bind, "token"); err != nil || d.engine.judged() != before+1 {
			t.Fatalf("the same release again: %v, judged %d times more", err, d.engine.judged()-before-1)
		}
	})

	t.Run("the newer documents refuse the guest", func(t *testing.T) {
		d := newDated(t, 0)
		g, other := d.opened(t), d.opened(t)
		bind := g.bind(d.owner, d.ks, nil)
		d.engine.set(func(e *vendor) { e.documents, e.revoked = e.documents+1, true })
		// On the path of a release.
		if answer, err := g.acquire(bind, "token"); status(err) != 403 || answer != nil {
			t.Fatalf("a release to a guest the newer documents refuse: %+v, %v, want HTTP 403", answer, err)
		}
		// And off it: the guest is forgotten.
		if judged, err := d.ks.Service.Rejudge(within(t)); err != nil || judged != 0 {
			t.Fatalf("Rejudge: %d judged, %v", judged, err)
		}
		for _, guest := range []*guest{g, other} {
			if _, _, _, ok := d.ks.Service.Verdict(guest.keyDigest); ok {
				t.Fatal("the key service keeps a verdict on a guest its documents refuse")
			}
		}
		d.engine.set(func(e *vendor) { e.revoked = false })
		if _, err := other.acquire(other.bind(d.owner, d.ks, nil), "token"); status(err) != 409 {
			t.Fatalf("a release to a guest that was forgotten: %v, want HTTP 409", err)
		}
	})

	t.Run("a verdict made while a document came in is made once more", func(t *testing.T) {
		d := newDated(t, 0)
		g := newGuest(t, d.pool, d.ks)
		g.ttl = 24 * time.Hour
		before := d.engine.judged()
		d.engine.set(func(e *vendor) { e.taking = 1 })
		if err := g.open(); err != nil {
			t.Fatal(err)
		}
		if d.engine.judged() != before+2 {
			t.Fatalf("the guest's evidence was judged %d times, want twice: once on documents that then changed", d.engine.judged()-before)
		}
		// The verdict is on the documents the key service holds now: a
		// release judges nothing more.
		before = d.engine.judged()
		if _, err := g.acquire(d.lasting(g), "token"); err != nil || d.engine.judged() != before {
			t.Fatalf("a release on that verdict: %v, judged %d times more", err, d.engine.judged()-before)
		}
		// An engine whose documents never settle gives no verdict to keep.
		d.engine.set(func(e *vendor) { e.taking = 1 << 30 })
		late := newGuest(t, d.pool, d.ks)
		if err := late.open(); status(err) != 503 {
			t.Fatalf("open while documents keep coming: %v, want HTTP 503", err)
		}
	})

	t.Run("a guest that cannot be judged when it opens is told to ask again", func(t *testing.T) {
		d := newDated(t, 2*time.Hour)
		g := newGuest(t, d.pool, d.ks)
		if err := g.open(); status(err) != 503 {
			t.Fatalf("open with documents two hours old and the vendor down: %v, want HTTP 503", err)
		}
		if _, _, _, ok := d.ks.Service.Verdict(g.keyDigest); ok {
			t.Fatal("the key service keeps a verdict it could not make")
		}
		d.engine.set(func(e *vendor) { e.fetched = d.clock() })
		if err := g.open(); err != nil {
			t.Fatalf("open once the documents are here: %v", err)
		}
	})
}

// A verdict never outlives the certificate that carried its evidence, so a
// guest that waits for its bind opens again under its next certificate, with
// a fresh quote. Once a bind is accepted the evidence the guest acquired
// with is what the key service keeps.
func TestGuestOpensAgainUnderItsNextCertificate(t *testing.T) {
	d := newDated(t, 0)
	g := newGuest(t, d.pool, d.ks)
	// A certificate that ends within the hour ends the verdict with it.
	g.ttl = 20 * time.Minute
	if err := g.open(); err != nil {
		t.Fatal(err)
	}
	first, until, bound, ok := d.ks.Service.Verdict(g.keyDigest)
	if !ok || bound || until.After(time.Now().Add(g.ttl)) || until.Before(time.Now().Add(g.ttl-time.Minute)) {
		t.Fatalf("the verdict stands until %s, want the end of a certificate that lasts %s", until, g.ttl)
	}
	// The same certificate again changes nothing, and costs no judgment.
	before := d.engine.judged()
	if err := g.open(); err != nil || d.engine.judged() != before {
		t.Fatalf("open again on the same connection: %v, judged %d times", err, d.engine.judged()-before)
	}
	// A new connection presents the guest's next certificate.
	g.ttl = 24 * time.Hour
	g.client.Close()
	if err := g.open(); err != nil {
		t.Fatal(err)
	}
	second, until, _, _ := d.ks.Service.Verdict(g.keyDigest)
	if second == first || !until.Equal(d.clock().Add(time.Hour)) {
		t.Fatalf("after the guest opened again the verdict rests on the same certificate: %t, until %s", second == first, until)
	}

	// The guest's next certificate must still be a ready guest's: one of a
	// guest that has measured more, as a bind makes it, is refused, and the
	// verdict the guest has is kept.
	measured := runtimemeasure.Event("sha256:" + strings.Repeat("ab", 32))
	if err := g.td.Extend(measured[:]); err != nil {
		t.Fatal(err)
	}
	g.client.Close()
	if err := g.open(); status(err) != 403 {
		t.Fatalf("open under a certificate of a guest that measured more: %v, want HTTP 403", err)
	}
	if kept, _, _, ok := d.ks.Service.Verdict(g.keyDigest); !ok || kept != second {
		t.Fatal("a refused open replaced the verdict the guest had")
	}

	// A bind is accepted: from here the evidence is the one it came with.
	bind := d.lasting(g)
	if _, err := g.acquire(bind, "token"); err != nil {
		t.Fatal(err)
	}
	g.client.Close()
	before = d.engine.judged()
	if err := g.open(); err != nil || d.engine.judged() != before {
		t.Fatalf("open after the bind: %v, judged %d times", err, d.engine.judged()-before)
	}
	kept, _, bound, ok := d.ks.Service.Verdict(g.keyDigest)
	if !ok || !bound || kept != second {
		t.Fatalf("after its bind the guest's evidence changed: bound %t, the same certificate %t", bound, kept == second)
	}
	// Off the path the key service judges no bound guest for a release: of
	// the pool's two guests, the one that is still nobody's. A repeat of the
	// bound guest's acquire rests on the verdict it was released on, made
	// again on the path once a newer document is here.
	released := d.until(t, g)
	d.advance(10 * time.Minute)
	d.engine.set(func(e *vendor) { e.documents++ })
	if judged, err := d.ks.Service.Rejudge(within(t)); err != nil || judged != 1 || !d.until(t, g).Equal(released) {
		t.Fatalf("Rejudge with one bound guest: %d judged, %v", judged, err)
	}
	before = d.engine.judged()
	if _, err := g.acquire(bind, "token"); err != nil || d.engine.judged() != before+1 {
		t.Fatalf("the same acquire again after a newer document: %v, judged %d times", err, d.engine.judged()-before)
	}
	d.engine.set(func(e *vendor) { e.documents, e.revoked = e.documents+1, true })
	if _, err := g.acquire(bind, "token"); status(err) != 403 {
		t.Fatalf("the same acquire again once the documents refuse the guest: %v, want HTTP 403", err)
	}
}

// A guest that waits for its bind opens its session again as its certificate
// nears its end, so that the key service's verdict, which ends with that
// certificate, is made anew on a fresh quote, and the guest can still be
// bound.
func TestWaitingGuestKeepsItsKeyServiceSessionOpen(t *testing.T) {
	w := newWorld(t)
	w.pool.CertTTL = 4 * time.Second
	g := w.pool.Boot(t, nil, w.ks.Pin)
	identity, err := runtimemeasure.LoadImageManifest(g.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	launchKey, err := os.ReadFile(g.LaunchKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := session.NewClient(g.URL, session.Policy{Image: identity, LaunchKey: launchKey, Authority: w.owner.pub, AllowReady: true}, sessiontest.Engine{}, w.owner.signer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	var ready *session.ReadyTD
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if ready, err = reader.Ready(within(t)); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the guest is not ready: %v", err)
		}
	}
	key, err := session.InstanceKeyDigest(ready.InstanceKey)
	if err != nil {
		t.Fatal(err)
	}
	var first [32]byte
	var firstUntil time.Time
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		var ok bool
		if first, firstUntil, _, ok = w.ks.Service.Verdict(key); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the guest opened no session with its key service")
		}
	}
	if firstUntil.After(time.Now().Add(w.pool.CertTTL)) {
		t.Fatalf("the verdict stands until %s, past the end of the certificate that carried its evidence", firstUntil)
	}
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		next, until, bound, ok := w.ks.Service.Verdict(key)
		if ok && next != first {
			if bound || !until.After(firstUntil) {
				t.Fatalf("after the guest opened again its verdict stands until %s, and the first stood until %s", until, firstUntil)
			}
			// It opened again while the first verdict still stood: the
			// guest was at no time one the key service would release
			// nothing to.
			if !time.Now().Before(firstUntil) {
				t.Fatalf("the guest opened again only after its first verdict had ended at %s", firstUntil)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the guest did not open its session again under its next certificate")
		}
	}
	// The guest says so once the key service has answered it, which is
	// after the key service has its verdict.
	for deadline := time.Now().Add(5 * time.Second); g.Logged("opened the session with the key service again, under a new certificate") == 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the guest does not say it opened its session again")
		}
	}
	// Bound now, it takes its stored credential on the verdict of the
	// certificate it last opened with.
	if _, err := w.start(t, g); err != nil {
		t.Fatalf("a guest that waited past its first certificate could not be started: %v", err)
	}
}
