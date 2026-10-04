package sessionagent_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// harness is one booted guest: a simulated TD whose initrd measured the launch
// key, the staged agent inside it, an owner who binds it, and a verifier's
// view from outside.
type harness struct {
	td     *sessiontest.TD
	dir    string
	bundle *session.Bundle
	cfg    sessionagent.Config
	agent  *sessionagent.Agent
	url    string
	// policy is what a client holds the guest to: before a bind, that it is
	// the pinned image and unbound; after, its documents.
	policy  session.Policy
	credDir string
	home    string
	srv     *http.Server

	// authority signs the guest's bind, and owner is the key the bind grants:
	// what drives the guest once it is bound.
	authority *ecdsa.PrivateKey
	owner     *operatorauth.Signer
	ownerPub  string
	// binds, when set, is how start binds the guest. A guest left unbound
	// has none.
	binds func(*session.BindOptions)
	bind  *session.SignedBind
}

func (h *harness) stop() {
	if h.srv != nil {
		_ = h.srv.Close()
	}
}

// newHarness is a guest that start boots and binds: to a session with no
// sandbox image, one credential and one key that may drive it. mutate changes
// the bind.
func newHarness(t *testing.T, mutate func(*session.BindOptions)) *harness {
	t.Helper()
	return newHarnessIn(t, nil, mutate)
}

// newHarnessIn is newHarness in a pool whose launch document pool changes.
func newHarnessIn(t *testing.T, pool func(*session.BundleOptions), mutate func(*session.BindOptions)) *harness {
	t.Helper()
	h := newUnbound(t, pool)
	h.binds = func(o *session.BindOptions) {
		if mutate != nil {
			mutate(o)
		}
	}
	return h
}

// newUnbound is a guest that start boots and leaves as its pool made it.
// mutate changes the pool's launch document.
func newUnbound(t *testing.T, mutate func(*session.BundleOptions)) *harness {
	t.Helper()
	td := sessiontest.NewTD()
	dir := filepath.Join(t.TempDir(), "bundle")
	opts := session.BundleOptions{Dir: dir, ManifestPath: td.WriteManifest(t), Pool: "agents", Class: "s-4x16"}
	if mutate != nil {
		mutate(&opts)
	}
	if err := session.NewBundle(opts); err != nil {
		t.Fatal(err)
	}
	bundle, err := session.LoadBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	// What the measured initrd does with the opkeydata pubkey.
	td.SeedLaunchKey(bundle.LaunchKey)

	h := &harness{td: td, dir: dir, bundle: bundle, credDir: filepath.Join(t.TempDir(), "credentials"), home: t.TempDir(), authority: newECKey(t)}
	h.owner, h.ownerPub = newSigner(t)
	runner, err := sessionagent.NewProcessRunner(sessionagent.RunnerConfig{UID: -1, GID: -1, Home: h.home, CredentialDir: h.credDir})
	if err != nil {
		t.Fatal(err)
	}
	h.cfg = sessionagent.Config{
		Platform:      "tdx",
		PubkeyPath:    filepath.Join(dir, session.OpkeyDir, session.PubkeyFile),
		LaunchDir:     filepath.Join(dir, session.OpkeyDir),
		CredentialDir: h.credDir,
		TEE:           sessiontest.TEE{TD: td},
		Runner:        runner,
		// A dev guest: most of these tests drive a guest with no sandbox image.
		Bare: true,
	}
	identity, err := runtimemeasure.LoadImageManifest(opts.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := session.PublicKeyPEM(&h.authority.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	// What the owner's side pins before it binds: the image, the pool's
	// launch key, and its own authority.
	h.policy = session.Policy{Image: identity, LaunchKey: bundle.LaunchKey, Authority: pub, AllowReady: true}
	return h
}

// start stages and serves the agent on a loopback listener, and binds the
// guest if the harness binds.
func (h *harness) start(t *testing.T) {
	t.Helper()
	if err := h.admitErr(t); err != nil {
		t.Fatalf("Bind: %v", err)
	}
}

// admitErr is start that returns, where the guest ended over its bind, the
// error it ended with.
func (h *harness) admitErr(t *testing.T) error {
	t.Helper()
	agent, err := sessionagent.Stage(context.Background(), h.cfg)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := agent.WarmUp(context.Background()); err != nil {
		t.Fatalf("WarmUp: %v", err)
	}
	if err := agent.Admit(context.Background()); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.srv = agent.Server()
	go func(srv *http.Server) { _ = agent.Serve(srv, ln) }(h.srv)
	t.Cleanup(h.stop)
	h.agent, h.url = agent, "https://"+ln.Addr().String()
	if h.binds == nil {
		return nil
	}
	binder := h.client(t, h.owner)
	ready, err := binder.Ready(ctxT(t))
	if err != nil {
		t.Fatalf("Ready: %v", err)
	}
	h.bind = h.bindFor(t, ready, func(o *session.BindOptions) {
		o.Policy.Sandbox = nil
		h.binds(o)
	})
	if _, err := binder.Bind(ctxT(t), h.bind); err != nil {
		// The guest's own reason is not the sender's to know: it ends with it.
		select {
		case fatal := <-agent.Fatal():
			return fatal
		case <-time.After(5 * time.Second):
			t.Fatalf("the guest refused its bind (%v) and carries on", err)
		}
	}
	h.pin(ready, h.bind)
	return nil
}

// bindFor signs a bind for the guest a verified connection showed: to a
// session that runs sandboxImage, with one credential, which the owner's key
// may drive.
func (h *harness) bindFor(t *testing.T, ready *session.ReadyTD, mutate func(*session.BindOptions)) *session.SignedBind {
	t.Helper()
	opts := session.BindOptions{
		Authority: h.authority, InstanceKey: ready.InstanceKey,
		Tenant: "acme", Session: "sbx-1", NotAfter: time.Now().Add(time.Hour),
		Policy: session.BindPolicy{
			Sandbox:     &session.Sandbox{Image: sandboxImage},
			Access:      session.Access{Exec: []string{h.ownerPub}, Credentials: []string{h.ownerPub}},
			Credentials: []session.Credential{{Name: "test-token", MaxBytes: 64}},
		},
	}
	if mutate != nil {
		mutate(&opts)
	}
	bind, err := session.NewBind(opts)
	if err != nil {
		t.Fatal(err)
	}
	return bind
}

// pin makes the harness's policy the one of a client of the bound guest: it
// pins the exact documents and no longer accepts an unbound guest.
func (h *harness) pin(ready *session.ReadyTD, bind *session.SignedBind) {
	h.policy.Launch, h.policy.Bind, h.policy.AllowReady = ready.Launch, bind.Raw, false
}

// launchSigner signs with the pool's launch key, which made the guest and
// may do nothing with it.
func (h *harness) launchSigner(t *testing.T) *operatorauth.Signer {
	t.Helper()
	keyPEM, err := os.ReadFile(filepath.Join(h.dir, session.BundleKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func (h *harness) client(t *testing.T, auth operatorauth.AudienceAuthorizer) *session.Client {
	t.Helper()
	client, err := session.NewClient(h.url, h.policy, sessiontest.Engine{}, auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func newSigner(t *testing.T) (*operatorauth.Signer, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := session.PublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer, string(pub)
}

func ctxT(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// The whole path against a simulated TD: a bound guest attests, the client
// verifies the pinned build, the bind and the guest-generated key, releases a
// credential, and runs one authenticated command that proves the credential
// arrived.
func TestAttestReleaseExec(t *testing.T) {
	h := newHarness(t, nil)
	h.start(t)
	client := h.client(t, h.owner)

	att, err := client.Attest(ctxT(t))
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if att.Phase != session.PhaseRunning || att.Tenant != "acme" || att.Session != "sbx-1" || len(att.Events) != 2 {
		t.Fatalf("unexpected attestation: phase=%s events=%v", att.Phase, att.Events)
	}
	secret := []byte("s3cr3t-token")
	if _, err := client.PutCredential(ctxT(t), "test-token", secret); err != nil {
		t.Fatalf("PutCredential: %v", err)
	}
	onDisk, err := os.ReadFile(filepath.Join(h.credDir, "test-token"))
	if err != nil || !bytes.Equal(onDisk, secret) {
		t.Fatalf("credential on disk = %q, %v", onDisk, err)
	}
	if info, err := os.Stat(filepath.Join(h.credDir, "test-token")); err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("credential mode = %v, %v", info.Mode(), err)
	}
	resp, err := client.Exec(ctxT(t), session.ExecRequest{Argv: []string{"sh", "-c", `cat "$C8S_CREDENTIALS_DIR/test-token"`}})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if resp.ExitCode != 0 || !bytes.Equal(resp.Stdout, secret) {
		t.Fatalf("exec = exit %d stdout %q stderr %q", resp.ExitCode, resp.Stdout, resp.Stderr)
	}
}

func TestCredentialRefusals(t *testing.T) {
	h := newHarness(t, nil)
	h.start(t)
	client := h.client(t, h.owner)

	for name, tc := range map[string]struct {
		cred  string
		value []byte
	}{
		"undeclared name":    {"other-token", []byte("x")},
		"over declared size": {"test-token", bytes.Repeat([]byte("x"), 65)},
		"empty":              {"test-token", nil},
		"path traversal":     {"../escape", []byte("x")},
		"uppercase name":     {"Test-Token", []byte("x")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := client.PutCredential(ctxT(t), tc.cred, tc.value); err == nil {
				t.Fatal("released")
			}
		})
	}
	entries, err := os.ReadDir(h.credDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("refused credentials left files behind: %v, %v", entries, err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(h.credDir), "escape")); err == nil {
		t.Fatal("a credential escaped its directory")
	}
}

// A credential is taken once: the same value again is answered as held, and
// another value under its name is refused, over the API as in the store.
func TestCredentialTakenOnce(t *testing.T) {
	h := newHarness(t, nil)
	h.start(t)
	client := h.client(t, h.owner)
	for range 2 {
		if _, err := client.PutCredential(ctxT(t), "test-token", []byte("first")); err != nil {
			t.Fatal(err)
		}
	}
	_, err := client.PutCredential(ctxT(t), "test-token", []byte("second"))
	assertStatus(t, err, http.StatusConflict)
	got, err := os.ReadFile(filepath.Join(h.credDir, "test-token"))
	if err != nil || string(got) != "first" {
		t.Fatalf("credential = %q, %v", got, err)
	}
}

// Access is exactly what the bind grants: a key granted exec cannot
// release credentials, and a key granted nothing can do nothing.
func TestAccessIsPerRoute(t *testing.T) {
	execSigner, execPub := newSigner(t)
	stranger, _ := newSigner(t)
	h := newHarness(t, func(o *session.BindOptions) { o.Policy.Access.Exec = append(o.Policy.Access.Exec, execPub) })
	h.start(t)

	execClient := h.client(t, execSigner)
	if _, err := execClient.Exec(ctxT(t), session.ExecRequest{Argv: []string{"true"}}); err != nil {
		t.Fatalf("exec key cannot exec: %v", err)
	}
	_, err := execClient.PutCredential(ctxT(t), "test-token", []byte("x"))
	assertStatus(t, err, http.StatusUnauthorized)

	strangerClient := h.client(t, stranger)
	_, err = strangerClient.Attest(ctxT(t))
	assertStatus(t, err, http.StatusUnauthorized)
	_, err = strangerClient.Exec(ctxT(t), session.ExecRequest{Argv: []string{"true"}})
	assertStatus(t, err, http.StatusUnauthorized)
	if entries, _ := os.ReadDir(h.credDir); len(entries) != 0 {
		t.Fatalf("an unauthorized key released a credential: %v", entries)
	}
}

func assertStatus(t *testing.T, err error, want int) {
	t.Helper()
	var status *session.StatusError
	if !errors.As(err, &status) || status.Status != want {
		t.Fatalf("want HTTP %d, got %v", want, err)
	}
}

// A token authorizes one method, path and body. Captured, it buys nothing else.
func TestTokenIsBoundToTheRequest(t *testing.T) {
	h := newHarness(t, nil)
	h.start(t)
	signer := h.owner
	audience := sessiontest.Audience(t, h.url)
	body := []byte(`{"id":"` + strings.Repeat("a", 32) + `","argv":["true"]}`)
	other := []byte(`{"id":"` + strings.Repeat("b", 32) + `","argv":["true"]}`)

	for name, tc := range map[string]struct {
		signMethod, signPath string
		signBody             []byte
		method, path         string
		body                 []byte
		want                 int
	}{
		"control":         {"POST", session.PathExec, body, "POST", session.PathExec, body, http.StatusOK},
		"swapped body":    {"POST", session.PathExec, body, "POST", session.PathExec, other, http.StatusUnauthorized},
		"another path":    {"POST", session.PathAttest, body, "POST", session.PathExec, body, http.StatusUnauthorized},
		"another method":  {"PUT", session.PathExec, body, "POST", session.PathExec, body, http.StatusUnauthorized},
		"no token at all": {"", "", nil, "POST", session.PathExec, body, http.StatusUnauthorized},
	} {
		t.Run(name, func(t *testing.T) {
			header := ""
			if tc.signMethod != "" {
				var err error
				if header, err = signer.AuthorizationFor(audience, tc.signMethod, tc.signPath, tc.signBody); err != nil {
					t.Fatal(err)
				}
			}
			if status := h.raw(t, tc.method, tc.path, tc.body, header); status != tc.want {
				t.Fatalf("status = %d, want %d", status, tc.want)
			}
		})
	}
}

// A key can be granted on many guests. A token names the one guest it is for,
// by its instance key, and no other takes it: what one guest was sent buys
// nothing at the next, on any route.
func TestTokenIsForOneGuest(t *testing.T) {
	h := newHarness(t, nil)
	h.start(t)
	signer := h.owner
	// A second guest that grants the same key everything.
	twin := newHarness(t, func(o *session.BindOptions) {
		o.Policy.Access = session.Access{Exec: []string{h.ownerPub}, Credentials: []string{h.ownerPub}}
	})
	twin.start(t)
	first, second := sessiontest.Audience(t, h.url), sessiontest.Audience(t, twin.url)
	if first == second {
		t.Fatal("fixture: two guests with one instance key")
	}

	nonce := make([]byte, session.NonceSize)
	attest, err := json.Marshal(session.AttestRequest{Nonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		method, path string
		body         []byte
		want         int
	}{
		"attest":     {"POST", session.PathAttest, attest, http.StatusOK},
		"exec":       {"POST", session.PathExec, []byte(`{"id":"` + strings.Repeat("c", 32) + `","argv":["true"]}`), http.StatusOK},
		"credential": {"PUT", session.PathCredentials + "test-token", []byte(`{"value":"eA=="}`), http.StatusCreated},
	} {
		t.Run(name, func(t *testing.T) {
			// Minted for the first guest, as that guest was sent it.
			captured, err := signer.AuthorizationFor(first, tc.method, tc.path, tc.body)
			if err != nil {
				t.Fatal(err)
			}
			if status := twin.raw(t, tc.method, tc.path, tc.body, captured); status != http.StatusUnauthorized {
				t.Errorf("the second guest answered a token for the first with HTTP %d", status)
			}
			unnamed, err := signer.Authorization(tc.method, tc.path, tc.body)
			if err != nil {
				t.Fatal(err)
			}
			if status := twin.raw(t, tc.method, tc.path, tc.body, unnamed); status != http.StatusUnauthorized {
				t.Errorf("the second guest answered a token that names no guest with HTTP %d", status)
			}
			// The control: the same request with a token of its own.
			own, err := signer.AuthorizationFor(second, tc.method, tc.path, tc.body)
			if err != nil {
				t.Fatal(err)
			}
			if status := twin.raw(t, tc.method, tc.path, tc.body, own); status != tc.want {
				t.Errorf("control: the second guest answered its own token with HTTP %d, want %d", status, tc.want)
			}
		})
	}
	if entries, _ := os.ReadDir(twin.credDir); len(entries) != 1 {
		t.Fatalf("the second guest holds %d credentials, want the control's one", len(entries))
	}
}

// The agent must refuse these itself: a caller is not obliged to use the
// client library that would have refused them first.
func TestAgentRefusesMalformedRequests(t *testing.T) {
	h := newHarness(t, nil)
	h.start(t)
	signer := h.owner
	audience := sessiontest.Audience(t, h.url)
	big := bytes.Repeat([]byte("x"), session.MaxRequestBytes+1)

	for name, tc := range map[string]struct {
		method, path string
		body         []byte
		want         int
	}{
		"credential path traversal": {"PUT", session.PathCredentials + "..%2Fescape", []byte(`{"value":"eA=="}`), http.StatusNotFound},
		"undeclared credential":     {"PUT", session.PathCredentials + "other", []byte(`{"value":"eA=="}`), http.StatusNotFound},
		"credential unknown field":  {"PUT", session.PathCredentials + "test-token", []byte(`{"value":"eA==","mode":"0777"}`), http.StatusBadRequest},
		"credential trailing data":  {"PUT", session.PathCredentials + "test-token", []byte(`{"value":"eA=="}{}`), http.StatusBadRequest},
		"exec without id":           {"POST", session.PathExec, []byte(`{"argv":["true"]}`), http.StatusBadRequest},
		"exec unknown field":        {"POST", session.PathExec, []byte(`{"id":"` + strings.Repeat("d", 32) + `","argv":["true"],"uid":0}`), http.StatusBadRequest},
		"exec relative cwd":         {"POST", session.PathExec, []byte(`{"id":"` + strings.Repeat("e", 32) + `","argv":["true"],"cwd":"../etc"}`), http.StatusBadRequest},
		"exec unclean cwd":          {"POST", session.PathExec, []byte(`{"id":"` + strings.Repeat("f", 32) + `","argv":["true"],"cwd":"/home/../etc"}`), http.StatusBadRequest},
		"attest short nonce":        {"POST", session.PathAttest, []byte(`{"nonce":"AAAA"}`), http.StatusBadRequest},
		"oversized body":            {"POST", session.PathExec, big, http.StatusRequestEntityTooLarge},
		"wrong method on a route":   {"GET", session.PathExec, nil, http.StatusMethodNotAllowed},
		"route that does not exist": {"POST", "/v1/shell", []byte(`{}`), http.StatusNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			path := tc.path
			signed := strings.ReplaceAll(path, "%2F", "/")
			header, err := signer.AuthorizationFor(audience, tc.method, signed, tc.body)
			if err != nil {
				t.Fatal(err)
			}
			if status := h.raw(t, tc.method, path, tc.body, header); status != tc.want {
				t.Fatalf("status = %d, want %d", status, tc.want)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(h.credDir), "escape")); err == nil {
		t.Fatal("a credential escaped its directory")
	}
}

// The agent speaks HTTP/1 only: one capped connection must not carry hundreds
// of concurrent request bodies before any token is checked.
func TestAgentDoesNotOfferHTTP2(t *testing.T) {
	h := newHarness(t, nil)
	h.start(t)
	conn, err := tls.Dial("tcp", strings.TrimPrefix(h.url, "https://"), &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // a probe: nothing about this peer is trusted
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if proto := conn.ConnectionState().NegotiatedProtocol; proto == "h2" {
		t.Fatal("the agent negotiated HTTP/2")
	}
}

// raw sends one request with no trust gate in front of it, the way an
// arbitrary network peer would.
func (h *harness) raw(t *testing.T, method, path string, body []byte, authorization string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(ctxT(t), method, h.url+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // a probe: nothing about this peer is trusted
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// The host's quoting service is every guest's. A guest answers a burst of
// attestations, then paces them, and past a second's worth says when to come
// back. Its client waits.
func TestFreshQuotesAreRationed(t *testing.T) {
	h := newHarness(t, nil)
	// The guest's clock stands still, so no quote comes due by itself.
	clock := &testClock{now: time.Now()}
	h.cfg.Now = clock.Now
	h.start(t)
	client := h.client(t, h.owner)
	const burst, perSecond, step = 20, 5, time.Second / 5
	for i := range burst {
		if _, err := client.Attest(ctxT(t)); err != nil {
			t.Fatalf("attestation %d of the burst: %v", i+1, err)
		}
	}
	// The next is held until it is due.
	started := time.Now()
	if _, err := client.Attest(ctxT(t)); err != nil {
		t.Fatalf("the attestation after the burst: %v", err)
	}
	if held := time.Since(started); held < step {
		t.Errorf("the attestation after the burst was served in %s, before the %s it was due in", held, step)
	}
	// Callers that leave while they are held have still booked their turn.
	// Each stays long enough for its request to arrive on a busy machine, and
	// leaves before the 200 ms after which its turn would come.
	for range perSecond - 1 {
		gone, cancel := context.WithTimeout(ctxT(t), 100*time.Millisecond)
		_, err := client.Attest(gone)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("a caller that left while held: %v", err)
		}
	}
	// With a second's worth booked the guest holds nobody. A caller with no
	// time to wait is told what the guest said.
	short, cancel := context.WithTimeout(ctxT(t), 200*time.Millisecond)
	defer cancel()
	_, err := client.Attest(short)
	var busy *session.StatusError
	if !errors.As(err, &busy) || busy.Status != http.StatusTooManyRequests || busy.RetryAfter != time.Second {
		t.Fatalf("with a second booked: %v, want a 429 that says to come back in a second", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("the error does not say the caller gave up waiting: %v", err)
	}
	// A caller with time waits the second it was told, and is served once
	// the guest's clock has moved.
	go func() {
		time.Sleep(300 * time.Millisecond)
		clock.advance(2 * time.Second)
	}()
	started = time.Now()
	if _, err := client.Attest(ctxT(t)); err != nil {
		t.Fatalf("an attestation that was told to come back: %v", err)
	}
	if waited := time.Since(started); waited < time.Second {
		t.Errorf("served after %s, before the second the guest asked for", waited)
	}
}

func TestExecIsIdempotentPerID(t *testing.T) {
	h := newHarness(t, nil)
	h.start(t)
	client := h.client(t, h.owner)
	counter := filepath.Join(h.home, "runs")
	req := session.ExecRequest{ID: strings.Repeat("c", 32), Argv: []string{"sh", "-c", "echo run >> " + counter + "; date +%N"}}

	first, err := client.Exec(ctxT(t), req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.Exec(ctxT(t), req)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Stdout, second.Stdout) {
		t.Fatalf("a repeated id returned a different result: %q vs %q", first.Stdout, second.Stdout)
	}
	runs, err := os.ReadFile(counter)
	if err != nil || strings.Count(string(runs), "run") != 1 {
		t.Fatalf("command ran %q times, want once (%v)", runs, err)
	}
}

// refusals counts what an agent logs as a refused request.
type refusals struct {
	slog.Handler
	n atomic.Int32
}

func (r *refusals) Handle(ctx context.Context, record slog.Record) error {
	if record.Message == "request refused" {
		r.n.Add(1)
	}
	return r.Handler.Handle(ctx, record)
}

// A command whose connection is lost before its answer is not lost with it,
// and is not run again: the client asks once more by the same id, on a new
// connection, and reads the one result.
func TestExecOutlivesItsConnection(t *testing.T) {
	// A key that may attest and may not run commands.
	releaser, releaserPub := newSigner(t)
	h := newHarness(t, func(o *session.BindOptions) {
		o.Policy.Access.Credentials = append(o.Policy.Access.Credentials, releaserPub)
	})
	refused := &refusals{Handler: slog.Default().Handler()}
	h.cfg.Logger = slog.New(refused)
	h.start(t)
	hop := sessiontest.NewHop(t, strings.TrimPrefix(h.url, "https://"))
	client, err := session.NewClient(hop.URL, h.policy, sessiontest.Engine{}, h.owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if _, err := client.Attest(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	started := filepath.Join(h.home, "started")
	type result struct {
		resp *session.ExecResponse
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := client.Exec(ctxT(t), session.ExecRequest{Argv: []string{"sh", "-c", `echo run >> "$HOME/started"; sleep 1; echo finished`}})
		done <- result{resp, err}
	}()
	// The command is running in the guest: now its connection goes.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the command never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	before := hop.Cut()
	got := <-done
	if got.err != nil || got.resp.ExitCode != 0 || string(got.resp.Stdout) != "finished\n" {
		t.Fatalf("exec across a lost connection = %+v, %v", got.resp, got.err)
	}
	if runs, err := os.ReadFile(started); err != nil || string(runs) != "run\n" {
		t.Fatalf("the command ran %q, %v: want once", runs, err)
	}
	if after := hop.Cut(); after <= before {
		t.Fatalf("the answer arrived on a connection that was cut (%d connections before the cut, %d after)", before, after)
	}

	// A refusal is an answer, and is not asked for again.
	other, err := session.NewClient(hop.URL, h.policy, sessiontest.Engine{}, releaser)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Close)
	_, err = other.Exec(ctxT(t), session.ExecRequest{Argv: []string{"true"}})
	assertStatus(t, err, http.StatusUnauthorized)
	if n := refused.n.Load(); n != 1 {
		t.Fatalf("the guest refused the command %d times: a refusal was asked for again", n)
	}
}

func TestExecResults(t *testing.T) {
	h := newHarness(t, nil)
	h.start(t)
	client := h.client(t, h.owner)

	for name, tc := range map[string]struct {
		req   session.ExecRequest
		check func(*testing.T, *session.ExecResponse)
	}{
		"exit status": {session.ExecRequest{Argv: []string{"sh", "-c", "echo out; echo err >&2; exit 3"}}, func(t *testing.T, r *session.ExecResponse) {
			if r.ExitCode != 3 || string(r.Stdout) != "out\n" || string(r.Stderr) != "err\n" {
				t.Fatalf("%+v", r)
			}
		}},
		"stdin and env": {session.ExecRequest{Argv: []string{"sh", "-c", `cat; printf %s "$GREETING"`}, Stdin: []byte("in:"), Env: map[string]string{"GREETING": "hi"}}, func(t *testing.T, r *session.ExecResponse) {
			if string(r.Stdout) != "in:hi" {
				t.Fatalf("%q", r.Stdout)
			}
		}},
		"no inherited environment": {session.ExecRequest{Argv: []string{"sh", "-c", `printf %s "${AGENT_SECRET:-unset}"`}}, func(t *testing.T, r *session.ExecResponse) {
			if string(r.Stdout) != "unset" {
				t.Fatalf("the agent's environment leaked into a command: %q", r.Stdout)
			}
		}},
		"command not found": {session.ExecRequest{Argv: []string{"/nonexistent/binary"}}, func(t *testing.T, r *session.ExecResponse) {
			if r.ExitCode != 127 || len(r.Stderr) == 0 {
				t.Fatalf("%+v", r)
			}
		}},
		"timeout kills the whole group": {session.ExecRequest{Argv: []string{"sh", "-c", "sleep 30 & sleep 30"}, TimeoutSeconds: 1}, func(t *testing.T, r *session.ExecResponse) {
			if !r.TimedOut || r.ExitCode == 0 || r.DurationMillis > 10_000 {
				t.Fatalf("%+v", r)
			}
		}},
		// The command finished; a child it left behind still holds its stdout.
		// That is a result with the command's own status. Reported as a
		// failure to run, it would invite the caller to run the work twice.
		"descendant keeps the output pipe open": {session.ExecRequest{Argv: []string{"sh", "-c", "echo done; sleep 30 &"}}, func(t *testing.T, r *session.ExecResponse) {
			if r.ExitCode != 0 || string(r.Stdout) != "done\n" || r.TimedOut || r.DurationMillis > 15_000 {
				t.Fatalf("%+v", r)
			}
		}},
		"output is capped": {session.ExecRequest{Argv: []string{"sh", "-c", "head -c 3000000 /dev/zero"}}, func(t *testing.T, r *session.ExecResponse) {
			if !r.StdoutTruncated || len(r.Stdout) != session.MaxExecOutput {
				t.Fatalf("stdout %d bytes, truncated=%v", len(r.Stdout), r.StdoutTruncated)
			}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("AGENT_SECRET", "must-not-leak")
			resp, err := client.Exec(ctxT(t), tc.req)
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, resp)
		})
	}
}
