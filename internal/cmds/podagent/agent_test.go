package podagent_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/podagent"
	"github.com/confidential-dot-ai/c8s/internal/podcvmtest"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/podcvm"
)

// harness is one booted guest: a simulated TD whose initrd measured the launch
// key, the staged agent inside it, and a verifier's view from outside.
type harness struct {
	td      *podcvmtest.TD
	dir     string
	bundle  *podcvm.Bundle
	cfg     podagent.Config
	agent   *podagent.Agent
	url     string
	policy  podcvm.Policy
	credDir string
	home    string
	srv     *http.Server
}

func (h *harness) stop() {
	if h.srv != nil {
		_ = h.srv.Close()
	}
}

func newHarness(t *testing.T, mutate func(*podcvm.BundleOptions)) *harness {
	t.Helper()
	td := podcvmtest.NewTD()
	dir := filepath.Join(t.TempDir(), "bundle")
	opts := podcvm.BundleOptions{
		Dir: dir, ManifestPath: td.WriteManifest(t), Tenant: "acme.user-42", Sandbox: "sbx-1",
		Credentials: []podcvm.Credential{{Name: "test-token", MaxBytes: 64}},
	}
	if mutate != nil {
		mutate(&opts)
	}
	if err := podcvm.NewBundle(opts); err != nil {
		t.Fatal(err)
	}
	bundle, err := podcvm.LoadBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	// What the measured initrd does with the opkeydata pubkey.
	td.SeedLaunchKey(bundle.LaunchKey)

	h := &harness{td: td, dir: dir, bundle: bundle, credDir: filepath.Join(t.TempDir(), "credentials"), home: t.TempDir()}
	runner, err := podagent.NewProcessRunner(podagent.RunnerConfig{UID: -1, GID: -1, Home: h.home, CredentialDir: h.credDir})
	if err != nil {
		t.Fatal(err)
	}
	h.cfg = podagent.Config{
		Platform:      "tdx",
		PubkeyPath:    filepath.Join(dir, podcvm.OpkeyDir, podcvm.PubkeyFile),
		LaunchDir:     filepath.Join(dir, podcvm.OpkeyDir),
		CredentialDir: h.credDir,
		TEE:           podcvmtest.TEE{TD: td},
		Runner:        runner,
	}
	identity, err := runtimemeasure.LoadImageManifest(opts.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	h.policy = podcvm.Policy{Image: identity, LaunchKey: bundle.LaunchKey, Launch: bundle.Launch}
	return h
}

// start stages, admits and serves the agent on a loopback listener.
func (h *harness) start(t *testing.T) {
	t.Helper()
	agent, err := podagent.Stage(context.Background(), h.cfg)
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
	go func(srv *http.Server) { _ = srv.ServeTLS(ln, "", "") }(h.srv)
	t.Cleanup(h.stop)
	h.agent, h.url = agent, "https://"+ln.Addr().String()
}

func (h *harness) launchSigner(t *testing.T) *operatorauth.Signer {
	t.Helper()
	keyPEM, err := os.ReadFile(filepath.Join(h.dir, podcvm.BundleKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func (h *harness) client(t *testing.T, auth operatorauth.Authorizer) *podcvm.Client {
	t.Helper()
	client, err := podcvm.NewClient(h.url, h.policy, podcvmtest.Engine{}, auth)
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
	pub, err := podcvm.PublicKeyPEM(&key.PublicKey)
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

// The whole first-milestone path against a simulated TD: attest, verify the
// pinned build and the guest-generated key, release a credential, and run one
// authenticated command that proves the credential arrived.
func TestAttestReleaseExec(t *testing.T) {
	h := newHarness(t, nil)
	h.start(t)
	client := h.client(t, h.launchSigner(t))

	att, err := client.Attest(ctxT(t))
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if att.Phase != podcvm.PhaseRunning || att.Document.Tenant != "acme.user-42" || len(att.Events) != 1 {
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
	resp, err := client.Exec(ctxT(t), podcvm.ExecRequest{Argv: []string{"sh", "-c", `cat "$C8S_CREDENTIALS_DIR/test-token"`}})
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
	client := h.client(t, h.launchSigner(t))

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

func TestCredentialReplaced(t *testing.T) {
	h := newHarness(t, nil)
	h.start(t)
	client := h.client(t, h.launchSigner(t))
	for _, value := range []string{"first", "second"} {
		if _, err := client.PutCredential(ctxT(t), "test-token", []byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(filepath.Join(h.credDir, "test-token"))
	if err != nil || string(got) != "second" {
		t.Fatalf("credential = %q, %v", got, err)
	}
}

// Access is exactly what the document grants: a key granted exec cannot
// release credentials, and a key granted nothing can do nothing.
func TestAccessIsPerRoute(t *testing.T) {
	execSigner, execPub := newSigner(t)
	stranger, _ := newSigner(t)
	h := newHarness(t, func(o *podcvm.BundleOptions) { o.ExecKeys = []string{execPub} })
	h.start(t)

	execClient := h.client(t, execSigner)
	if _, err := execClient.Exec(ctxT(t), podcvm.ExecRequest{Argv: []string{"true"}}); err != nil {
		t.Fatalf("exec key cannot exec: %v", err)
	}
	_, err := execClient.PutCredential(ctxT(t), "test-token", []byte("x"))
	assertStatus(t, err, http.StatusUnauthorized)

	strangerClient := h.client(t, stranger)
	_, err = strangerClient.Attest(ctxT(t))
	assertStatus(t, err, http.StatusUnauthorized)
	_, err = strangerClient.Exec(ctxT(t), podcvm.ExecRequest{Argv: []string{"true"}})
	assertStatus(t, err, http.StatusUnauthorized)
	if entries, _ := os.ReadDir(h.credDir); len(entries) != 0 {
		t.Fatalf("an unauthorized key released a credential: %v", entries)
	}
}

func assertStatus(t *testing.T, err error, want int) {
	t.Helper()
	var status *podcvm.StatusError
	if !errors.As(err, &status) || status.Status != want {
		t.Fatalf("want HTTP %d, got %v", want, err)
	}
}

// A token authorizes one method, path and body. Captured, it buys nothing else.
func TestTokenIsBoundToTheRequest(t *testing.T) {
	h := newHarness(t, nil)
	h.start(t)
	signer := h.launchSigner(t)
	body := []byte(`{"id":"` + strings.Repeat("a", 32) + `","argv":["true"]}`)
	other := []byte(`{"id":"` + strings.Repeat("b", 32) + `","argv":["true"]}`)

	for name, tc := range map[string]struct {
		signMethod, signPath string
		signBody             []byte
		method, path         string
		body                 []byte
		want                 int
	}{
		"control":         {"POST", podcvm.PathExec, body, "POST", podcvm.PathExec, body, http.StatusOK},
		"swapped body":    {"POST", podcvm.PathExec, body, "POST", podcvm.PathExec, other, http.StatusUnauthorized},
		"another path":    {"POST", podcvm.PathAttest, body, "POST", podcvm.PathExec, body, http.StatusUnauthorized},
		"another method":  {"PUT", podcvm.PathExec, body, "POST", podcvm.PathExec, body, http.StatusUnauthorized},
		"no token at all": {"", "", nil, "POST", podcvm.PathExec, body, http.StatusUnauthorized},
	} {
		t.Run(name, func(t *testing.T) {
			header := ""
			if tc.signMethod != "" {
				var err error
				if header, err = signer.Authorization(tc.signMethod, tc.signPath, tc.signBody); err != nil {
					t.Fatal(err)
				}
			}
			if status := h.raw(t, tc.method, tc.path, tc.body, header); status != tc.want {
				t.Fatalf("status = %d, want %d", status, tc.want)
			}
		})
	}
}

// The agent must refuse these itself: a caller is not obliged to use the
// client library that would have refused them first.
func TestAgentRefusesMalformedRequests(t *testing.T) {
	h := newHarness(t, nil)
	h.start(t)
	signer := h.launchSigner(t)
	big := bytes.Repeat([]byte("x"), podcvm.MaxRequestBytes+1)

	for name, tc := range map[string]struct {
		method, path string
		body         []byte
		want         int
	}{
		"credential path traversal": {"PUT", podcvm.PathCredentials + "..%2Fescape", []byte(`{"value":"eA=="}`), http.StatusNotFound},
		"undeclared credential":     {"PUT", podcvm.PathCredentials + "other", []byte(`{"value":"eA=="}`), http.StatusNotFound},
		"credential unknown field":  {"PUT", podcvm.PathCredentials + "test-token", []byte(`{"value":"eA==","mode":"0777"}`), http.StatusBadRequest},
		"credential trailing data":  {"PUT", podcvm.PathCredentials + "test-token", []byte(`{"value":"eA=="}{}`), http.StatusBadRequest},
		"exec without id":           {"POST", podcvm.PathExec, []byte(`{"argv":["true"]}`), http.StatusBadRequest},
		"exec unknown field":        {"POST", podcvm.PathExec, []byte(`{"id":"` + strings.Repeat("d", 32) + `","argv":["true"],"uid":0}`), http.StatusBadRequest},
		"exec relative cwd":         {"POST", podcvm.PathExec, []byte(`{"id":"` + strings.Repeat("e", 32) + `","argv":["true"],"cwd":"../etc"}`), http.StatusBadRequest},
		"exec unclean cwd":          {"POST", podcvm.PathExec, []byte(`{"id":"` + strings.Repeat("f", 32) + `","argv":["true"],"cwd":"/home/../etc"}`), http.StatusBadRequest},
		"attest short nonce":        {"POST", podcvm.PathAttest, []byte(`{"nonce":"AAAA"}`), http.StatusBadRequest},
		"oversized body":            {"POST", podcvm.PathExec, big, http.StatusRequestEntityTooLarge},
		"wrong method on a route":   {"GET", podcvm.PathExec, nil, http.StatusMethodNotAllowed},
		"route that does not exist": {"POST", "/v1/shell", []byte(`{}`), http.StatusNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			path := tc.path
			signed := strings.ReplaceAll(path, "%2F", "/")
			header, err := signer.Authorization(tc.method, signed, tc.body)
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

func TestExecIsIdempotentPerID(t *testing.T) {
	h := newHarness(t, nil)
	h.start(t)
	client := h.client(t, h.launchSigner(t))
	counter := filepath.Join(h.home, "runs")
	req := podcvm.ExecRequest{ID: strings.Repeat("c", 32), Argv: []string{"sh", "-c", "echo run >> " + counter + "; date +%N"}}

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

func TestExecResults(t *testing.T) {
	h := newHarness(t, nil)
	h.start(t)
	client := h.client(t, h.launchSigner(t))

	for name, tc := range map[string]struct {
		req   podcvm.ExecRequest
		check func(*testing.T, *podcvm.ExecResponse)
	}{
		"exit status": {podcvm.ExecRequest{Argv: []string{"sh", "-c", "echo out; echo err >&2; exit 3"}}, func(t *testing.T, r *podcvm.ExecResponse) {
			if r.ExitCode != 3 || string(r.Stdout) != "out\n" || string(r.Stderr) != "err\n" {
				t.Fatalf("%+v", r)
			}
		}},
		"stdin and env": {podcvm.ExecRequest{Argv: []string{"sh", "-c", `cat; printf %s "$GREETING"`}, Stdin: []byte("in:"), Env: map[string]string{"GREETING": "hi"}}, func(t *testing.T, r *podcvm.ExecResponse) {
			if string(r.Stdout) != "in:hi" {
				t.Fatalf("%q", r.Stdout)
			}
		}},
		"no inherited environment": {podcvm.ExecRequest{Argv: []string{"sh", "-c", `printf %s "${AGENT_SECRET:-unset}"`}}, func(t *testing.T, r *podcvm.ExecResponse) {
			if string(r.Stdout) != "unset" {
				t.Fatalf("the agent's environment leaked into a command: %q", r.Stdout)
			}
		}},
		"command not found": {podcvm.ExecRequest{Argv: []string{"/nonexistent/binary"}}, func(t *testing.T, r *podcvm.ExecResponse) {
			if r.ExitCode != 127 || len(r.Stderr) == 0 {
				t.Fatalf("%+v", r)
			}
		}},
		"timeout kills the whole group": {podcvm.ExecRequest{Argv: []string{"sh", "-c", "sleep 30 & sleep 30"}, TimeoutSeconds: 1}, func(t *testing.T, r *podcvm.ExecResponse) {
			if !r.TimedOut || r.ExitCode == 0 || r.DurationMillis > 10_000 {
				t.Fatalf("%+v", r)
			}
		}},
		"output is capped": {podcvm.ExecRequest{Argv: []string{"sh", "-c", "head -c 3000000 /dev/zero"}}, func(t *testing.T, r *podcvm.ExecResponse) {
			if !r.StdoutTruncated || len(r.Stdout) != podcvm.MaxExecOutput {
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
