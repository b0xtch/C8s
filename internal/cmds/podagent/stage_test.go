package podagent_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/podagent"
	"github.com/confidential-dot-ai/c8s/internal/podcvmtest"
	"github.com/confidential-dot-ai/c8s/pkg/podcvm"
)

const workloadImage = "ghcr.io/acme/agent@sha256:2222222222222222222222222222222222222222222222222222222222222222"

func register(t *testing.T, td *podcvmtest.TD) []byte {
	t.Helper()
	value, err := td.Extension()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestStageMeasuresTheLaunchDocumentOnce(t *testing.T) {
	h := newHarness(t, nil)
	seed := runtimemeasure.Seed(h.bundle.LaunchKey)
	if !bytes.Equal(register(t, h.td), seed[:]) {
		t.Fatal("fixture: register does not start at the launch-key seed")
	}
	want := runtimemeasure.FromDigestsSeeded(seed, []string{podcvm.LaunchDigest(h.bundle.Launch)})

	for boot := 1; boot <= 3; boot++ {
		// A second Stage on the same guest is an agent restart: the register
		// already holds the document and must not absorb it again.
		if _, err := podagent.Stage(context.Background(), h.cfg); err != nil {
			t.Fatalf("stage %d: %v", boot, err)
		}
		if got := register(t, h.td); !bytes.Equal(got, want[:]) {
			t.Fatalf("after stage %d the register is %x, want %x", boot, got, want)
		}
	}
}

// Everything the host controls at boot, bent one way each. The agent must
// refuse to stage, and must leave the register where the initrd put it.
func TestStageRefuses(t *testing.T) {
	for name, tc := range map[string]struct {
		break_ func(t *testing.T, h *harness)
		want   string
	}{
		"launch document modified": {func(t *testing.T, h *harness) {
			rewrite(t, filepath.Join(h.cfg.LaunchDir, podcvm.DocumentFile), func(b []byte) []byte {
				return bytes.Replace(b, []byte("tenant: acme.user-42"), []byte("tenant: evil.user-66"), 1)
			})
		}, "signature"},
		"signature removed": {func(t *testing.T, h *harness) {
			if err := os.Remove(filepath.Join(h.cfg.LaunchDir, podcvm.SignatureFile)); err != nil {
				t.Fatal(err)
			}
		}, "launch.yaml.sig"},
		"signature truncated to nothing": {func(t *testing.T, h *harness) {
			rewrite(t, filepath.Join(h.cfg.LaunchDir, podcvm.SignatureFile), func([]byte) []byte { return []byte("\n") })
		}, "signature"},
		"host swaps in its own key and a document it signed": {func(t *testing.T, h *harness) {
			// The initrd measured the tenant's key. The host then replaces the
			// staged pubkey and the launch files with a consistent set of its own.
			other := newHarness(t, func(o *podcvm.BundleOptions) { o.ManifestPath = h.td.WriteManifest(t) })
			h.cfg.PubkeyPath, h.cfg.LaunchDir = other.cfg.PubkeyPath, other.cfg.LaunchDir
		}, "not the one this guest was launched for"},
		"pubkey file replaced": {func(t *testing.T, h *harness) {
			_, pub := newSigner(t)
			rewrite(t, h.cfg.PubkeyPath, func([]byte) []byte { return []byte(pub) })
		}, "signature"},
		"no pubkey staged": {func(t *testing.T, h *harness) {
			h.cfg.PubkeyPath = filepath.Join(t.TempDir(), "absent")
		}, "opkeydata"},
		"document signed for another image": {func(t *testing.T, h *harness) {
			h.td.MRTD[3] ^= 1
		}, "image measurement does not match this boot"},
		"guest kernel differs from the document's pin": {func(t *testing.T, h *harness) {
			h.td.RTMR[1][3] ^= 1
		}, "RTMR[1] does not match this boot"},
		"debuggable guest": {func(t *testing.T, h *harness) {
			h.td.Debug = true
		}, "debuggable"},
		"register already extended by something else": {func(t *testing.T, h *harness) {
			event := runtimemeasure.Event("sha256:" + strings.Repeat("7", 64))
			if err := h.td.Extend(event[:]); err != nil {
				t.Fatal(err)
			}
		}, "not the one this guest was launched for"},
		"image built for the other platform": {func(t *testing.T, h *harness) {
			h.cfg.Platform = "snp"
		}, "built for"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, nil)
			tc.break_(t, h)
			before := register(t, h.td)
			_, err := podagent.Stage(context.Background(), h.cfg)
			if err == nil {
				t.Fatal("staged")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refused for the wrong reason: %v (want %q)", err, tc.want)
			}
			if after := register(t, h.td); !bytes.Equal(before, after) {
				t.Fatal("a refused launch still extended the register")
			}
		})
	}
}

func rewrite(t *testing.T, path string, f func([]byte) []byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, f(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

// recordingRunner stands in for a container runtime and records the order the
// agent drives it in, with the register value at each step.
type recordingRunner struct {
	*podagent.ProcessRunner
	td      *podcvmtest.TD
	mu      sync.Mutex
	steps   []string
	atStart []byte
	fail    error
}

func (r *recordingRunner) Prepare(_ context.Context, w *podcvm.Workload) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.steps = append(r.steps, "prepare "+w.Image)
	return r.fail
}

func (r *recordingRunner) Start(context.Context, string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.steps = append(r.steps, "start")
	r.atStart, _ = r.td.Extension()
	return nil
}

func workloadHarness(t *testing.T) (*harness, *recordingRunner) {
	t.Helper()
	h := newHarness(t, func(o *podcvm.BundleOptions) { o.Workload = &podcvm.Workload{Image: workloadImage} })
	runner := &recordingRunner{ProcessRunner: h.cfg.Runner.(*podagent.ProcessRunner), td: h.td}
	h.cfg.Runner = runner
	return h, runner
}

// The image is measured after it is verified and before it runs, so nothing
// unmeasured ever executes and a failed pull is never measured.
func TestWorkloadIsMeasuredBeforeItStarts(t *testing.T) {
	h, runner := workloadHarness(t)
	agent, err := podagent.Stage(context.Background(), h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	seed := runtimemeasure.Seed(h.bundle.LaunchKey)
	doc := podcvm.LaunchDigest(h.bundle.Launch)
	staged := runtimemeasure.FromDigestsSeeded(seed, []string{doc})
	running := runtimemeasure.FromDigestsSeeded(seed, []string{doc, "sha256:" + strings.Repeat("2", 64)})

	if got := register(t, h.td); !bytes.Equal(got, staged[:]) {
		t.Fatalf("staged register = %x", got)
	}
	if err := agent.Admit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(runner.steps, ",") != "prepare "+workloadImage+",start" {
		t.Fatalf("runner steps = %v", runner.steps)
	}
	if !bytes.Equal(runner.atStart, running[:]) {
		t.Fatal("the workload started before its image was measured")
	}
	if got := register(t, h.td); !bytes.Equal(got, running[:]) {
		t.Fatalf("running register = %x", got)
	}
}

func TestFailedPullIsNeverMeasured(t *testing.T) {
	h, runner := workloadHarness(t)
	runner.fail = errors.New("manifest digest mismatch")
	agent, err := podagent.Stage(context.Background(), h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	before := register(t, h.td)
	if err := agent.Admit(context.Background()); err == nil {
		t.Fatal("admitted a workload whose image did not verify")
	}
	if !bytes.Equal(before, register(t, h.td)) || len(runner.steps) != 1 {
		t.Fatalf("a failed pull was measured or started: steps=%v", runner.steps)
	}
}

func TestProcessRunnerRefusesAWorkloadImage(t *testing.T) {
	h := newHarness(t, func(o *podcvm.BundleOptions) { o.Workload = &podcvm.Workload{Image: workloadImage} })
	agent, err := podagent.Stage(context.Background(), h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Admit(context.Background()); err == nil {
		t.Fatal("a guest with no container runtime admitted a workload image")
	}
}

// Before admission the guest is verifiable but inert: it attests as staged,
// and neither runs commands nor accepts credentials.
func TestStagedGuestIsInert(t *testing.T) {
	h, _ := workloadHarness(t)
	agent, err := podagent.Stage(context.Background(), h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.WarmUp(context.Background()); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := agent.Server()
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	h.url = "https://" + ln.Addr().String()
	signer := h.launchSigner(t)

	strict := h.client(t, signer)
	if _, err := strict.Attest(ctxT(t)); !isVerdict(err) {
		t.Fatalf("a policy that wants the workload accepted a staged guest: %v", err)
	}
	h.policy.AllowStaged = true
	lenient := h.client(t, signer)
	att, err := lenient.Attest(ctxT(t))
	if err != nil || att.Phase != podcvm.PhaseStaged || len(att.Events) != 1 {
		t.Fatalf("staged attestation = %+v, %v", att, err)
	}
	if _, err := lenient.PutCredential(ctxT(t), "test-token", []byte("x")); !isVerdict(err) {
		t.Fatalf("the client released a credential to a staged guest: %v", err)
	}
	body := []byte(`{"value":"eA=="}`)
	header, err := signer.Authorization("PUT", podcvm.PathCredentials+"test-token", body)
	if err != nil {
		t.Fatal(err)
	}
	if status := h.raw(t, "PUT", podcvm.PathCredentials+"test-token", body, header); status != http.StatusConflict {
		t.Fatalf("the agent accepted a credential while staged: HTTP %d", status)
	}
	_, err = lenient.Exec(ctxT(t), podcvm.ExecRequest{Argv: []string{"true"}})
	assertStatus(t, err, http.StatusConflict)

	if err := agent.Admit(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.policy.AllowStaged = false
	after := h.client(t, signer)
	att, err = after.Attest(ctxT(t))
	if err != nil || att.Phase != podcvm.PhaseRunning || len(att.Events) != 2 {
		t.Fatalf("running attestation = %+v, %v", att, err)
	}
	if _, err := after.PutCredential(ctxT(t), "test-token", []byte("x")); err != nil {
		t.Fatalf("release after admission: %v", err)
	}
}

func isVerdict(err error) bool {
	var verdict *podcvm.VerificationError
	return errors.As(err, &verdict)
}

// A guest of another build is refused in the handshake; a guest launched for
// another key is refused at the fresh attestation. Either way no credential
// leaves the client.
func TestWrongGuestGetsNothing(t *testing.T) {
	h := newHarness(t, nil)
	h.start(t)
	signer := h.launchSigner(t)

	other := podcvmtest.NewTD()
	wrongImage := h.policy
	identity, err := runtimemeasure.LoadImageManifest(other.WriteManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	wrongImage.Image = identity
	wrongImage.Launch, wrongImage.Tenant, wrongImage.Sandbox = nil, "acme.user-42", "sbx-1"

	_, strangerPub := newSigner(t)
	wrongKey := h.policy
	wrongKey.LaunchKey = []byte(strangerPub)
	wrongKey.Launch, wrongKey.Tenant, wrongKey.Sandbox = nil, "acme.user-42", "sbx-1"

	for name, policy := range map[string]podcvm.Policy{"another image": wrongImage, "another launch key": wrongKey} {
		t.Run(name, func(t *testing.T) {
			client, err := podcvm.NewClient(h.url, policy, podcvmtest.Engine{}, signer)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if _, err := client.Attest(ctxT(t)); !isVerdict(err) {
				t.Fatalf("want a verification refusal, got %v", err)
			}
			if _, err := client.PutCredential(ctxT(t), "test-token", []byte("x")); !isVerdict(err) {
				t.Fatalf("want a verification refusal, got %v", err)
			}
		})
	}
	if entries, _ := os.ReadDir(h.credDir); len(entries) != 0 {
		t.Fatalf("a credential reached a guest that failed verification: %v", entries)
	}
}

// Once a client has attested a guest, a different key on the same address is
// a different guest, whatever it would attest to.
func TestClientPinsTheInstanceKey(t *testing.T) {
	h := newHarness(t, nil)
	h.start(t)
	client := h.client(t, h.launchSigner(t))
	if _, err := client.Exec(ctxT(t), podcvm.ExecRequest{Argv: []string{"true"}}); err != nil {
		t.Fatal(err)
	}
	addr := strings.TrimPrefix(h.url, "https://")

	// The agent restarts: same guest, same measurements, a new instance key.
	restarted, err := podagent.Stage(context.Background(), h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Admit(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Stop the first server and take over its address.
	client.Close()
	h.stop()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("cannot rebind %s: %v", addr, err)
	}
	srv := restarted.Server()
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	if _, err := client.Exec(ctxT(t), podcvm.ExecRequest{Argv: []string{"true"}}); !isVerdict(err) {
		t.Fatalf("a client kept talking to a new instance key without attesting it: %v", err)
	}
	if _, err := client.Attest(ctxT(t)); !isVerdict(err) {
		t.Fatalf("attest must not silently adopt a new key on a pinned client: %v", err)
	}
	// A fresh client attests the restarted guest from scratch and is fine.
	fresh := h.client(t, h.launchSigner(t))
	if _, err := fresh.Exec(ctxT(t), podcvm.ExecRequest{Argv: []string{"true"}}); err != nil {
		t.Fatalf("fresh client after restart: %v", err)
	}
}

// gatedTEE holds a fresh attestation in flight until released.
type gatedTEE struct {
	podagent.TEE
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (g *gatedTEE) Evidence(ctx context.Context, reportData []byte) (teetypes.AttestationEvidence, error) {
	if g.armed.Load() {
		g.entered <- struct{}{}
		<-g.release
	}
	return g.TEE.Evidence(ctx, reportData)
}

// splitter is the host in the middle: one address, and its own choice, per
// connection, of which guest answers. firstDropped closes when the client side
// of connection 1 ends.
type splitter struct {
	url          string
	firstDropped chan struct{}
}

func newSplitter(t *testing.T, route func(n int) string) *splitter {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := &splitter{url: "https://" + ln.Addr().String(), firstDropped: make(chan struct{})}
	go func() {
		for n := 1; ; n++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			backend, err := net.Dial("tcp", route(n))
			if err != nil {
				_ = conn.Close()
				continue
			}
			go func() {
				_, _ = io.Copy(backend, conn)
				if n == 1 {
					close(s.firstDropped)
				}
				_ = backend.Close()
			}()
			go func() { _, _ = io.Copy(conn, backend); _ = conn.Close() }()
		}
	}()
	return s
}

// The host can answer one address with two guests. A connection opened before
// the client attested may reach a guest of the pinned image that the host
// launched itself, under a document that welcomes the client's own key. Once
// the client has attested the right guest, nothing may travel on that
// connection: a command sent there would run where the host can watch it.
func TestPooledConnectionToAnotherGuestCarriesNothing(t *testing.T) {
	h := newHarness(t, nil)
	h.start(t)
	victim := string(h.bundle.LaunchKey)

	impostor := newHarness(t, func(o *podcvm.BundleOptions) {
		o.ManifestPath = h.td.WriteManifest(t)
		o.ExecKeys, o.CredentialKeys = []string{victim}, []string{victim}
	})
	impostor.td.MRTD, impostor.td.RTMR[1], impostor.td.RTMR[2] = h.td.MRTD, h.td.RTMR[1], h.td.RTMR[2]
	gate := &gatedTEE{TEE: impostor.cfg.TEE, entered: make(chan struct{}, 1), release: make(chan struct{})}
	impostor.cfg.TEE = gate
	impostor.start(t)
	gate.armed.Store(true)

	// Without a pinned document the handshake proves the image and nothing
	// about who launched the guest, so the impostor passes it.
	policy := h.policy
	policy.Launch, policy.Tenant, policy.Sandbox = nil, "acme.user-42", "sbx-1"
	host := newSplitter(t, func(n int) string {
		if n == 1 {
			return strings.TrimPrefix(impostor.url, "https://")
		}
		return strings.TrimPrefix(h.url, "https://")
	})
	client, err := podcvm.NewClient(host.url, policy, podcvmtest.Engine{}, h.launchSigner(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)

	// The first connection reaches the impostor and stays busy there.
	first := make(chan error, 1)
	go func() {
		_, err := client.Attest(ctxT(t))
		first <- err
	}()
	<-gate.entered
	// The second reaches the real guest, which attests and gets pinned.
	if _, err := client.Attest(ctxT(t)); err != nil {
		t.Fatalf("attest the real guest: %v", err)
	}
	gate.armed.Store(false)
	close(gate.release)
	if err := <-first; !isVerdict(err) {
		t.Fatalf("the impostor's evidence must be refused, got %v", err)
	}

	// The impostor's connection is now idle in the pool, most recently used,
	// so the next request is offered it first.
	select {
	case <-host.firstDropped:
		t.Fatal("fixture: the impostor's connection ended before the client was offered it")
	default:
	}
	marker := podcvm.ExecRequest{Argv: []string{"sh", "-c", `echo here > "$HOME/marker"`}}
	if resp, err := client.Exec(ctxT(t), marker); err != nil || resp.ExitCode != 0 {
		t.Fatalf("exec = %+v, %v", resp, err)
	}
	// The client must have dropped that connection itself. Were it still open,
	// this test would have proved nothing about a request offered to it.
	select {
	case <-host.firstDropped:
	case <-time.After(5 * time.Second):
		t.Fatal("the client kept its connection to a guest it never attested")
	}
	if _, err := client.PutCredential(ctxT(t), "test-token", []byte("s3cret")); err != nil {
		t.Fatalf("release to the real guest: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.home, "marker")); err != nil {
		t.Fatalf("the command did not run in the attested guest: %v", err)
	}
	if _, err := os.Stat(filepath.Join(impostor.home, "marker")); err == nil {
		t.Fatal("the command ran in a guest the client never attested")
	}
	if entries, _ := os.ReadDir(impostor.credDir); len(entries) != 0 {
		t.Fatalf("a credential reached a guest the client never attested: %v", entries)
	}
	if got, err := os.ReadFile(filepath.Join(h.credDir, "test-token")); err != nil || string(got) != "s3cret" {
		t.Fatalf("credential in the attested guest = %q, %v", got, err)
	}
}
