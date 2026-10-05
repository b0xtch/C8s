package sessionagent_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

const sandboxImage = "ghcr.io/acme/agent@sha256:2222222222222222222222222222222222222222222222222222222222222222"

func register(t *testing.T, td *sessiontest.TD) []byte {
	t.Helper()
	value, err := td.Extension()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestStageMeasuresTheLaunchDocumentOnce(t *testing.T) {
	h := newUnbound(t, nil)
	seed := runtimemeasure.Seed(h.bundle.LaunchKey)
	if !bytes.Equal(register(t, h.td), seed[:]) {
		t.Fatal("fixture: register does not start at the launch-key seed")
	}
	want := runtimemeasure.FromDigestsSeeded(seed, []string{session.DocumentDigest(h.bundle.Launch)})

	for boot := 1; boot <= 3; boot++ {
		// A second Stage on the same guest is an agent restart: the register
		// already holds the document and must not absorb it again.
		if _, err := sessionagent.Stage(context.Background(), h.cfg); err != nil {
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
			rewrite(t, filepath.Join(h.cfg.LaunchDir, session.DocumentFile), func(b []byte) []byte {
				return bytes.Replace(b, []byte("pool: agents"), []byte("pool: others"), 1)
			})
		}, "signature"},
		"signature removed": {func(t *testing.T, h *harness) {
			if err := os.Remove(filepath.Join(h.cfg.LaunchDir, session.SignatureFile)); err != nil {
				t.Fatal(err)
			}
		}, "launch.yaml.sig"},
		"signature truncated to nothing": {func(t *testing.T, h *harness) {
			rewrite(t, filepath.Join(h.cfg.LaunchDir, session.SignatureFile), func([]byte) []byte { return []byte("\n") })
		}, "signature"},
		"host swaps in its own key and a document it signed": {func(t *testing.T, h *harness) {
			// The initrd measured the pool's key. The host then replaces the
			// staged pubkey and the launch files with a consistent set of its own.
			other := newUnbound(t, func(o *session.BundleOptions) {
				o.ManifestPath, o.Machines = h.td.WriteManifest(t), []string{hex.EncodeToString(h.td.RTMR[0][:])}
			})
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
			h := newUnbound(t, nil)
			tc.break_(t, h)
			before := register(t, h.td)
			_, err := sessionagent.Stage(context.Background(), h.cfg)
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
	*sessionagent.ProcessRunner
	td        *sessiontest.TD
	mu        sync.Mutex
	steps     []string
	atPrepare []byte
	atStart   []byte
	fail      error
	// imageUser, when set, is who the image runs as: known once it is prepared.
	imageUser *[2]int
	// ended delivers the sandbox's end to Wait.
	ended chan error
	// egress is the allowlist the sandbox was prepared under.
	egress *session.Egress
	// unpacking is what Prestage returns: the test closes it when the images
	// it was asked for are done with.
	unpacking chan struct{}
	// gate, when set, holds Prepare until the test closes it.
	gate chan struct{}
	// starting, when set, is closed when Start is reached, and Start then
	// waits until the test closes started.
	starting, started chan struct{}
	// onStart, when set, is called as Start is reached, before anything
	// else happens there: what it reads is the agent as it starts a sandbox.
	onStart func()
}

// preparedIn is how long the recording runner says its one step took.
const preparedIn = 3 * time.Millisecond

func (r *recordingRunner) CredentialOwner() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.imageUser != nil && len(r.steps) > 0 {
		return r.imageUser[0], r.imageUser[1]
	}
	return r.ProcessRunner.CredentialOwner()
}

func (r *recordingRunner) recorded() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.steps, ",")
}

func (r *recordingRunner) Wait(ctx context.Context) error {
	select {
	case err := <-r.ended:
		return err
	case <-ctx.Done():
		return nil
	}
}

func (r *recordingRunner) Prestage(_ context.Context, images []string) <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.steps = append(r.steps, "prestage "+strings.Join(images, " "))
	if r.unpacking == nil {
		r.unpacking = make(chan struct{})
	}
	return r.unpacking
}

func (r *recordingRunner) Prepare(ctx context.Context, w *session.Sandbox, egress *session.Egress) error {
	r.mu.Lock()
	sessionagent.RecordStep(ctx, "fetch", preparedIn)
	r.steps = append(r.steps, "prepare "+w.Image)
	r.egress = egress
	r.atPrepare, _ = r.td.Extension()
	gate, fail := r.gate, r.fail
	r.mu.Unlock()
	if gate != nil {
		<-gate
	}
	return fail
}

func (r *recordingRunner) Start(context.Context, string) error {
	r.mu.Lock()
	if r.onStart != nil {
		r.onStart()
	}
	r.steps = append(r.steps, "start")
	r.atStart, _ = r.td.Extension()
	starting, started := r.starting, r.started
	r.mu.Unlock()
	if starting != nil {
		close(starting)
		<-started
	}
	return nil
}

// While a bind's sandbox is admitted, the register already holds the
// sandbox's image and the guest still says it is bound and no more. A quote
// asked for in between waits until the sandbox runs: no quote shows a
// register that the guest's account of itself does not explain. The bind's
// own answer carries a quote taken meanwhile, of a guest that runs.
func TestQuoteWaitsWhileTheSandboxIsAdmitted(t *testing.T) {
	p := newPool(t)
	p.runner.starting, p.runner.started = make(chan struct{}), make(chan struct{})
	p.start(t)
	client := p.client(t, p.access)
	ready, err := client.Ready(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	bind := p.bindFor(t, ready, nil)
	type answer struct {
		resp *session.BindResponse
		err  error
	}
	bound := make(chan answer, 1)
	go func() {
		resp, err := client.Bind(ctxT(t), bind)
		bound <- answer{resp, err}
	}()
	select {
	case <-p.runner.starting:
	case <-time.After(10 * time.Second):
		t.Fatal("the sandbox was never started")
	}
	all, err := session.ExpectedEvents(p.bundle.Launch, bind, session.PhaseRunning)
	if err != nil {
		t.Fatal(err)
	}
	final := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(p.bundle.LaunchKey), all)
	if !bytes.Equal(final[:], register(t, p.td)) {
		t.Fatal("the register does not hold the sandbox's image while the sandbox starts")
	}
	if state := p.state(t); state.Phase != session.PhaseBound || len(state.Events) != 2 {
		t.Fatalf("while its sandbox starts the guest says %s with %d events", state.Phase, len(state.Events))
	}

	p.pin(ready, bind)
	asker := p.client(t, p.access)
	type asked struct {
		evidence *session.Evidence
		err      error
	}
	quote := make(chan asked, 1)
	go func() {
		evidence, err := asker.FetchEvidence(ctxT(t))
		quote <- asked{evidence, err}
	}()
	select {
	case got := <-quote:
		t.Fatalf("a quote was given while the sandbox was being admitted: %+v, %v", got.evidence, got.err)
	case <-time.After(300 * time.Millisecond):
	}

	close(p.runner.started)
	first := <-bound
	if first.err != nil {
		t.Fatal(first.err)
	}
	if att := first.resp.Attestation; att == nil || att.Phase != session.PhaseRunning || !slices.Equal(att.Events, all) {
		t.Fatalf("the bind's answer carries %+v", att)
	}
	got := <-quote
	if got.err != nil {
		t.Fatal(got.err)
	}
	if resp := got.evidence.Response; resp.Phase != session.PhaseRunning || !slices.Equal(resp.Events, all) {
		t.Fatalf("the quote that waited is of a guest in phase %s with %d events", resp.Phase, len(resp.Events))
	}
	if _, err := got.evidence.Verify(ctxT(t), p.policy, sessiontest.Engine{}); err != nil {
		t.Fatalf("the quote that waited: %v", err)
	}
}

// The image names the user its sandbox runs as, so the agent asks who owns
// the credentials again once the image is prepared, and hands them over.
func TestCredentialsGoToTheImageUser(t *testing.T) {
	p := newPool(t)
	p.runner.imageUser = &[2]int{54321, 54321}
	p.start(t)
	client := p.client(t, p.access)
	ready, err := client.Ready(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Bind(ctxT(t), p.bindFor(t, ready, nil))
	if os.Geteuid() != 0 {
		// Only root can give a directory away. The attempt is the evidence.
		if fatal := p.fatal(t); err == nil || fatal == nil || !strings.Contains(fatal.Error(), "hand credential directory to the sandbox") {
			t.Fatalf("Bind = %v, and the guest ends with %v", err, fatal)
		}
		if got := p.runner.recorded(); got != "prepare "+sandboxImage {
			t.Fatalf("the sandbox started without its credentials' owner in place: %s", got)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p.credDir)
	if err != nil {
		t.Fatal(err)
	}
	if st := info.Sys().(*syscall.Stat_t); st.Uid != 54321 || st.Gid != 54321 {
		t.Fatalf("credential directory is owned by %d:%d", st.Uid, st.Gid)
	}
}

// A session's guest is its sandbox: when the sandbox ends, Run returns and
// the unit powers the guest off.
func TestRunEndsWithTheSandbox(t *testing.T) {
	for name, tc := range map[string]struct {
		end  error
		want string
	}{
		"failed":  {errors.New("sandbox exited with status 3"), "sandbox ended: sandbox exited with status 3"},
		"cleanly": {nil, ""},
	} {
		t.Run(name, func(t *testing.T) {
			p := newPool(t)
			p.cfg.Logger = slog.New(slog.DiscardHandler)
			p.runner.ended = make(chan error, 1)
			addr := freeAddr(t)
			done := make(chan error, 1)
			go func() { done <- sessionagent.Run(context.Background(), p.cfg, addr) }()
			p.url = "https://" + addr
			until(t, "the guest serves", func() bool {
				conn, err := net.DialTimeout("tcp", addr, time.Second)
				if err == nil {
					_ = conn.Close()
				}
				return err == nil
			})
			client := p.client(t, p.access)
			ready, err := client.Ready(ctxT(t))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Bind(ctxT(t), p.bindFor(t, ready, nil)); err != nil {
				t.Fatal(err)
			}
			if got := p.runner.recorded(); got != "prepare "+sandboxImage+",start" {
				t.Fatalf("the sandbox was not started: %s", got)
			}
			select {
			case err := <-done:
				t.Fatalf("Run returned while the sandbox runs: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			p.runner.ended <- tc.end
			select {
			case err := <-done:
				if (tc.want == "") != (err == nil) || (err != nil && err.Error() != tc.want) {
					t.Fatalf("Run = %v, want %q", err, tc.want)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("Run did not return after the sandbox ended")
			}
		})
	}
}

// A guest with no container runtime runs no image: a bind that names one is
// measured, cannot be admitted, and ends the guest.
func TestProcessRunnerRefusesASandboxImage(t *testing.T) {
	h := newUnbound(t, nil)
	h.start(t)
	client := h.client(t, h.owner)
	ready, err := client.Ready(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Bind(ctxT(t), h.bindFor(t, ready, nil)); !isStatus(err, http.StatusInternalServerError) {
		t.Fatalf("a guest with no container runtime admitted a sandbox image: %v", err)
	}
	select {
	case err := <-h.agent.Fatal():
		if err == nil {
			t.Fatal("the guest ends for no reason")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the guest carries on with a sandbox it could not admit")
	}
}

// Between its bind and its sandbox's start the guest is verifiable but inert:
// it attests as bound, and neither runs commands nor accepts credentials.
func TestBoundGuestIsInertUntilItsSandboxRuns(t *testing.T) {
	p := newPool(t)
	p.runner.gate = make(chan struct{})
	p.start(t)
	binder := p.client(t, p.access)
	ready, err := binder.Ready(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	bind := p.bindFor(t, ready, nil)
	bound := make(chan error, 1)
	go func() {
		_, err := binder.Bind(ctxT(t), bind)
		bound <- err
	}()
	until(t, "the bind reaches the runner", func() bool { return p.runner.recorded() == "prepare "+sandboxImage })
	p.pin(ready, bind)
	signer := p.access

	strict := p.client(t, signer)
	if _, err := strict.Attest(ctxT(t)); !isVerdict(err) {
		t.Fatalf("a policy that wants the sandbox accepted a guest that does not run it yet: %v", err)
	}
	p.policy.AllowBound = true
	lenient := p.client(t, signer)
	att, err := lenient.Attest(ctxT(t))
	if err != nil || att.Phase != session.PhaseBound || len(att.Events) != 2 {
		t.Fatalf("attestation before the sandbox runs = %+v, %v", att, err)
	}
	if _, err := lenient.PutCredential(ctxT(t), "test-token", []byte("x")); !isVerdict(err) {
		t.Fatalf("the client released a credential to a guest whose sandbox does not run: %v", err)
	}
	body := []byte(`{"value":"eA=="}`)
	header, err := signer.AuthorizationFor(sessiontest.Audience(t, p.url), "PUT", session.PathCredentials+"test-token", body)
	if err != nil {
		t.Fatal(err)
	}
	if status := p.raw(t, "PUT", session.PathCredentials+"test-token", body, header); status != http.StatusConflict {
		t.Fatalf("the agent accepted a credential before its sandbox ran: HTTP %d", status)
	}
	_, err = lenient.Exec(ctxT(t), session.ExecRequest{Argv: []string{"true"}})
	assertStatus(t, err, http.StatusConflict)

	close(p.runner.gate)
	if err := <-bound; err != nil {
		t.Fatalf("Bind: %v", err)
	}
	// The client that saw the guest a moment ago looks again.
	if _, err := lenient.PutCredential(ctxT(t), "test-token", []byte("x")); err != nil {
		t.Fatalf("release once the sandbox runs, by the client that had seen the guest before: %v", err)
	}
	p.policy.AllowBound = false
	after := p.client(t, signer)
	att, err = after.Attest(ctxT(t))
	if err != nil || att.Phase != session.PhaseRunning || len(att.Events) != 3 {
		t.Fatalf("running attestation = %+v, %v", att, err)
	}
	if _, err := after.PutCredential(ctxT(t), "test-token", []byte("x")); err != nil {
		t.Fatalf("release once the sandbox runs: %v", err)
	}
}

func isVerdict(err error) bool {
	var verdict *session.VerificationError
	return errors.As(err, &verdict)
}

// A guest of another build is refused in the handshake; a guest launched for
// another key is refused at the fresh attestation. Either way no credential
// leaves the client.
func TestWrongGuestGetsNothing(t *testing.T) {
	h := newHarness(t, nil)
	h.start(t)
	signer := h.owner

	other := sessiontest.NewTD()
	wrongImage := h.policy
	identity, err := runtimemeasure.LoadImageManifest(other.WriteManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	wrongImage.Image = identity
	wrongImage.Launch, wrongImage.Bind, wrongImage.Tenant, wrongImage.Session = nil, nil, "acme", "sbx-1"

	_, strangerPub := newSigner(t)
	wrongKey := h.policy
	wrongKey.LaunchKey = []byte(strangerPub)
	wrongKey.Launch, wrongKey.Bind, wrongKey.Tenant, wrongKey.Session = nil, nil, "acme", "sbx-1"

	for name, policy := range map[string]session.Policy{"another image": wrongImage, "another launch key": wrongKey} {
		t.Run(name, func(t *testing.T) {
			client, err := session.NewClient(h.url, policy, sessiontest.Engine{}, signer)
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
	client := h.client(t, h.owner)
	if _, err := client.Exec(ctxT(t), session.ExecRequest{Argv: []string{"true"}}); err != nil {
		t.Fatal(err)
	}
	addr := strings.TrimPrefix(h.url, "https://")

	// Another guest of the same image, bound to a session that welcomes the
	// client's key, takes over the address.
	other := newHarnessIn(t, func(o *session.BundleOptions) { o.ManifestPath = h.td.WriteManifest(t) }, func(o *session.BindOptions) {
		o.Policy.Access = session.Access{Exec: []string{h.ownerPub}, Credentials: []string{h.ownerPub}}
	})
	other.td.MRTD, other.td.RTMR[1], other.td.RTMR[2] = h.td.MRTD, h.td.RTMR[1], h.td.RTMR[2]
	other.start(t)
	client.Close()
	h.stop()
	other.stop()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("cannot rebind %s: %v", addr, err)
	}
	srv := other.agent.Server()
	go func() { _ = other.agent.Serve(srv, ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	if _, err := client.Exec(ctxT(t), session.ExecRequest{Argv: []string{"true"}}); !isVerdict(err) {
		t.Fatalf("a client kept talking to a new instance key without attesting it: %v", err)
	}
	if _, err := client.Attest(ctxT(t)); !isVerdict(err) {
		t.Fatalf("attest must not silently adopt a new key on a pinned client: %v", err)
	}
	// A client of the guest that is there now attests it from scratch and is
	// fine.
	other.url = h.url
	fresh := other.client(t, h.owner)
	if _, err := fresh.Exec(ctxT(t), session.ExecRequest{Argv: []string{"true"}}); err != nil {
		t.Fatalf("a client of the guest at the address now: %v", err)
	}
}

// splitter is the host in the middle: one address, and its own choice, per
// connection, of which guest answers. firstDropped closes when the client side
// of connection 1 ends, and accepted counts the connections it took.
type splitter struct {
	url          string
	firstDropped chan struct{}
	accepted     atomic.Int32
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
			s.accepted.Add(1)
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

// The host can answer one address with two guests. A client's first
// connection may reach a guest of the pinned image that the host launched and
// bound itself, to a session that welcomes the client's own key. The client
// refuses that guest's evidence and keeps no connection to it. Its next
// attempt starts on a new connection, and once it has attested the right
// guest there, its commands and credentials reach that guest alone.
func TestAGuestTheClientRefusedGetsNothing(t *testing.T) {
	h := newHarness(t, nil)
	h.start(t)

	impostor := newHarnessIn(t, func(o *session.BundleOptions) { o.ManifestPath = h.td.WriteManifest(t) }, func(o *session.BindOptions) {
		o.Policy.Access = session.Access{Exec: []string{h.ownerPub}, Credentials: []string{h.ownerPub}}
	})
	impostor.td.MRTD, impostor.td.RTMR[1], impostor.td.RTMR[2] = h.td.MRTD, h.td.RTMR[1], h.td.RTMR[2]
	impostor.start(t)

	// Without a pinned document the handshake proves the image and nothing
	// about who launched or bound the guest, so the impostor passes it.
	policy := h.policy
	policy.Launch, policy.Bind, policy.Tenant, policy.Session = nil, nil, "acme", "sbx-1"
	host := newSplitter(t, func(n int) string {
		if n == 1 {
			return strings.TrimPrefix(impostor.url, "https://")
		}
		return strings.TrimPrefix(h.url, "https://")
	})
	client, err := session.NewClient(host.url, policy, sessiontest.Engine{}, h.owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)

	// The first connection reaches the impostor. It answers the attestation:
	// the token named it, as the guest that connection ends at.
	if _, err := client.Attest(ctxT(t)); !isVerdict(err) {
		t.Fatalf("the impostor's evidence must be refused, got %v", err)
	}
	// The client must have dropped that connection itself. Were it still open,
	// the next request would be the impostor's too.
	select {
	case <-host.firstDropped:
	case <-time.After(5 * time.Second):
		t.Fatal("the client kept its connection to a guest whose evidence it refused")
	}
	// The second reaches the real guest, which attests and gets pinned.
	if _, err := client.Attest(ctxT(t)); err != nil {
		t.Fatalf("attest the real guest: %v", err)
	}
	marker := session.ExecRequest{Argv: []string{"sh", "-c", `echo here > "$HOME/marker"`}}
	if resp, err := client.Exec(ctxT(t), marker); err != nil || resp.ExitCode != 0 {
		t.Fatalf("exec = %+v, %v", resp, err)
	}
	// The command traveled on the connection the guest was attested on: the
	// first command after an attestation costs no second handshake.
	if n := host.accepted.Load(); n != 2 {
		t.Fatalf("the client opened %d connections: one to the guest it refused, and one for the rest, makes 2", n)
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

// One guard speaks before the guest serves and another before a sandbox
// starts. A guest whose packet filter is not the image's does neither.
func TestGuardIsAskedBeforeServingAndBeforeTheSandbox(t *testing.T) {
	wrong := errors.New("the packet filter in force is not the one this image loads")

	h := newUnbound(t, nil)
	h.cfg.Logger = slog.New(slog.DiscardHandler)
	h.cfg.Guard = func(context.Context) error { return wrong }
	addr := freeAddr(t)
	if err := sessionagent.Run(context.Background(), h.cfg, addr); !errors.Is(err, wrong) || !strings.Contains(err.Error(), "before serving") {
		t.Fatalf("Run = %v", err)
	}
	if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		conn.Close()
		t.Fatal("the guest serves with the wrong packet filter")
	}

	// Right at boot, wrong by the time the sandbox is to start. What is
	// asked before the guest serves is not asked again.
	p := newPool(t)
	var asked, served atomic.Int32
	p.cfg.Guard = func(context.Context) error {
		served.Add(1)
		return nil
	}
	p.cfg.BindGuard = func(context.Context) error {
		asked.Add(1)
		return wrong
	}
	p.start(t)
	client := p.client(t, p.access)
	ready, err := client.Ready(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	bind := p.bindFor(t, ready, nil)
	if _, err := client.Bind(ctxT(t), bind); !isStatus(err, http.StatusInternalServerError) {
		t.Fatalf("Bind = %v", err)
	}
	if fatal := p.fatal(t); !errors.Is(fatal, wrong) || !strings.Contains(fatal.Error(), "before starting the sandbox") {
		t.Fatalf("the guest ends with %v", fatal)
	}
	if asked.Load() != 1 || p.runner.recorded() != "prepare "+sandboxImage {
		t.Fatalf("guard asked %d times, runner steps %s", asked.Load(), p.runner.recorded())
	}
	if served.Load() > 1 {
		t.Fatalf("what is checked before the guest serves was checked %d times", served.Load())
	}
	seed := runtimemeasure.Seed(p.bundle.LaunchKey)
	bound := runtimemeasure.FromDigestsSeeded(seed, []string{session.DocumentDigest(p.bundle.Launch), session.DocumentDigest(bind.Raw)})
	if !bytes.Equal(bound[:], register(t, p.td)) {
		t.Fatal("the sandbox was measured although it was not going to start")
	}
}
