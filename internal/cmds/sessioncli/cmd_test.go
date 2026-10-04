package sessioncli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/sessionsim"
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// counting is the test engine, counting what it is asked to judge.
type counting struct {
	sessiontest.Engine
	calls atomic.Int32
}

func (e *counting) VerifyEvidence(ctx context.Context, env teetypes.AttestationEvidence, reportData []byte) (*teetypes.VerificationResult, error) {
	e.calls.Add(1)
	return e.Engine.VerifyEvidence(ctx, env, reportData)
}

// Requirements makes the engine one whose verdicts a binding keeps.
func (e *counting) Requirements() string { return "counting" }

// unbound is the flags an owner binds a simulated guest with: a bare guest,
// whose bind names no image.
func unbound(t *testing.T, guest *sessionsim.Guest) *bindFlags {
	t.Helper()
	authority, err := certutil.MarshalECKeyPEM(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(t.TempDir(), "authority.key")
	if err := os.WriteFile(key, authority, 0o600); err != nil {
		t.Fatal(err)
	}
	b := &bindFlags{authorityKey: key, out: filepath.Join(t.TempDir(), "binding"), ttl: time.Minute}
	b.url, b.manifest, b.launchKey = guest.URL, guest.ManifestPath, guest.LaunchKeyPath
	b.tenant, b.session = "acme", "sbx-1"
	b.timeout, b.engineForTest = 30*time.Second, &counting{}
	b.w.credentials = []string{"test-token:64"}
	return b
}

// driving is the flags the owner's later commands take: the binding alone.
func driving(b *bindFlags) *trust {
	return &trust{url: b.url, binding: b.out, manifest: b.manifest, timeout: b.timeout, engineForTest: b.engineForTest}
}

func bind(t *testing.T, b *bindFlags) bound {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := runBind(context.Background(), b, true, &stdout, &stderr); code != ExitOK {
		t.Fatalf("bind exit %d: %s%s", code, stdout.String(), stderr.String())
	}
	var res bound
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	return res
}

func TestBundleNew(t *testing.T) {
	manifest := sessiontest.NewTD().WriteManifest(t)
	image := "ghcr.io/acme/agent@sha256:" + strings.Repeat("1", 64)
	run := func(args ...string) (string, string, error) {
		cmd := newBundleCmd()
		var stdout bytes.Buffer
		cmd.SetOut(&stdout)
		cmd.SetErr(io.Discard)
		out := filepath.Join(t.TempDir(), "bundle")
		cmd.SetArgs(append([]string{"--out", out, "--image-manifest", manifest}, args...))
		err := cmd.Execute()
		return out, stdout.String(), err
	}

	out, said, err := run("--pool", "agents", "--class", "s-4x16", "--prestage", image, "--machine", strings.Repeat("a", 96))
	if err != nil || !strings.Contains(said, "pool agents, class s-4x16") {
		t.Fatalf("launch-config new: %v, %q", err, said)
	}
	bundle, err := session.LoadBundle(out)
	if err != nil {
		t.Fatal(err)
	}
	doc := bundle.Document
	if doc.Pool != "agents" || doc.Class != "s-4x16" || doc.AgeLimit() != time.Hour || len(doc.Prestage) != 1 || doc.Machine == nil {
		t.Fatalf("the document: %+v", doc)
	}
	if out, _, err = run("--pool", "agents", "--class", "s-4x16", "--age-limit", "0"); err != nil {
		t.Fatal(err)
	}
	if bundle, err = session.LoadBundle(out); err != nil || bundle.Document.AgeLimitSeconds != 0 {
		t.Fatalf("a document with no age limit: %+v, %v", bundle, err)
	}

	for name, args := range map[string][]string{
		"no pool":                       {"--class", "s-4x16"},
		"no class":                      {"--pool", "agents"},
		"a tenant, which no pool names": {"--pool", "agents", "--class", "s-4x16", "--tenant", "acme"},
		"a sandbox, which a bind names": {"--pool", "agents", "--class", "s-4x16", "--sandbox-image", image},
		"an age limit under a minute":   {"--pool", "agents", "--class", "s-4x16", "--age-limit", "30s"},
		"an image with no digest":       {"--pool", "agents", "--class", "s-4x16", "--prestage", "ghcr.io/acme/agent:latest"},
	} {
		out, _, err := run(args...)
		if err == nil {
			t.Errorf("launch-config new with %s was accepted", name)
		}
		if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
			t.Errorf("launch-config new with %s wrote a bundle", name)
		}
	}
}

func TestBindThenDrive(t *testing.T) {
	guest := sessionsim.NewGuest(t, nil)
	b := unbound(t, guest)
	res := bind(t, b)
	if !res.Bound || res.Tenant != "acme" || res.Session != "sbx-1" || res.Phase != "running" || res.BindDigest == "" || res.Binding != b.out {
		t.Fatalf("bind result = %+v", res)
	}
	for _, name := range []string{session.BindFile, session.BindSignatureFile, session.DocumentFile, session.SignatureFile, session.PubkeyFile, session.AccessKeyFile, session.VerdictFile} {
		if _, err := os.Stat(filepath.Join(b.out, name)); err != nil {
			t.Fatalf("binding directory: %v", err)
		}
	}
	if info, err := os.Stat(filepath.Join(b.out, session.AccessKeyFile)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("access key mode: %v, %v", info.Mode(), err)
	}

	// The binding directory alone is enough to verify and drive the guest.
	flags := driving(b)
	var stdout, stderr bytes.Buffer
	if code := runVerify(context.Background(), flags, true, &stdout, &stderr); code != ExitOK {
		t.Fatalf("verify exit %d: %s%s", code, stdout.String(), stderr.String())
	}
	var v verdict
	if err := json.Unmarshal(stdout.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if !v.Verified || v.Tenant != "acme" || v.Session != "sbx-1" || len(v.Events) != 2 || v.BindDigest != res.BindDigest || v.Machine == "" || !v.MachinePinned {
		t.Fatalf("verdict = %+v", v)
	}
	stdout.Reset()
	if code := runCredentialPut(context.Background(), flags, "test-token", []byte("hunter2"), &stdout, &stderr); code != ExitOK {
		t.Fatalf("credential put exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "released 7 bytes as test-token to tenant acme session sbx-1") {
		t.Fatalf("credential put said %q", stdout.String())
	}
	stdout.Reset()
	show := session.ExecRequest{Argv: []string{"sh", "-c", `cat "$C8S_CREDENTIALS_DIR/test-token"`}}
	if code := runExec(context.Background(), flags, show, &stdout, &stderr); code != 0 || stdout.String() != "hunter2" {
		t.Fatalf("exec exit %d stdout %q stderr %q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	if code := runExec(context.Background(), flags, session.ExecRequest{Argv: []string{"sh", "-c", "exit 7"}}, &stdout, &stderr); code != 7 {
		t.Fatalf("a command that exits 7: exit %d", code)
	}

	// A second owner finds the guest taken, and nothing of theirs is written.
	second := unbound(t, guest)
	stdout.Reset()
	if code := runBind(context.Background(), second, true, &stdout, &stderr); code != ExitRefused {
		t.Fatalf("second bind exit %d: %s", code, stdout.String())
	}
	if _, err := os.Stat(second.out); !os.IsNotExist(err) {
		t.Fatalf("a refused bind left a binding directory: %v", err)
	}

	// Pinning another authority than the one that signed the binding is a
	// usage error.
	other := *flags
	other.authority = b.launchKey
	if _, err := other.client(io.Discard); err == nil {
		t.Fatal("a binding signed by one authority was accepted under another")
	}
}

func TestBindUsageErrors(t *testing.T) {
	b := unbound(t, sessionsim.NewGuest(t, nil))
	for name, mutate := range map[string]func(*bindFlags){
		"out exists":                func(f *bindFlags) { f.out = t.TempDir() },
		"no authority key":          func(f *bindFlags) { f.authorityKey = filepath.Join(t.TempDir(), "absent") },
		"launch key is not a key":   func(f *bindFlags) { f.launchKey = f.manifest },
		"a tenant that is no name":  func(f *bindFlags) { f.tenant = "Acme Corp" },
		"an image without a digest": func(f *bindFlags) { f.w.image = "ghcr.io/acme/agent:latest" },
	} {
		t.Run(name, func(t *testing.T) {
			f := *b
			mutate(&f)
			var stdout, stderr bytes.Buffer
			if code := runBind(context.Background(), &f, false, &stdout, &stderr); code != ExitUsage {
				t.Fatalf("exit %d: %s", code, stderr.String())
			}
		})
	}
	// None of them reached the guest: it still takes its bind.
	bind(t, b)
}

func TestTrustFlagsUsageErrors(t *testing.T) {
	b := unbound(t, sessionsim.NewGuest(t, nil))
	bind(t, b)
	for name, mutate := range map[string]func(*trust){
		"no binding and no launch key": func(f *trust) { f.binding = "" },
		"a binding and a launch key":   func(f *trust) { f.launchKey = b.launchKey },
		"a launch key and no authority": func(f *trust) {
			f.binding, f.launchKey, f.key = "", b.launchKey, filepath.Join(b.out, session.AccessKeyFile)
		},
		"a manifest that is not there":   func(f *trust) { f.manifest = filepath.Join(t.TempDir(), "absent.json") },
		"a signing key that is not one":  func(f *trust) { f.key = b.manifest },
		"a binding that is not readable": func(f *trust) { f.binding = t.TempDir() },
		"a TCB status nobody can accept": func(f *trust) { f.acceptTCB = []string{"Revoked"} },
		"a TCB status Intel has not":     func(f *trust) { f.acceptTCB = []string{"Fine"} },
	} {
		f := *driving(b)
		mutate(&f)
		var stdout, stderr bytes.Buffer
		if code := runVerify(context.Background(), &f, false, &stdout, &stderr); code != ExitUsage {
			t.Errorf("%s: exit %d: %s", name, code, stderr.String())
		}
	}

	// The flag's statuses reach a policy in one order, each once, however
	// they were given, and a guest that is UpToDate verifies under them.
	f := *driving(b)
	f.acceptTCB = []string{"SWHardeningNeeded", "OutOfDate", "OutOfDate"}
	if got := f.acceptedTCB(); !slices.Equal(got, []string{"OutOfDate", "SWHardeningNeeded"}) {
		t.Fatalf("the policy accepts %v", got)
	}
	if got := (&trust{}).acceptedTCB(); len(got) != 0 {
		t.Fatalf("a command with no flag accepts %v", got)
	}
	var stdout, stderr bytes.Buffer
	if code := runVerify(context.Background(), &f, false, &stdout, &stderr); code != ExitOK {
		t.Fatalf("verify --accept-tcb-status: exit %d: %s", code, stderr.String())
	}
}

// The bind's answer carries a verdict into the binding, and the owner's next
// commands rest on it: they ask the guest for no quote and judge nothing.
// 'verify' always judges fresh evidence, and --fresh makes any command do so.
func TestCommandsOfABindingShareAVerdict(t *testing.T) {
	b := unbound(t, sessionsim.NewGuest(t, nil))
	bind(t, b)
	engine := b.engineForTest.(*counting)
	run := func(flags *trust) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if code := runExec(context.Background(), flags, session.ExecRequest{Argv: []string{"true"}}, &stdout, &stderr); code != 0 {
			t.Fatalf("exec exit %d: %s", code, stderr.String())
		}
	}

	before := engine.calls.Load()
	run(driving(b))
	run(driving(b))
	if n := engine.calls.Load() - before; n != 0 {
		t.Fatalf("two commands under a kept verdict judged evidence %d times", n)
	}
	fresh := driving(b)
	fresh.fresh = true
	run(fresh)
	if n := engine.calls.Load() - before; n == 0 {
		t.Fatal("a command told to ask afresh judged nothing")
	}
	before = engine.calls.Load()
	var stdout, stderr bytes.Buffer
	if code := runVerify(context.Background(), driving(b), true, &stdout, &stderr); code != ExitOK || engine.calls.Load() == before {
		t.Fatalf("verify exit %d after %d judgments: %s", code, engine.calls.Load()-before, stderr.String())
	}

	// A file that is no verdict costs the next command an attestation and
	// nothing else.
	if err := os.WriteFile(filepath.Join(b.out, session.VerdictFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	before = engine.calls.Load()
	run(driving(b))
	if engine.calls.Load() == before {
		t.Fatal("a command with no usable verdict judged nothing")
	}
	if _, err := session.LoadVerdict(b.out); err != nil {
		t.Fatalf("the command did not keep its own verdict in the damaged one's place: %v", err)
	}
}

// A binding is for one guest. Another guest of the same pool at the address
// gets no command, and the verdict that did not hold is removed.
func TestCommandUnderABindingRefusesAnotherGuest(t *testing.T) {
	guest := sessionsim.NewGuest(t, nil)
	b := unbound(t, guest)
	bind(t, b)
	twin := guest.Twin(t, nil)
	other := unbound(t, twin)
	other.authorityKey, other.engineForTest = b.authorityKey, b.engineForTest
	bind(t, other)

	flags := driving(b)
	flags.url = twin.URL
	var stdout, stderr bytes.Buffer
	if code := runExec(context.Background(), flags, session.ExecRequest{Argv: []string{"true"}}, &stdout, &stderr); code != ExitExecRefused {
		t.Fatalf("a command for one guest, sent to another: exit %d: %s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(b.out, session.VerdictFile)); !os.IsNotExist(err) {
		t.Fatalf("the verdict that did not hold was kept: %v", err)
	}
	stdout.Reset()
	if code := runVerify(context.Background(), flags, true, &stdout, &stderr); code != ExitRefused {
		t.Fatalf("verify of another guest under the binding: exit %d: %s", code, stdout.String())
	}
}

func TestVerifyExitCodes(t *testing.T) {
	b := unbound(t, sessionsim.NewGuest(t, nil))
	bind(t, b)

	// Another image than the guest's: a verdict, and it is no.
	wrongImage := driving(b)
	wrongImage.manifest = sessiontest.NewTD().WriteManifest(t)
	var stdout, stderr bytes.Buffer
	if code := runVerify(context.Background(), wrongImage, true, &stdout, &stderr); code != ExitRefused {
		t.Fatalf("a guest of another image: exit %d: %s", code, stdout.String())
	}
	var v verdict
	if err := json.Unmarshal(stdout.Bytes(), &v); err != nil || v.Verified || v.Error == "" {
		t.Fatalf("verdict = %+v, %v", v, err)
	}

	// Nobody at the address: no verdict.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gone := driving(b)
	gone.url, gone.timeout = "https://"+ln.Addr().String(), 5*time.Second
	_ = ln.Close()
	stdout.Reset()
	if code := runVerify(context.Background(), gone, true, &stdout, &stderr); code != ExitUnavailable {
		t.Fatalf("a guest that is not there: exit %d: %s", code, stdout.String())
	}
	stdout.Reset()
	if code := runExec(context.Background(), gone, session.ExecRequest{Argv: []string{"true"}}, &stdout, &stderr); code != ExitExecUnavailable {
		t.Fatalf("a command for a guest that is not there: exit %d", code)
	}
}

func TestAdmissionText(t *testing.T) {
	steps := []session.AdmissionStep{{Name: "fetch", Micros: 1500}, {Name: "start", Micros: 250}}
	if got := admissionText(steps); got != "fetch 1.5ms, start 300µs" {
		t.Fatalf("admission text = %q", got)
	}
}
