package sessioncli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/sessiond"
	"github.com/confidential-dot-ai/c8s/internal/sessiond/sessiondtest"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/daemon"
	"github.com/confidential-dot-ai/c8s/pkg/session/sessionsim"
)

// starting is the flags an owner starts a session with on host, as its own
// orchestrator.
func starting(t *testing.T, host *sessiondtest.Host, name string) *startFlags {
	t.Helper()
	authority, err := certutil.MarshalECKeyPEM(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(t.TempDir(), "authority.key")
	if err := os.WriteFile(key, authority, 0o600); err != nil {
		t.Fatal(err)
	}
	s := &startFlags{pool: sessiondtest.Pool, wait: 10 * time.Second}
	s.authorityKey, s.out, s.ttl = key, filepath.Join(t.TempDir(), "binding"), time.Minute
	s.daemon = daemonFlags{address: host.Addr, ca: host.CAFile, cert: host.OrchestratorCertFile, key: host.OrchestratorKeyFile}
	s.manifest, s.launchKey = host.ManifestPath, host.LaunchKeyPath
	s.tenant, s.session = "acme", name
	s.timeout, s.engineForTest = 30*time.Second, &counting{}
	s.w.credentials = []string{"test-token:64"}
	return s
}

func start(t *testing.T, s *startFlags) startedSession {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := runStart(context.Background(), s, true, &stdout, &stderr); code != ExitOK {
		t.Fatalf("start exit %d: %s%s", code, stdout.String(), stderr.String())
	}
	var res startedSession
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	return res
}

// The owner's whole path through a daemon, with the commands alone: start,
// verify, release a credential, run a command, destroy. After the start, the
// binding directory is all the later commands are given.
func TestStartThenDriveThroughADaemon(t *testing.T) {
	host := sessiondtest.NewHost(t, 1, nil)
	s := starting(t, host, "sbx-1")
	res := start(t, s)
	if !res.Started || res.Tenant != "acme" || res.Session != "sbx-1" || res.Phase != "running" || res.TD == "" || res.Host != "host-a" || res.Binding != s.out {
		t.Fatalf("start result = %+v", res)
	}
	for _, name := range []string{session.BindFile, session.DocumentFile, session.PubkeyFile, session.AccessKeyFile, session.VerdictFile, session.ReceiptFile, daemon.RouteFile} {
		if _, err := os.Stat(filepath.Join(s.out, name)); err != nil {
			t.Fatalf("binding directory: %v", err)
		}
	}
	// The guest answered the bind with its receipt, and the quote the start
	// judged confirmed it.
	if !res.Receipt || (res.Quote != quoteWithAnswer && res.Quote != quoteWithEvidence) {
		t.Fatalf("start result = %+v", res)
	}
	// The start judged the bind's answer, and asked the guest for no quote of
	// its own. Its verdict spares the next commands theirs.
	engine := s.engineForTest.(*counting)
	judged := engine.calls.Load()

	flags := &trust{binding: s.out, manifest: s.manifest, timeout: s.timeout, engineForTest: engine}
	var stdout, stderr bytes.Buffer
	if code := runCredentialPut(context.Background(), flags, "test-token", []byte("hunter2"), &stdout, &stderr); code != ExitOK {
		t.Fatalf("credential put exit %d: %s", code, stderr.String())
	}
	stdout.Reset()
	show := session.ExecRequest{Argv: []string{"sh", "-c", `cat "$C8S_CREDENTIALS_DIR/test-token"`}}
	flags = &trust{binding: s.out, manifest: s.manifest, timeout: s.timeout, engineForTest: engine}
	if code := runExec(context.Background(), flags, show, &stdout, &stderr); code != 0 || stdout.String() != "hunter2" {
		t.Fatalf("exec exit %d stdout %q stderr %q", code, stdout.String(), stderr.String())
	}
	if now := engine.calls.Load(); now > judged+2 {
		t.Fatalf("the commands after the start judged evidence %d times", now-judged)
	}
	stdout.Reset()
	flags = &trust{binding: s.out, manifest: s.manifest, timeout: s.timeout, engineForTest: engine}
	if code := runVerify(context.Background(), flags, true, &stdout, &stderr); code != ExitOK {
		t.Fatalf("verify exit %d: %s%s", code, stdout.String(), stderr.String())
	}
	var v verdict
	if err := json.Unmarshal(stdout.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if !v.Verified || v.Tenant != "acme" || v.Session != "sbx-1" || v.BindDigest != res.BindDigest || !v.Receipt {
		t.Fatalf("verdict = %+v", v)
	}

	// A second session of the same name is refused while the first lives.
	second := starting(t, host, "sbx-1")
	stdout.Reset()
	if code := runStart(context.Background(), second, true, &stdout, &stderr); code != ExitUnavailable {
		t.Fatalf("a second start of a live session: exit %d: %s", code, stdout.String())
	}
	if _, err := os.Stat(second.out); !os.IsNotExist(err) {
		t.Fatal("the refused start wrote a binding")
	}

	orchestrator := &daemonFlags{cert: host.OrchestratorCertFile, key: host.OrchestratorKeyFile}
	stdout.Reset()
	if code := runDestroy(context.Background(), orchestrator, s.out, "", 30*time.Second, &stdout, &stderr); code != ExitOK {
		t.Fatalf("destroy exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "DESTROYED session sbx-1") || !strings.Contains(stdout.String(), res.TD) {
		t.Fatalf("destroy said %q", stdout.String())
	}
	flags = &trust{binding: s.out, manifest: s.manifest, timeout: 10 * time.Second, engineForTest: engine}
	if code := runExec(context.Background(), flags, session.ExecRequest{Argv: []string{"true"}}, &stdout, &stderr); code != ExitExecUnavailable {
		t.Fatalf("a command on a destroyed session: exit %d", code)
	}
}

// A start that pins another image, or another pool's launch key, signs
// nothing, writes nothing, and gives its claim back at once.
func TestStartRefusesAGuestItDidNotPin(t *testing.T) {
	host := sessiondtest.NewHost(t, 1, func(c *sessiond.Config) { c.Capacity = 1 })
	other := sessionsim.NewGuest(t, nil)
	for name, mutate := range map[string]func(*startFlags){
		"another image":             func(s *startFlags) { s.manifest = other.ManifestPath },
		"another pool's launch key": func(s *startFlags) { s.launchKey = other.LaunchKeyPath },
	} {
		s := starting(t, host, "sbx-1")
		mutate(s)
		var stdout, stderr bytes.Buffer
		if code := runStart(context.Background(), s, true, &stdout, &stderr); code != ExitRefused {
			t.Fatalf("%s: start exit %d: %s%s", name, code, stdout.String(), stderr.String())
		}
		if _, err := os.Stat(s.out); !os.IsNotExist(err) {
			t.Fatalf("%s: the refused start wrote a binding", name)
		}
	}
	// The host has room for one TD: the session starts only if the refused
	// starts left none claimed.
	if res := start(t, starting(t, host, "sbx-1")); !res.Started {
		t.Fatalf("start after the refusals = %+v", res)
	}
}

// The receipt a start keeps with the binding is the guest's signed word that
// it took the bind. A verification holds it to the guest it attests: another
// session's receipt in its place is refused, and so is one that was changed.
// Without one, a verification says so and judges the guest alone.
func TestVerifyHoldsTheKeptReceiptToItsGuest(t *testing.T) {
	host := sessiondtest.NewHost(t, 2, nil)
	s1, s2 := starting(t, host, "sbx-1"), starting(t, host, "sbx-2")
	start(t, s1)
	start(t, s2)
	verify := func(binding string) (int, verdict) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		flags := &trust{binding: binding, manifest: s1.manifest, timeout: s1.timeout, engineForTest: &counting{}}
		code := runVerify(context.Background(), flags, true, &stdout, &stderr)
		var v verdict
		if err := json.Unmarshal(stdout.Bytes(), &v); err != nil {
			t.Fatalf("verify said %s%s", stdout.String(), stderr.String())
		}
		return code, v
	}
	if code, v := verify(s1.out); code != ExitOK || !v.Verified || !v.Receipt {
		t.Fatalf("verify with the guest's own receipt: exit %d, %+v", code, v)
	}
	own, err := os.ReadFile(filepath.Join(s1.out, session.ReceiptFile))
	if err != nil {
		t.Fatal(err)
	}
	others, err := os.ReadFile(filepath.Join(s2.out, session.ReceiptFile))
	if err != nil {
		t.Fatal(err)
	}
	var signed session.SignedReceipt
	if err := json.Unmarshal(own, &signed); err != nil {
		t.Fatal(err)
	}
	signed.Receipt = bytes.Replace(signed.Receipt, []byte(`"running"`), []byte(`"bound"`), 1)
	changed, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	for name, receipt := range map[string][]byte{
		"another session's receipt":           others,
		"a receipt changed after it was kept": changed,
	} {
		if err := os.WriteFile(filepath.Join(s1.out, session.ReceiptFile), receipt, 0o600); err != nil {
			t.Fatal(err)
		}
		if code, v := verify(s1.out); code != ExitRefused || v.Verified || v.Receipt || !strings.Contains(v.Error, "receipt kept with the binding") {
			t.Fatalf("verify with %s: exit %d, %+v", name, code, v)
		}
	}
	if err := os.Remove(filepath.Join(s1.out, session.ReceiptFile)); err != nil {
		t.Fatal(err)
	}
	if code, v := verify(s1.out); code != ExitOK || !v.Verified || v.Receipt {
		t.Fatalf("verify with no receipt kept: exit %d, %+v", code, v)
	}
	if err := os.WriteFile(filepath.Join(s1.out, session.ReceiptFile), own, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, v := verify(s1.out); code != ExitOK || !v.Receipt {
		t.Fatalf("verify with the guest's own receipt put back: exit %d, %+v", code, v)
	}
}

// failingLater is an engine that judges its first evidence, the unbound
// guest's, and fails every one after it with err. With holds it still holds
// evidence to what needs none of the vendor's documents, as an engine does
// that only lacks a document.
type failingLater struct {
	counting
	err   error
	holds bool
	held  atomic.Int32
}

func (e *failingLater) VerifyEvidence(ctx context.Context, env teetypes.AttestationEvidence, reportData []byte) (*teetypes.VerificationResult, error) {
	if e.calls.Add(1) == 1 {
		return e.Engine.VerifyEvidence(ctx, env, reportData)
	}
	if e.holds && session.Offline(ctx) {
		e.held.Add(1)
		return e.Engine.VerifyEvidence(ctx, env, reportData)
	}
	return nil, e.err
}

// A guest that took the bind and cannot be held to it is of no use to
// anyone: the start ends its session, and the host has its place again. That
// is a guest whose quote is refused, and one whose quote can neither be
// judged nor held. A quote that cannot be judged for want of a document, and
// passes everything that needs none, leaves the session running with no
// verdict kept.
func TestStartEndsAGuestItCannotHoldToItsBind(t *testing.T) {
	host := sessiondtest.NewHost(t, 1, func(c *sessiond.Config) { c.Capacity = 1 })
	orchestrator := &daemonFlags{cert: host.OrchestratorCertFile, key: host.OrchestratorKeyFile}
	for name, tc := range map[string]struct {
		engine *failingLater
		code   int
	}{
		"a quote that is refused": {
			&failingLater{err: &session.VerificationError{Err: errors.New("the quote is not the pinned guest's")}}, ExitRefused,
		},
		"a quote that is refused, by an engine that would hold it": {
			&failingLater{err: &session.VerificationError{Err: errors.New("the quote is not the pinned guest's")}, holds: true}, ExitRefused,
		},
		"a quote that can be neither judged nor held": {
			&failingLater{err: errors.New("collateral unavailable")}, ExitUnavailable,
		},
	} {
		s := starting(t, host, "sbx-1")
		s.engineForTest = tc.engine
		var stdout, stderr bytes.Buffer
		if code := runStart(context.Background(), s, true, &stdout, &stderr); code != tc.code {
			t.Fatalf("%s: exit %d, want %d: %s%s", name, code, tc.code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), "its session was ended") {
			t.Fatalf("%s: the start said %s", name, stdout.String())
		}
		if tc.engine.held.Load() != 0 {
			t.Fatalf("%s: a refused quote was held %d times", name, tc.engine.held.Load())
		}
		if _, err := os.Stat(filepath.Join(s.out, session.VerdictFile)); err == nil {
			t.Fatalf("%s: a verdict was kept", name)
		}
		// The host has room for one TD, and the name is taken while a
		// session of it lives: the next start succeeds only if this one's
		// guest is gone.
		next := starting(t, host, "sbx-1")
		if res := start(t, next); !res.Started {
			t.Fatalf("%s: the start after it = %+v", name, res)
		}
		stdout.Reset()
		if code := runDestroy(context.Background(), orchestrator, next.out, "", 30*time.Second, &stdout, &stderr); code != ExitOK {
			t.Fatalf("destroy exit %d: %s", code, stderr.String())
		}
	}

	// Intel's service being away says nothing about the guest. Its quote is
	// the guest's own and agrees with its receipt: the session runs, and what
	// could not be judged is not kept as judged.
	away := starting(t, host, "sbx-2")
	engine := &failingLater{err: errors.New("collateral unavailable"), holds: true}
	away.engineForTest = engine
	var stdout, stderr bytes.Buffer
	if code := runStart(context.Background(), away, true, &stdout, &stderr); code != ExitUnavailable {
		t.Fatalf("a start whose guest's quote could not be judged: exit %d: %s%s", code, stdout.String(), stderr.String())
	}
	var res startedSession
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Started || !res.Receipt || !strings.Contains(res.Error, "no verdict was kept") || strings.Contains(res.Error, "its session was ended") {
		t.Fatalf("the start said %+v", res)
	}
	if engine.held.Load() != 1 {
		t.Fatalf("the quote was held %d times, want once", engine.held.Load())
	}
	if _, err := os.Stat(filepath.Join(away.out, session.VerdictFile)); err == nil {
		t.Fatal("a verdict was kept on a quote that was held and never judged")
	}
	if _, err := os.Stat(filepath.Join(away.out, session.ReceiptFile)); err != nil {
		t.Fatalf("the receipt the held quote confirmed was not kept: %v", err)
	}
	// The session is there: the owner's next command judges the guest
	// itself, and here it is ended by its name.
	stdout.Reset()
	if code := runDestroy(context.Background(), orchestrator, away.out, "", 30*time.Second, &stdout, &stderr); code != ExitOK || !strings.Contains(stdout.String(), "DESTROYED session sbx-2") {
		t.Fatalf("the session whose quote was held was not there to destroy: exit %d: %s%s", code, stdout.String(), stderr.String())
	}
}

// Without an orchestrator's certificate nothing starts, and a destroy needs
// one too.
func TestStartAndDestroyNeedACertificate(t *testing.T) {
	host := sessiondtest.NewHost(t, 1, nil)
	s := starting(t, host, "sbx-1")
	s.daemon.cert, s.daemon.key = "", ""
	var stdout, stderr bytes.Buffer
	if code := runStart(context.Background(), s, true, &stdout, &stderr); code != ExitUnavailable || !strings.Contains(stdout.String(), "certificate") {
		t.Fatalf("start with no certificate: exit %d: %s", code, stdout.String())
	}
	res := start(t, starting(t, host, "sbx-1"))
	anyone := &daemonFlags{address: host.Addr, ca: host.CAFile}
	if code := runDestroy(context.Background(), anyone, "", "sbx-1", 10*time.Second, &stdout, &stderr); code != ExitUnavailable {
		t.Fatalf("destroy with no certificate: exit %d", code)
	}
	_ = res
	for name, run := range map[string]func() int{
		"no daemon and no binding": func() int {
			return runDestroy(context.Background(), &daemonFlags{}, "", "sbx-1", time.Second, &stdout, &stderr)
		},
		"no session": func() int {
			return runDestroy(context.Background(), anyone, "", "", time.Second, &stdout, &stderr)
		},
	} {
		if code := run(); code != ExitUsage {
			t.Errorf("destroy with %s: exit %d", name, code)
		}
	}
}

// The flags that say where a guest is reached exclude each other.
func TestReachUsageErrors(t *testing.T) {
	for name, flags := range map[string]*trust{
		"neither an address nor a daemon": {},
		"an address and a daemon":         {url: "https://127.0.0.1:8443", daemon: daemonFlags{address: "127.0.0.1:7443"}, td: "td-1"},
		"a daemon and no TD":              {daemon: daemonFlags{address: "127.0.0.1:7443"}},
	} {
		if _, _, err := flags.reach(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// A start given a command sends it with the bind: the guest runs it as its
// session's first, and the start prints what it wrote once the session has
// verified. The guest is asked for no command over its own route, and the
// command's status is reported without changing the start's.
func TestStartCarriesTheSessionsFirstCommand(t *testing.T) {
	host := sessiondtest.NewHost(t, 1, nil)
	s := starting(t, host, "sbx-1")
	marker := filepath.Join(t.TempDir(), "ran")
	s.command = []string{"sh", "-c", `echo ran >> "$0"; echo out; echo err >&2; exit 7`, marker}
	res := start(t, s)
	if !res.Started || res.FirstCommand == nil {
		t.Fatalf("start result = %+v", res)
	}
	first := res.FirstCommand
	if !first.WithBind || first.ExitCode != 7 || string(first.Stdout) != "out\n" || string(first.Stderr) != "err\n" {
		t.Fatalf("the first command: %+v", first)
	}
	guest := host.Runner.All()[0]
	if n := guest.Asked(session.PathExec); n != 0 {
		t.Fatalf("the guest was asked for %d commands over its own route", n)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "ran\n" {
		t.Fatalf("the command ran %q times: %v", data, err)
	}
	// The session goes on under the binding the start wrote.
	var stdout, stderr bytes.Buffer
	flags := &trust{binding: s.out, manifest: s.manifest, timeout: s.timeout, engineForTest: s.engineForTest}
	if code := runExec(context.Background(), flags, session.ExecRequest{Argv: []string{"cat", marker}}, &stdout, &stderr); code != 0 || stdout.String() != "ran\n" {
		t.Fatalf("exec exit %d stdout %q stderr %q", code, stdout.String(), stderr.String())
	}

	// As text, the command's output follows the start's own.
	text := starting(t, host, "sbx-2")
	text.command = []string{"echo", "hello"}
	stdout.Reset()
	stderr.Reset()
	if code := runStart(context.Background(), text, false, &stdout, &stderr); code != ExitOK {
		t.Fatalf("start exit %d: %s%s", code, stdout.String(), stderr.String())
	}
	if out := stdout.String(); !strings.Contains(out, "first command exit 0, sent with the bind\nhello\n") || !strings.HasSuffix(out, "hello\n") {
		t.Fatalf("start printed %q", out)
	}
}
