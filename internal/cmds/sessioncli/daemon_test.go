package sessioncli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	if !res.Receipt || (res.Quote != quoteWithAnswer && res.Quote != quoteOnCall) {
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

// A start given a credential it holds seals it with the bind, beside the
// session's first command: the guest has it in place before its sandbox
// starts, where that command finds it, and is asked for nothing over its own
// routes.
func TestStartSealsTheCredentialsItHolds(t *testing.T) {
	host := sessiondtest.NewHost(t, 1, nil)
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("s3cr3t"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := starting(t, host, "sbx-1")
	s.sealed = []string{"api-token:16=" + token}
	s.command = []string{"sh", "-c", `cat "$C8S_CREDENTIALS_DIR/api-token"`}
	res := start(t, s)
	if !res.Started || res.FirstCommand == nil || res.Credentials == nil {
		t.Fatalf("start result = %+v", res)
	}
	if first := res.FirstCommand; !first.WithBind || first.ExitCode != 0 || string(first.Stdout) != "s3cr3t" {
		t.Fatalf("the first command: %+v", first)
	}
	if got := res.Credentials; len(got.WithBind) != 1 || got.WithBind[0] != "api-token" || len(got.After) != 0 {
		t.Fatalf("the credentials: %+v", got)
	}
	guest := host.Runner.All()[0]
	if n := guest.Asked(session.PathExec) + guest.Asked(session.PathCredentials+"api-token"); n != 0 {
		t.Fatalf("the guest was asked %d times over its own routes", n)
	}
	// The bind the start wrote declares the credential as its binder's.
	binding, err := session.LoadBinding(s.out)
	if err != nil {
		t.Fatal(err)
	}
	declared, ok := binding.Bind.Doc.Policy.Credential("api-token")
	if !ok || declared.Source != session.SourceBinder || declared.MaxBytes != 16 {
		t.Fatalf("the bind declares the credential as %+v", declared)
	}

	// With no command, the credential goes alone, and the start says so.
	alone := starting(t, host, "sbx-2")
	alone.sealed = []string{"api-token=" + token}
	var stdout, stderr bytes.Buffer
	if code := runStart(context.Background(), alone, false, &stdout, &stderr); code != ExitOK {
		t.Fatalf("start exit %d: %s%s", code, stdout.String(), stderr.String())
	}
	if out := stdout.String(); !strings.Contains(out, "credentials   api-token in place before the sandbox started\n") || strings.Contains(out, "first command") {
		t.Fatalf("start printed %q", out)
	}
}

// rooted is an engine whose verdict rests on the vendor's documents as the
// guest's host handed them over whenever its verification lets it: a
// verifier that has none of its own at hand.
type rooted struct{ session.Engine }

func (e rooted) VerifyEvidence(ctx context.Context, env teetypes.AttestationEvidence, reportData []byte) (*teetypes.VerificationResult, error) {
	res, err := e.Engine.VerifyEvidence(ctx, env, reportData)
	if err != nil {
		return nil, err
	}
	finding := &session.CollateralFinding{Fetched: time.Now(), Expires: time.Now().Add(time.Hour)}
	if session.HandedDocumentsAllowed(ctx) {
		finding = &session.CollateralFinding{Stapled: true, RootCRLStapled: true, Fetched: time.Now(), Expires: time.Now().Add(time.Hour)}
	}
	if res.Claims.PlatformData == nil {
		res.Claims.PlatformData = map[string]any{}
	}
	res.Claims.PlatformData[session.CollateralClaim] = finding
	return res, nil
}

// A start that sends something with its bind judges the guest as a verifier
// does whose verdict lets a secret go: on documents of its own, never on
// those the guest's host handed over. A start that sends nothing with its
// bind needs no more than a verdict that leads to a bind, and judges the
// bound guest on documents of its own before it sends anything after.
func TestStartSealsOnAVerdictMadeForRelease(t *testing.T) {
	host := sessiondtest.NewHost(t, 1, nil)
	s := starting(t, host, "sbx-1")
	s.engineForTest = rooted{s.engineForTest}
	s.command = []string{"echo", "sealed"}
	if res := start(t, s); !res.Started || res.FirstCommand == nil || !res.FirstCommand.WithBind {
		t.Fatalf("a start with a command: %+v", res)
	}
	plain := starting(t, host, "sbx-2")
	plain.engineForTest = rooted{plain.engineForTest}
	if res := start(t, plain); !res.Started || res.FirstCommand != nil {
		t.Fatalf("a start with nothing to seal: %+v", res)
	}
}

// With no sealed answer a start owes its guest everything it sealed, over
// the session's connection: every credential, then the command. With one, it
// owes the credentials the answer does not say the guest holds, and no
// command: what the answer says of the command is the guest's last word.
func TestStartOwesWhatNoSealedAnswerSaysIsDone(t *testing.T) {
	credentials := map[string][]byte{"b-token": []byte("b"), "a-token": []byte("a")}
	both := &session.SealedMessage{Command: &session.ExecRequest{Argv: []string{"true"}}}
	alone := &session.SealedMessage{}
	for name, tc := range map[string]struct {
		message     *session.SealedMessage
		said        *session.SealedAnswer
		held, again string
		resend      bool
	}{
		"no answer":                      {both, nil, "", "a-token,b-token", true},
		"no answer, and no command":      {alone, nil, "", "a-token,b-token", false},
		"an answer that holds both":      {both, &session.SealedAnswer{Credentials: map[string]string{"a-token": session.SealedHeld, "b-token": session.SealedHeld}}, "a-token,b-token", "", false},
		"an answer that refused one":     {both, &session.SealedAnswer{Credentials: map[string]string{"a-token": session.SealedHeld, "b-token": session.SealedUnauthorized}}, "a-token", "b-token", false},
		"an answer that says of neither": {both, &session.SealedAnswer{}, "", "a-token,b-token", false},
	} {
		held, again, resend := owed(tc.message, credentials, tc.said)
		if strings.Join(held, ",") != tc.held || strings.Join(again, ",") != tc.again || resend != tc.resend {
			t.Errorf("%s: held %v, owed %v, the command again %t", name, held, again, resend)
		}
	}
}

// A start waits for the quote over its bind's nonce on the bind's own call:
// a guest whose quoting service is slow answers with its receipt, the quote
// follows on that call, and the start says where it came from. It asks the
// daemon for none of the guest's evidence, and the guest for no attestation.
func TestStartTakesItsQuoteFromTheBindsOwnCall(t *testing.T) {
	host := sessiondtest.NewHost(t, 1, nil)
	for deadline := time.Now().Add(10 * time.Second); host.Runner.Booted() == 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the pool never launched its guest")
		}
	}
	guest := host.Runner.All()[0]
	s := starting(t, host, "sbx-1")
	release := guest.HoldQuotes()
	defer release()
	go func() {
		// Well after the guest has answered its bind.
		for deadline := time.Now().Add(10 * time.Second); guest.Asked(session.PathBind) == 0 && time.Now().Before(deadline); {
			time.Sleep(time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond)
		release()
	}()
	res := start(t, s)
	if !res.Started || !res.Receipt || res.Quote != quoteOnCall {
		t.Fatalf("a start whose guest's quote came after its receipt: %+v", res)
	}
	if n := guest.Asked(session.PathAttest); n != 0 {
		t.Fatalf("the guest was asked for %d attestations", n)
	}
}

// A start reads what it is to seal before it claims a guest: a credential it
// cannot read, cannot declare, or declares twice is a usage error, and no
// guest is taken for it.
func TestStartRefusesACredentialItCannotSeal(t *testing.T) {
	host := sessiondtest.NewHost(t, 1, nil)
	dir := t.TempDir()
	token, long := filepath.Join(dir, "token"), filepath.Join(dir, "long")
	for path, data := range map[string]string{token: "s3cr3t", long: strings.Repeat("x", 17)} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, set := range map[string]func(s *startFlags){
		"no file":                    func(s *startFlags) { s.sealed = []string{"api-token"} },
		"an empty file name":         func(s *startFlags) { s.sealed = []string{"api-token="} },
		"a file that is not there":   func(s *startFlags) { s.sealed = []string{"api-token=" + filepath.Join(dir, "absent")} },
		"a value beyond its size":    func(s *startFlags) { s.sealed = []string{"api-token:16=" + long} },
		"a size that is none":        func(s *startFlags) { s.sealed = []string{"api-token:0=" + token} },
		"a name that is none":        func(s *startFlags) { s.sealed = []string{"../token=" + token} },
		"one name twice":             func(s *startFlags) { s.sealed = []string{"api-token=" + token, "api-token=" + token} },
		"a name a key hands over":    func(s *startFlags) { s.sealed, s.w.credentials = []string{"api-token=" + token}, []string{"api-token"} },
		"a name of the key services": func(s *startFlags) { s.sealed, s.w.stored = []string{"api-token=" + token}, []string{"api-token"} },
	} {
		s := starting(t, host, "sbx-1")
		set(s)
		var stdout, stderr bytes.Buffer
		if code := runStart(context.Background(), s, false, &stdout, &stderr); code != ExitUsage {
			t.Errorf("%s: start exit %d: %s%s", name, code, stdout.String(), stderr.String())
		}
		// Told apart from the bind's own refusal of one name twice, which
		// comes once a guest is claimed.
		if (name == "a name a key hands over" || name == "a name of the key services") && !strings.Contains(stderr.String(), "declared by more than one flag") {
			t.Errorf("%s: start said %q", name, stderr.String())
		}
	}
	// The pool's guest boots beside the starts that were refused, and none
	// of them waited for it.
	for deadline := time.Now().Add(10 * time.Second); host.Runner.Booted() == 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the pool never launched its guest")
		}
	}
	if n := host.Runner.All()[0].Asked(session.PathBind); n != 0 {
		t.Fatalf("a guest was sent %d binds for starts that were refused", n)
	}
	// The pool still has its guest for a start that is in order.
	s := starting(t, host, "sbx-1")
	s.sealed = []string{"api-token=" + token}
	if res := start(t, s); !res.Started {
		t.Fatalf("start result = %+v", res)
	}
}

// printed is what a command that runs on has printed so far.
type printed struct {
	mu  sync.Mutex
	out bytes.Buffer
}

func (p *printed) Write(data []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.out.Write(data)
}

// events are the whole lines printed so far, read as `watch` writes them.
func (p *printed) events(t *testing.T) []tdEvent {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	var all []tdEvent
	for line := range strings.Lines(p.out.String()) {
		if !strings.HasSuffix(line, "\n") {
			break
		}
		var event tdEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("watch printed %q: %v", line, err)
		}
		all = append(all, event)
	}
	return all
}

// An orchestrator watches its host: each guest as it is, and then as it
// changes, so that it sees the session a start made and the guest's end.
func TestWatchShowsAnOrchestratorItsHostsGuests(t *testing.T) {
	host := sessiondtest.NewHost(t, 1, nil)
	orchestrator := &daemonFlags{address: host.Addr, ca: host.CAFile, cert: host.OrchestratorCertFile, key: host.OrchestratorKeyFile}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := &printed{}
	ended := make(chan int, 1)
	go func() { ended <- runWatch(ctx, orchestrator, out, io.Discard) }()
	shows := func(what string, ok func(tdEvent) bool) tdEvent {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for {
			events := out.events(t)
			for i := len(events) - 1; i >= 0; i-- {
				if ok(events[i]) {
					return events[i]
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("watch never showed %s: %+v", what, events)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	ready := shows("the pool's ready guest", func(e tdEvent) bool { return e.State == "ready" })
	if ready.TD == "" || ready.Pool != sessiondtest.Pool || ready.Host != "host-a" || ready.Session != "" || ready.At == "" {
		t.Fatalf("a ready guest was shown as %+v", ready)
	}
	res := start(t, starting(t, host, "sbx-1"))
	if res.TD != ready.TD {
		t.Fatalf("the session started on %s, and the guest shown ready was %s", res.TD, ready.TD)
	}
	running := shows("the session's guest running", func(e tdEvent) bool { return e.TD == res.TD && e.State == "running" })
	if running.Session != "sbx-1" || running.ClaimedBy != "" {
		t.Fatalf("the session's guest was shown as %+v", running)
	}
	var stdout, stderr bytes.Buffer
	if code := runDestroy(context.Background(), orchestrator, "", "sbx-1", 30*time.Second, &stdout, &stderr); code != ExitOK {
		t.Fatalf("destroy exit %d: %s", code, stderr.String())
	}
	if gone := shows("the session's guest ended", func(e tdEvent) bool { return e.TD == res.TD && e.State == "ended" }); gone.Reason != "destroyed" {
		t.Fatalf("the destroyed guest was shown as %+v", gone)
	}
	// Interrupted, the command ends well.
	cancel()
	select {
	case code := <-ended:
		if code != ExitOK {
			t.Fatalf("watch exit %d after it was interrupted", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("watch ran on after it was interrupted")
	}

	// Nobody but an orchestrator is shown a host's guests.
	anyone := &daemonFlags{address: host.Addr, ca: host.CAFile}
	stderr.Reset()
	if code := runWatch(context.Background(), anyone, &stdout, &stderr); code != ExitUnavailable || !strings.Contains(stderr.String(), "NOT WATCHED") {
		t.Fatalf("watch with no certificate: exit %d: %s", code, stderr.String())
	}
	if code := runWatch(context.Background(), &daemonFlags{}, &stdout, &stderr); code != ExitUsage {
		t.Fatalf("watch with no daemon: exit %d", code)
	}
	// A daemon that goes away ends the command, which says so.
	again, stop := context.WithCancel(context.Background())
	defer stop()
	go func() { ended <- runWatch(again, orchestrator, &printed{}, io.Discard) }()
	time.Sleep(200 * time.Millisecond)
	host.Stop()
	select {
	case code := <-ended:
		if code != ExitUnavailable {
			t.Fatalf("watch exit %d after its daemon went away", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("watch ran on after its daemon went away")
	}
}

// A session that a binder's bind started with no claim is shown to the
// orchestrator with the key of that binder.
func TestWatchNamesTheBinderWhoseBindClaimed(t *testing.T) {
	authority := newKey(t)
	authorityPub, err := session.PublicKeyPEM(&authority.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	named, err := session.InstanceKeyDigest(&authority.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	host := sessiondtest.NewHost(t, 1, func(c *sessiond.Config) {
		for i := range c.Pools[0].Binders {
			c.Pools[0].Binders[i].Authorities = []string{named}
		}
	})
	binderKey, err := daemon.BinderName(host.Binder.Leaf)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out := &printed{}
	orchestrator := &daemonFlags{address: host.Addr, ca: host.CAFile, cert: host.OrchestratorCertFile, key: host.OrchestratorKeyFile}
	go runWatch(ctx, orchestrator, out, io.Discard)

	binder := host.Client(&host.Binder)
	shown := make(chan *session.Relayed, 1)
	go func() {
		_ = binder.WatchReady(ctx, sessiondtest.Pool, func(r *session.Relayed) {
			select {
			case shown <- r:
			default:
			}
		}, nil)
	}()
	var evidence *session.Relayed
	select {
	case evidence = <-shown:
	case <-ctx.Done():
		t.Fatal("the binder was shown no ready guest")
	}
	policy := session.Policy{Image: host.Identity, LaunchKey: host.LaunchKey, Authority: authorityPub, AllowReady: true}
	ready, err := session.VerifyReady(ctx, policy, host.Engine, evidence, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bind, err := session.NewBind(session.BindOptions{Authority: authority, InstanceKey: ready.InstanceKey, Tenant: "acme", Session: "sbx-b", NotAfter: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	id, err := daemon.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	call, err := binder.BindWith(ctx, id, "", bind, nil)
	if err != nil {
		t.Fatalf("the binder's bind that claims: %v", err)
	}
	defer call.Close()
	deadline := time.Now().Add(20 * time.Second)
	for {
		for _, e := range out.events(t) {
			if e.TD == call.TD && e.Session == "sbx-b" && e.ClaimedBy == binderKey {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("watch never showed the binder that claimed %s: %+v", call.TD, out.events(t))
		}
		time.Sleep(10 * time.Millisecond)
	}
}
