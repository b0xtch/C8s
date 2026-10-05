package sessioncli

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/keyservice/keyservicetest"
	"github.com/confidential-dot-ai/c8s/internal/sessiond"
	"github.com/confidential-dot-ai/c8s/internal/sessiond/sessiondtest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/keyservice"
	"github.com/confidential-dot-ai/c8s/pkg/session/sessionsim"
)

// pinFile writes a key service's pin the way 'key-service pin' does.
func pinFile(t *testing.T, pin *session.KeyService) string {
	t.Helper()
	data, err := json.Marshal(pin)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "pin.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// The owner's whole path with a key service, with the commands alone: the
// tenant registers its authority and stores a credential, and a session
// started later finds it in its sandbox, with nobody handing it over.
func TestStoredCredentialReachesASessionStartedThroughADaemon(t *testing.T) {
	host := sessiondtest.NewHostWithKeyService(t, 1, nil)
	pin := pinFile(t, host.KeyService.Pin)
	s := starting(t, host, "sbx-1")
	s.w.credentials, s.w.stored, s.w.keyService = nil, []string{"api-token:64"}, pin
	tenant := &tenantFlags{pin: pin, tenant: "acme", authorityKey: s.authorityKey}
	tenant.timeout, tenant.engineForTest = s.timeout, s.engineForTest

	var stdout, stderr bytes.Buffer
	if code := runTenantRegister(context.Background(), tenant, &stdout, &stderr); code != ExitOK {
		t.Fatalf("tenant register exit %d: %s", code, stderr.String())
	}
	if code := runStoredCredentialPut(context.Background(), tenant, "api-token", []byte("hunter2"), &stdout, &stderr); code != ExitOK {
		t.Fatalf("credential put exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "stored 7 bytes as api-token for tenant acme") {
		t.Fatalf("credential put said %q", stdout.String())
	}

	res := start(t, s)
	if !res.Started {
		t.Fatalf("start result = %+v", res)
	}
	loaded, err := session.LoadBinding(s.out)
	if err != nil {
		t.Fatal(err)
	}
	// The bind names the key service, and the replica of it this command
	// judged before it claimed a guest.
	if named := loaded.Bind.Doc.KeyService; !named.Pin().Equal(host.KeyService.Pin) || !slices.Equal(named.Members, host.KeyService.Members) {
		t.Fatalf("the bind names %+v", named)
	}
	flags := &trust{binding: s.out, manifest: s.manifest, timeout: s.timeout, engineForTest: s.engineForTest}
	stdout.Reset()
	show := session.ExecRequest{Argv: []string{"sh", "-c", `cat "$C8S_CREDENTIALS_DIR/api-token"`}}
	if code := runExec(context.Background(), flags, show, &stdout, &stderr); code != 0 || stdout.String() != "hunter2" {
		t.Fatalf("exec exit %d stdout %q stderr %q", code, stdout.String(), stderr.String())
	}
	// What the key service holds for the session, no access key hands over.
	flags = &trust{binding: s.out, manifest: s.manifest, timeout: s.timeout, engineForTest: s.engineForTest}
	if code := runCredentialPut(context.Background(), flags, "api-token", []byte("another"), &stdout, &stderr); code == ExitOK {
		t.Fatal("an access key replaced a credential that comes from the key service")
	}
}

// A start whose owner pins another key service than the pool's signs nothing,
// and one that asks for a stored credential without a pin is a usage error.
func TestStartHoldsThePoolToTheOwnersKeyService(t *testing.T) {
	host := sessiondtest.NewHostWithKeyService(t, 1, func(c *sessiond.Config) { c.Capacity = 1 })
	other := keyservicetest.New(t, sessionsim.NewPool(t))

	s := starting(t, host, "sbx-1")
	s.w.credentials, s.w.stored, s.w.keyService = nil, []string{"api-token"}, pinFile(t, other.Pin)
	var stdout, stderr bytes.Buffer
	if code := runStart(context.Background(), s, true, &stdout, &stderr); code != ExitRefused {
		t.Fatalf("a start that pins another key service: exit %d: %s", code, stdout.String())
	}
	if _, err := os.Stat(s.out); !os.IsNotExist(err) {
		t.Fatal("the refused start wrote a binding")
	}
	s = starting(t, host, "sbx-1")
	s.w.credentials, s.w.stored = nil, []string{"api-token"}
	stdout.Reset()
	if code := runStart(context.Background(), s, true, &stdout, &stderr); code != ExitUsage || !strings.Contains(stdout.String(), "--key-service") {
		t.Fatalf("a stored credential with no pin: exit %d: %s", code, stdout.String())
	}

	// A tenant the key service does not know: the guest is refused its
	// credential, takes no session and ends.
	s = starting(t, host, "sbx-1")
	s.w.credentials, s.w.stored, s.w.keyService = nil, []string{"api-token"}, pinFile(t, host.KeyService.Pin)
	stdout.Reset()
	if code := runStart(context.Background(), s, true, &stdout, &stderr); code != ExitUnavailable {
		t.Fatalf("a start for a tenant the key service does not know: exit %d: %s", code, stdout.String())
	}
}

// A start that names a key service judges the replica that answers before it
// claims a guest, since its bind names that replica: a key service it cannot
// reach, or one that is not what the pin says, costs the pool no claim.
func TestStartJudgesItsKeyServicesReplicaBeforeItClaims(t *testing.T) {
	host := sessiondtest.NewHostWithKeyService(t, 1, func(c *sessiond.Config) { c.Capacity = 1 })
	// An address nobody serves.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gone := *host.KeyService.Pin
	gone.URL = "https://" + ln.Addr().String()
	_ = ln.Close()
	// The key service that answers, held to another image than it runs.
	other := *host.KeyService.Pin
	flipped := []byte(other.Image.Measurement)
	flipped[0] = map[bool]byte{true: '1', false: '0'}[flipped[0] == '0']
	other.Image.Measurement = string(flipped)

	// record is the daemon's record of the pool's one guest, once it has one.
	record := func() []byte {
		t.Helper()
		records, err := filepath.Glob(filepath.Join(host.Config.StateDir, "tds", "*", "td.json"))
		if err != nil || len(records) > 1 {
			t.Fatalf("the daemon keeps %d records, %v", len(records), err)
		}
		if len(records) == 0 {
			return nil
		}
		// A record is replaced whole: one read is of one version.
		data, err := os.ReadFile(records[0])
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	for deadline := time.Now().Add(20 * time.Second); !bytes.Contains(record(), []byte(`"state":"ready"`)); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the pool's guest never became ready")
		}
	}
	for name, tc := range map[string]struct {
		pin  *session.KeyService
		want int
	}{
		"a key service out of reach":           {&gone, ExitUnavailable},
		"a key service that is not the pinned": {&other, ExitRefused},
	} {
		s := starting(t, host, "sbx-1")
		s.w.credentials, s.w.stored, s.w.keyService = nil, []string{"api-token"}, pinFile(t, tc.pin)
		s.wait = 0
		var stdout, stderr bytes.Buffer
		if code := runStart(context.Background(), s, true, &stdout, &stderr); code != tc.want || !strings.Contains(stdout.String(), "nothing was claimed") {
			t.Fatalf("%s: exit %d: %s", name, code, stdout.String())
		}
		if _, err := os.Stat(s.out); !os.IsNotExist(err) {
			t.Fatalf("%s: the start wrote a binding", name)
		}
		// The pool's one guest was claimed by nobody, not even for a moment:
		// no record of the daemon's holds a claim, or one that was given
		// back.
		if kept := record(); !bytes.Contains(kept, []byte(`"state":"ready"`)) || bytes.Contains(kept, []byte(`"claim"`)) || bytes.Contains(kept, []byte(`"released"`)) {
			t.Fatalf("%s: the pool's guest was claimed: %s", name, kept)
		}
	}
}

// A bind sent to a guest by its address names the key service's replica its
// sender judged, as a start through a daemon does, and the guest takes its
// stored credential from that replica.
func TestDirectBindNamesTheKeyServicesReplica(t *testing.T) {
	pool := sessionsim.NewPool(t)
	ks := keyservicetest.New(t, pool)
	guest := pool.Boot(t, nil, ks.Pin)
	b := unbound(t, guest)
	pin := pinFile(t, ks.Pin)
	b.w.credentials, b.w.stored, b.w.keyService = nil, []string{"api-token:64"}, pin
	tenant := &tenantFlags{pin: pin, tenant: "acme", authorityKey: b.authorityKey}
	tenant.timeout, tenant.engineForTest = b.timeout, b.engineForTest
	var stdout, stderr bytes.Buffer
	if code := runTenantRegister(context.Background(), tenant, &stdout, &stderr); code != ExitOK {
		t.Fatalf("tenant register exit %d: %s", code, stderr.String())
	}
	if code := runStoredCredentialPut(context.Background(), tenant, "api-token", []byte("hunter2"), &stdout, &stderr); code != ExitOK {
		t.Fatalf("credential put exit %d: %s", code, stderr.String())
	}
	bind(t, b)
	loaded, err := session.LoadBinding(b.out)
	if err != nil {
		t.Fatal(err)
	}
	if named := loaded.Bind.Doc.KeyService; !named.Pin().Equal(ks.Pin) || !slices.Equal(named.Members, ks.Members) {
		t.Fatalf("the bind names %+v", named)
	}
	stdout.Reset()
	show := session.ExecRequest{Argv: []string{"sh", "-c", `cat "$C8S_CREDENTIALS_DIR/api-token"`}}
	if code := runExec(context.Background(), driving(b), show, &stdout, &stderr); code != 0 || stdout.String() != "hunter2" {
		t.Fatalf("exec exit %d stdout %q stderr %q", code, stdout.String(), stderr.String())
	}
}

// An owner's tool holds the key service to its pin before it sends anything.
func TestTenantCommandsRefuseAKeyServiceTheyDidNotPin(t *testing.T) {
	host := sessiondtest.NewHostWithKeyService(t, 0, nil)
	other := keyservicetest.New(t, sessionsim.NewPool(t))
	wrong := *host.KeyService.Pin
	wrong.Image = other.Pin.Image
	s := starting(t, host, "sbx-1")
	tenant := &tenantFlags{pin: pinFile(t, &wrong), tenant: "acme", authorityKey: s.authorityKey}
	tenant.timeout, tenant.engineForTest = s.timeout, s.engineForTest
	var stdout, stderr bytes.Buffer
	if code := runTenantRegister(context.Background(), tenant, &stdout, &stderr); code != ExitRefused {
		t.Fatalf("register at a key service of another image: exit %d: %s", code, stderr.String())
	}
	if code := runStoredCredentialPut(context.Background(), tenant, "api-token", []byte("hunter2"), &stdout, &stderr); code != ExitRefused {
		t.Fatalf("store at a key service of another image: exit %d: %s", code, stderr.String())
	}
	// At the right one, a credential needs its tenant registered first.
	tenant.pin = pinFile(t, host.KeyService.Pin)
	if code := runStoredCredentialPut(context.Background(), tenant, "api-token", []byte("hunter2"), &stdout, &stderr); code != ExitUnavailable {
		t.Fatalf("store for a tenant nobody registered: exit %d: %s", code, stderr.String())
	}
	for name, run := range map[string]func() int{
		"a name in capitals": func() int {
			return runStoredCredentialPut(context.Background(), tenant, "API", []byte("x"), &stdout, &stderr)
		},
		"an empty value": func() int {
			return runStoredCredentialPut(context.Background(), tenant, "api-token", nil, &stdout, &stderr)
		},
		"a pin that is no file": func() int {
			return runTenantRegister(context.Background(), &tenantFlags{pin: "/nonexistent", tenant: "acme", authorityKey: s.authorityKey}, &stdout, &stderr)
		},
	} {
		if code := run(); code != ExitUsage {
			t.Errorf("%s: exit %d", name, code)
		}
	}
}

// The operator's side: a pool's key comes first, the key service's bundle
// lists it, and the pool's launch document pins the key service.
func TestKeyServiceBundlePinAndPool(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) (string, error) {
		cmd := NewCmd()
		var stdout bytes.Buffer
		cmd.SetOut(&stdout)
		cmd.SetErr(&stdout)
		cmd.SetArgs(args)
		err := cmd.Execute()
		return stdout.String(), err
	}
	pool, service := sessionsim.NewPool(t), sessionsim.NewPool(t)
	key := filepath.Join(dir, "pool.key")
	if out, err := run("launch-config", "key", "--out", key); err != nil {
		t.Fatalf("launch-config key: %v: %s", err, out)
	}
	if _, err := run("launch-config", "key", "--out", key); err == nil {
		t.Fatal("a second run replaced a launch key")
	}
	bundle := filepath.Join(dir, "key-service")
	if out, err := run("key-service", "launch-config", "new", "--out", bundle, "--image-manifest", service.ManifestPath,
		"--pool", pool.ManifestPath+":"+key+".pub"); err != nil {
		t.Fatalf("key-service launch-config new: %v: %s", err, out)
	}
	pin := filepath.Join(dir, "pin.json")
	if out, err := run("key-service", "pin", "--bundle", bundle, "--url", "https://192.0.2.7:8443", "--out", pin); err != nil {
		t.Fatalf("key-service pin: %v: %s", err, out)
	}
	loaded, err := session.LoadKeyServicePin(pin)
	if err != nil {
		t.Fatal(err)
	}
	want, err := keyservice.Pin(bundle, "https://192.0.2.7:8443")
	if err != nil || !loaded.Equal(want) {
		t.Fatalf("the pin file reads %+v, %v", loaded, err)
	}
	out := filepath.Join(dir, "pool")
	if said, err := run("launch-config", "new", "--out", out, "--image-manifest", pool.ManifestPath, "--pool", "agents", "--class", "s-4x16",
		"--key", key, "--key-service", pin); err != nil {
		t.Fatalf("launch-config new: %v: %s", err, said)
	}
	poolBundle, err := session.LoadBundle(out)
	if err != nil {
		t.Fatal(err)
	}
	if !poolBundle.Document.KeyService.Equal(want) {
		t.Fatalf("the pool's document pins %+v", poolBundle.Document.KeyService)
	}
	// The key service's document lists the pool by the key its bundle is
	// signed with.
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(bundle, session.OpkeyDir, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	doc, err := keyservice.VerifySigned(read(session.PubkeyFile), read(session.DocumentFile), string(read(session.SignatureFile)))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Pools) != 1 || doc.Pools[0].LaunchKey != string(poolBundle.LaunchKey) || doc.Pools[0].Image.Measurement != poolBundle.Document.Image.Measurement {
		t.Fatalf("the key service's document lists %+v", doc.Pools)
	}

	// Each document names the TCB statuses its author accepts besides
	// UpToDate, in one order however the flags came, and the pool's document
	// carries its key service's pin with them.
	lenient := filepath.Join(dir, "key-service-lenient")
	if out, err := run("key-service", "launch-config", "new", "--out", lenient, "--image-manifest", service.ManifestPath,
		"--pool", pool.ManifestPath+":"+key+".pub", "--accept-tcb-status", "SWHardeningNeeded", "--accept-tcb-status", "OutOfDate,OutOfDate"); err != nil {
		t.Fatalf("key-service launch-config new --accept-tcb-status: %v: %s", err, out)
	}
	lenientDoc, err := os.ReadFile(filepath.Join(lenient, session.OpkeyDir, session.DocumentFile))
	if err != nil {
		t.Fatal(err)
	}
	accepted := []string{"OutOfDate", "SWHardeningNeeded"}
	if parsed, err := keyservice.Parse(lenientDoc); err != nil || !slices.Equal(parsed.Pools[0].AcceptTCBStatus, accepted) {
		t.Fatalf("the key service's document accepts %+v, %v", parsed, err)
	}
	lenientPin := filepath.Join(dir, "pin-lenient.json")
	if out, err := run("key-service", "pin", "--bundle", lenient, "--url", "https://192.0.2.7:8443", "--out", lenientPin,
		"--accept-tcb-status", "SWHardeningNeeded,OutOfDate"); err != nil {
		t.Fatalf("key-service pin --accept-tcb-status: %v: %s", err, out)
	}
	loadedLenient, err := session.LoadKeyServicePin(lenientPin)
	if err != nil || !slices.Equal(loadedLenient.AcceptTCBStatus, accepted) {
		t.Fatalf("the pin accepts %+v, %v", loadedLenient, err)
	}
	lenientPool := filepath.Join(dir, "pool-lenient")
	if said, err := run("launch-config", "new", "--out", lenientPool, "--image-manifest", pool.ManifestPath, "--pool", "agents", "--class", "s-4x16",
		"--key", key, "--key-service", lenientPin); err != nil {
		t.Fatalf("launch-config new: %v: %s", err, said)
	}
	if b, err := session.LoadBundle(lenientPool); err != nil || !slices.Equal(b.Document.KeyService.AcceptTCBStatus, accepted) {
		t.Fatalf("the pool's document pins %+v, %v", b, err)
	}

	for name, args := range map[string][]string{
		"a key service that accepts Revoked of its pools": {"key-service", "launch-config", "new", "--out", filepath.Join(dir, "e"), "--image-manifest", service.ManifestPath, "--pool", pool.ManifestPath + ":" + key + ".pub", "--accept-tcb-status", "Revoked"},
		"a pin that accepts a status nobody has":          {"key-service", "pin", "--bundle", bundle, "--url", "https://192.0.2.7:8443", "--out", filepath.Join(dir, "f.json"), "--accept-tcb-status", "Fine"},
		"a pool with no launch key":                       {"key-service", "launch-config", "new", "--out", filepath.Join(dir, "a"), "--image-manifest", service.ManifestPath, "--pool", pool.ManifestPath},
		"a pool whose key is no key":                      {"key-service", "launch-config", "new", "--out", filepath.Join(dir, "b"), "--image-manifest", service.ManifestPath, "--pool", pool.ManifestPath + ":" + pin},
		"a pin with a URL that is none":                   {"key-service", "pin", "--bundle", bundle, "--url", "http://192.0.2.7", "--out", filepath.Join(dir, "c.json")},
		"a pool that pins a pin that is no file":          {"launch-config", "new", "--out", filepath.Join(dir, "d"), "--image-manifest", pool.ManifestPath, "--pool", "agents", "--class", "s-4x16", "--key-service", "/nonexistent"},
	} {
		if _, err := run(args...); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	for _, left := range []string{"a", "b", "c.json", "d"} {
		if _, err := os.Stat(filepath.Join(dir, left)); !os.IsNotExist(err) {
			t.Errorf("a refused command left %s behind", left)
		}
	}
}

// An operator reads a key service's machine from a replica booted under a
// bundle that lists none, and writes the bundle again with it.
func TestMachineOfAKeyService(t *testing.T) {
	pool := sessionsim.NewPool(t)
	ks := keyservicetest.NewWith(t, keyservicetest.Options{Unpinned: true}, pool)
	flags := func() *trust { return &trust{timeout: 30 * time.Second, engineForTest: &counting{}} }
	var stdout, stderr bytes.Buffer
	if code := runKeyServiceMachine(context.Background(), flags(), ks.Bundle, ks.Pin.URL, &stdout, &stderr); code != ExitOK {
		t.Fatalf("key-service launch-config machine exit %d: %s", code, stderr.String())
	}
	machine := strings.TrimSpace(stdout.String())
	if machine != hex.EncodeToString(ks.Machine[:]) {
		t.Fatalf("printed %q, the replica's RTMR[0] is %x", machine, ks.Machine)
	}
	// The replica it was read from is sent nothing by an owner's tool.
	owner := starting(t, sessiondtest.NewHostWithKeyService(t, 0, nil), "sbx-1")
	tenant := &tenantFlags{pin: pinFile(t, ks.Pin), tenant: "acme", authorityKey: owner.authorityKey}
	tenant.timeout, tenant.engineForTest = owner.timeout, owner.engineForTest
	stderr.Reset()
	if code := runTenantRegister(context.Background(), tenant, io.Discard, &stderr); code != ExitRefused || !strings.Contains(stderr.String(), "lists no machine") {
		t.Fatalf("register at a key service whose document lists no machine: exit %d: %s", code, stderr.String())
	}

	// The value is what 'key-service launch-config new --machine' takes, and
	// the document then lists it.
	out := filepath.Join(t.TempDir(), "bundle")
	cmd := newKeyServiceBundleCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--out", out, "--image-manifest", pool.ManifestPath, "--pool", pool.ManifestPath + ":" + pool.LaunchKeyPath, "--machine", machine})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("key-service launch-config new --machine: %v", err)
	}
	launch, err := os.ReadFile(filepath.Join(out, session.OpkeyDir, session.DocumentFile))
	if err != nil {
		t.Fatal(err)
	}
	if doc, err := keyservice.Parse(launch); err != nil || doc.Machine == nil || len(doc.Machine.RTMR0) != 1 || doc.Machine.RTMR0[0] != machine {
		t.Fatalf("the document lists %+v, %v", doc, err)
	}

	// A replica that lists its machine prints the same way. One that is not
	// the bundle's is not read, and a bundle that is none is a usage error.
	pinned := keyservicetest.New(t, pool)
	stdout.Reset()
	if code := runKeyServiceMachine(context.Background(), flags(), pinned.Bundle, pinned.Pin.URL, &stdout, &stderr); code != ExitOK ||
		strings.TrimSpace(stdout.String()) != hex.EncodeToString(pinned.Machine[:]) {
		t.Fatalf("the machine of a pinned replica: exit %d, printed %q", code, stdout.String())
	}
	stdout.Reset()
	if code := runKeyServiceMachine(context.Background(), flags(), pinned.Bundle, ks.Pin.URL, &stdout, &stderr); code != ExitRefused || stdout.Len() != 0 {
		t.Fatalf("a replica of another bundle: exit %d, printed %q", code, stdout.String())
	}
	if code := runKeyServiceMachine(context.Background(), flags(), filepath.Join(t.TempDir(), "absent"), ks.Pin.URL, &stdout, &stderr); code != ExitUsage {
		t.Fatalf("a bundle that is no directory: exit %d", code)
	}
}
