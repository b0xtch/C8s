package sessionsim_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/sessioncli"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/sessionsim"
)

// released builds the command-line client the way it is built for users.
func released(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/confidential-dot-ai/c8s").Output()
	if err != nil {
		t.Fatalf("find the module: %v", err)
	}
	bin := filepath.Join(t.TempDir(), "c8s")
	build := exec.Command("go", "build", "-o", bin, "./cmd/c8s")
	build.Dir = strings.TrimSpace(string(out))
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build c8s: %v\n%s", err, out)
	}
	return bin
}

// A simulated guest is for tests. Its evidence is no hardware's, and the
// engine that accepts it is chosen in code, by a test: no flag, variable or
// file of a released binary selects it. So the client as users get it finds
// such a guest unverifiable and sends it nothing.
func TestReleasedClientRefusesASimulatedGuest(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the c8s binary")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("builds the c8s binary, and there is no go command here")
	}
	bin := released(t)
	guest := sessionsim.NewGuest(t, nil)
	_, authority, authorityPub := newKey(t)
	key := filepath.Join(t.TempDir(), "authority.key")
	if err := os.WriteFile(key, authority, 0o600); err != nil {
		t.Fatal(err)
	}
	binding := filepath.Join(t.TempDir(), "binding")
	cmd := exec.Command(bin, "session", "bind", "--url", guest.URL,
		"--image-manifest", guest.ManifestPath, "--launch-key", guest.LaunchKeyPath, "--authority-key", key,
		"--tenant", "acme", "--session", "sbx-1", "--out", binding,
		"--collateral-cache", t.TempDir(), "--timeout", "30s", "-o", "json")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != sessioncli.ExitRefused {
		t.Fatalf("exit: %v\n%s%s", err, stdout.String(), stderr.String())
	}
	var result struct {
		Bound bool   `json:"bound"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.Bound || result.Error == "" {
		t.Fatalf("result %s: %v", stdout.String(), err)
	}
	// Refused at the first handshake: no bind was signed, let alone sent.
	if _, err := os.Stat(binding); !os.IsNotExist(err) {
		t.Fatalf("a refused guest left a binding directory: %v", err)
	}
	// The same guest, the same inputs, and the test's engine: it binds. What
	// the released client refuses is the evidence, and nothing else here.
	identity, err := runtimemeasure.LoadImageManifest(guest.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	launchKey, err := os.ReadFile(guest.LaunchKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(authority)
	if err != nil {
		t.Fatal(err)
	}
	policy := session.Policy{Image: identity, LaunchKey: launchKey, Authority: []byte(authorityPub), AllowReady: true}
	unbound, err := session.NewClient(guest.URL, policy, sessionsim.Engine(), signer)
	if err != nil {
		t.Fatal(err)
	}
	defer unbound.Close()
	if _, err := unbound.Ready(t.Context()); err != nil {
		t.Fatalf("the simulated guest under the test's engine: %v", err)
	}
}
