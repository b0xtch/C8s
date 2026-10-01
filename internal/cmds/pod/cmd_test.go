package pod

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podagent"
	"github.com/confidential-dot-ai/c8s/internal/podcvmtest"
	"github.com/confidential-dot-ai/c8s/pkg/podcvm"
)

// guest boots a simulated pod CVM and returns the flags that address it.
func guest(t *testing.T) (*trust, *podcvmtest.TD, string) {
	t.Helper()
	td := podcvmtest.NewTD()
	manifest := td.WriteManifest(t)
	bundle := filepath.Join(t.TempDir(), "bundle")
	err := podcvm.NewBundle(podcvm.BundleOptions{
		Dir: bundle, ManifestPath: manifest, Tenant: "acme", Sandbox: "sbx-1",
		Credentials: []podcvm.Credential{{Name: "test-token"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := podcvm.LoadBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	td.SeedLaunchKey(loaded.LaunchKey)
	credDir := filepath.Join(t.TempDir(), "credentials")
	runner, err := podagent.NewProcessRunner(podagent.RunnerConfig{UID: -1, GID: -1, Home: t.TempDir(), CredentialDir: credDir})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := podagent.Stage(context.Background(), podagent.Config{
		Platform: "tdx", PubkeyPath: filepath.Join(bundle, podcvm.OpkeyDir, podcvm.PubkeyFile),
		LaunchDir: filepath.Join(bundle, podcvm.OpkeyDir), CredentialDir: credDir,
		TEE: podcvmtest.TEE{TD: td}, Runner: runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Admit(context.Background()); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := agent.Server()
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return &trust{
		url: "https://" + ln.Addr().String(), bundle: bundle, manifest: manifest,
		collateral: string(podcvm.CollateralSkip), timeout: 30 * time.Second, engineForTest: podcvmtest.Engine{},
	}, td, credDir
}

func TestVerifyExitCodesAndJSON(t *testing.T) {
	flags, td, _ := guest(t)
	var stdout, stderr bytes.Buffer
	if code := runVerify(context.Background(), flags, true, &stdout, &stderr); code != ExitOK {
		t.Fatalf("exit %d: %s%s", code, stdout.String(), stderr.String())
	}
	var v verdict
	if err := json.Unmarshal(stdout.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if !v.Verified || v.Tenant != "acme" || v.Sandbox != "sbx-1" || v.Phase != "running" || len(v.Events) != 1 || v.InstanceKeySHA256 == "" {
		t.Fatalf("verdict = %+v", v)
	}
	// The simulated engine checks no collateral, and the verdict must say so.
	if v.CollateralVerified || len(v.NotProven) != 1 {
		t.Fatalf("a verdict without collateral must name the gap: %+v", v)
	}

	// The same guest against a manifest for another build: refused, exit 2.
	other := *flags
	other.manifest = podcvmtest.NewTD().WriteManifest(t)
	stdout.Reset()
	if code := runVerify(context.Background(), &other, true, &stdout, &stderr); code != ExitRefused {
		t.Fatalf("wrong image: exit %d: %s", code, stdout.String())
	}
	if err := json.Unmarshal(stdout.Bytes(), &v); err != nil || v.Verified || v.Error == "" {
		t.Fatalf("refusal verdict = %+v, %v", v, err)
	}

	// Nothing listening: no verdict, exit 3.
	gone := *flags
	gone.url = "https://127.0.0.1:1"
	if code := runVerify(context.Background(), &gone, false, &stdout, &stderr); code != ExitUnavailable {
		t.Fatalf("unreachable guest: exit %d", code)
	}

	// Unusable local inputs: exit 1, before anything is sent.
	bad := *flags
	bad.bundle = filepath.Join(t.TempDir(), "absent")
	if code := runVerify(context.Background(), &bad, false, &stdout, &stderr); code != ExitUsage {
		t.Fatalf("missing bundle: exit %d", code)
	}
	_ = td
}

func TestCredentialPutThenExec(t *testing.T) {
	flags, _, credDir := guest(t)
	var stdout, stderr bytes.Buffer
	if code := runCredentialPut(context.Background(), flags, "test-token", []byte("hunter2"), &stdout, &stderr); code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "hunter2") {
		t.Fatal("the credential value was echoed")
	}
	if got, err := os.ReadFile(filepath.Join(credDir, "test-token")); err != nil || string(got) != "hunter2" {
		t.Fatalf("credential in guest = %q, %v", got, err)
	}

	stdout.Reset()
	stderr.Reset()
	req := podcvm.ExecRequest{Argv: []string{"sh", "-c", `cat "$C8S_CREDENTIALS_DIR/test-token"; echo warn >&2; exit 7`}}
	if code := runExec(context.Background(), flags, req, &stdout, &stderr); code != 7 {
		t.Fatalf("exec exit %d, want the command's own 7: %s", code, stderr.String())
	}
	if stdout.String() != "hunter2" || stderr.String() != "warn\n" {
		t.Fatalf("stdout %q stderr %q", stdout.String(), stderr.String())
	}
}

func TestExecAndCredentialRefuseAWrongGuest(t *testing.T) {
	flags, _, credDir := guest(t)
	flags.manifest = podcvmtest.NewTD().WriteManifest(t)
	var stdout, stderr bytes.Buffer
	if code := runCredentialPut(context.Background(), flags, "test-token", []byte("hunter2"), &stdout, &stderr); code != ExitRefused {
		t.Fatalf("credential put exit %d", code)
	}
	if code := runExec(context.Background(), flags, podcvm.ExecRequest{Argv: []string{"true"}}, &stdout, &stderr); code != ExitExecRefused {
		t.Fatalf("exec exit %d", code)
	}
	if entries, _ := os.ReadDir(credDir); len(entries) != 0 {
		t.Fatalf("a credential reached a guest that failed verification: %v", entries)
	}
}

func TestTrustFlagsUsageErrors(t *testing.T) {
	flags, _, _ := guest(t)
	pub := filepath.Join(flags.bundle, podcvm.OpkeyDir, podcvm.PubkeyFile)
	for name, mutate := range map[string]func(*trust){
		"bundle and launch key together": func(f *trust) { f.launchKey = pub },
		"neither bundle nor launch key":  func(f *trust) { f.bundle = "" },
		"launch key without tenant": func(f *trust) {
			f.bundle, f.launchKey, f.key = "", pub, filepath.Join(flags.bundle, podcvm.BundleKeyFile)
		},
		"launch key without signing key": func(f *trust) { f.bundle, f.launchKey, f.tenant, f.sandbox = "", pub, "acme", "sbx-1" },
		"plain http":                     func(f *trust) { f.url = strings.Replace(f.url, "https://", "http://", 1) },
		"url with a path":                func(f *trust) { f.url += "/v1" },
		"unknown collateral mode":        func(f *trust) { f.engineForTest, f.collateral = nil, "lenient" },
		"manifest is not an image pin":   func(f *trust) { f.manifest = pub },
	} {
		t.Run(name, func(t *testing.T) {
			f := *flags
			mutate(&f)
			if _, err := f.client(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// A policy may pin tenant and sandbox and leave the document open.
	f := *flags
	f.bundle, f.launchKey, f.tenant, f.sandbox, f.key = "", pub, "acme", "sbx-1", filepath.Join(flags.bundle, podcvm.BundleKeyFile)
	var stdout, stderr bytes.Buffer
	if code := runVerify(context.Background(), &f, false, &stdout, &stderr); code != ExitOK {
		t.Fatalf("tenant-pinned verify: exit %d: %s", code, stderr.String())
	}
}
