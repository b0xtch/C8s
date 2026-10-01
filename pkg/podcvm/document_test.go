package podcvm_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/podcvmtest"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/podcvm"
)

const workloadImage = "ghcr.io/acme/agent@sha256:1111111111111111111111111111111111111111111111111111111111111111"

func newBundle(t *testing.T, td *podcvmtest.TD, mutate func(*podcvm.BundleOptions)) (string, *podcvm.Bundle) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bundle")
	opts := podcvm.BundleOptions{
		Dir:          dir,
		ManifestPath: td.WriteManifest(t),
		Tenant:       "acme.user-42",
		Sandbox:      "sbx-1",
		Credentials:  []podcvm.Credential{{Name: "test-token"}},
	}
	if mutate != nil {
		mutate(&opts)
	}
	if err := podcvm.NewBundle(opts); err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	bundle, err := podcvm.LoadBundle(dir)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	return dir, bundle
}

func TestBundleRoundTrip(t *testing.T) {
	td := podcvmtest.NewTD()
	dir, bundle := newBundle(t, td, func(o *podcvm.BundleOptions) {
		o.Workload = &podcvm.Workload{Image: workloadImage, Command: []string{"/bin/agent"}, Env: map[string]string{"MODE": "serve"}}
	})
	doc := bundle.Document
	if doc.Tenant != "acme.user-42" || doc.Sandbox != "sbx-1" || doc.Image.Platform != "tdx" || len(doc.Image.RTMRs) != 2 {
		t.Fatalf("unexpected document: %+v", doc)
	}
	if len(doc.ExecKeys()) != 1 || len(doc.CredentialKeys()) != 1 || len(doc.AttestKeys()) != 1 {
		t.Fatalf("launch key must hold exec and credential access exactly once: %+v", doc.Access)
	}
	key, err := certutil.LoadECPrivateKeyFile(filepath.Join(dir, podcvm.BundleKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if !doc.ExecKeys()[0].Equal(&key.PublicKey) {
		t.Fatal("exec access is not the generated launch key")
	}
	info, err := os.Stat(filepath.Join(dir, podcvm.BundleKeyFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("launch key mode = %v, %v", info.Mode(), err)
	}
	if digest, err := doc.Workload.Digest(); err != nil || digest != "sha256:"+strings.Repeat("1", 64) {
		t.Fatalf("workload digest = %q, %v", digest, err)
	}
}

func TestNewBundleRefusesExistingDir(t *testing.T) {
	td := podcvmtest.NewTD()
	dir := t.TempDir()
	err := podcvm.NewBundle(podcvm.BundleOptions{Dir: dir, ManifestPath: td.WriteManifest(t), Tenant: "t", Sandbox: "s"})
	if err == nil {
		t.Fatal("NewBundle reused an existing directory")
	}
	if _, statErr := os.Stat(dir); statErr != nil {
		t.Fatalf("a refused bundle must not remove a directory it did not create: %v", statErr)
	}
}

func TestVerifySignedRejects(t *testing.T) {
	td := podcvmtest.NewTD()
	_, bundle := newBundle(t, td, nil)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, err := podcvm.PublicKeyPEM(&other.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	otherSig, err := operatorauth.SignDetached(other, bundle.Launch)
	if err != nil {
		t.Fatal(err)
	}
	flipped := append([]byte(nil), bundle.Launch...)
	flipped[len(flipped)/2] ^= 1

	for name, tc := range map[string]struct {
		pub  []byte
		data []byte
		sig  string
	}{
		"wrong key":           {otherPub, bundle.Launch, bundle.Signature},
		"foreign signature":   {bundle.LaunchKey, bundle.Launch, otherSig},
		"modified document":   {bundle.LaunchKey, flipped, bundle.Signature},
		"appended document":   {bundle.LaunchKey, append(append([]byte(nil), bundle.Launch...), "tenant: evil\n"...), bundle.Signature},
		"empty signature":     {bundle.LaunchKey, bundle.Launch, ""},
		"empty document":      {bundle.LaunchKey, nil, bundle.Signature},
		"unparseable pubkey":  {[]byte("not a key"), bundle.Launch, bundle.Signature},
		"two keys in the PEM": {append(append([]byte(nil), bundle.LaunchKey...), bundle.LaunchKey...), bundle.Launch, bundle.Signature},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := podcvm.VerifySigned(tc.pub, tc.data, tc.sig); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := podcvm.VerifySigned(bundle.LaunchKey, bundle.Launch, bundle.Signature); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func TestParseRejects(t *testing.T) {
	td := podcvmtest.NewTD()
	_, bundle := newBundle(t, td, func(o *podcvm.BundleOptions) {
		o.Workload = &podcvm.Workload{Image: workloadImage}
	})
	valid := string(bundle.Launch)
	replace := func(old, new string) string {
		t.Helper()
		if !strings.Contains(valid, old) {
			t.Fatalf("fixture lacks %q:\n%s", old, valid)
		}
		return strings.Replace(valid, old, new, 1)
	}
	for name, doc := range map[string]string{
		"unknown field":         valid + "extra: 1\n",
		"duplicate key":         valid + "tenant: other\n",
		"second document":       valid + "---\ntenant: other\n",
		"wrong schema":          replace("c8s-pod-launch/v1", "c8s-launch/v1"),
		"tenant not a name":     replace("tenant: acme.user-42", "tenant: Acme_User"),
		"sandbox not a label":   replace("sandbox: sbx-1", "sandbox: sbx.1"),
		"tag-pinned image":      replace(workloadImage, "ghcr.io/acme/agent:latest"),
		"bare digest image":     replace(workloadImage, "sha256:"+strings.Repeat("1", 64)),
		"uppercase measurement": replace("measurement: ", "measurement: A"),
		"rtmr 3 pinned":         replace("    1: ", "    3: "),
		"noncanonical rtmr key": replace("    1: ", "    01: "),
		"anchor":                replace("tenant: acme.user-42", "tenant: &t acme.user-42"),
		"credential name":       replace("name: test-token", "name: Test/Token"),
		"oversized":             valid + "#" + strings.Repeat("x", podcvm.MaxDocumentSize),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := podcvm.Parse([]byte(doc)); err == nil {
				t.Fatalf("accepted:\n%s", doc)
			}
		})
	}
	if _, err := podcvm.Parse([]byte(valid)); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func TestValidateAccessAndCredentials(t *testing.T) {
	td := podcvmtest.NewTD()
	_, bundle := newBundle(t, td, nil)
	base := *bundle.Document
	key := base.Access.Exec[0]

	for name, mutate := range map[string]func(*podcvm.Document){
		"credentials with no releasing key": func(d *podcvm.Document) { d.Access.Credentials = nil },
		"duplicate access key":              func(d *podcvm.Document) { d.Access.Exec = []string{key, key} },
		"duplicate credential":              func(d *podcvm.Document) { d.Credentials = append(d.Credentials, d.Credentials[0]) },
		"credential over the cap":           func(d *podcvm.Document) { d.Credentials[0].MaxBytes = podcvm.MaxCredentialBytes + 1 },
		"negative credential size":          func(d *podcvm.Document) { d.Credentials[0].MaxBytes = -1 },
		"bad id":                            func(d *podcvm.Document) { d.ID = "not-hex" },
		"env name": func(d *podcvm.Document) {
			d.Workload = &podcvm.Workload{Image: workloadImage, Env: map[string]string{"A-B": "x"}}
		},
		"relative working dir": func(d *podcvm.Document) { d.Workload = &podcvm.Workload{Image: workloadImage, WorkingDir: "work"} },
		"unclean working dir":  func(d *podcvm.Document) { d.Workload = &podcvm.Workload{Image: workloadImage, WorkingDir: "/a/../b"} },
		"NUL in args": func(d *podcvm.Document) {
			d.Workload = &podcvm.Workload{Image: workloadImage, Args: []string{"a\x00b"}}
		},
		"empty command": func(d *podcvm.Document) { d.Workload = &podcvm.Workload{Image: workloadImage, Command: []string{""}} },
	} {
		t.Run(name, func(t *testing.T) {
			doc := base
			doc.Credentials = append([]podcvm.Credential(nil), base.Credentials...)
			mutate(&doc)
			if err := doc.Validate(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("control: %v", err)
	}
	if c, ok := base.Credential("test-token"); !ok || c.Limit() != 64*1024 {
		t.Fatalf("default credential limit = %d, %v", c.Limit(), ok)
	}
}

func TestExecRequestValidate(t *testing.T) {
	id := strings.Repeat("a", 32)
	for name, req := range map[string]podcvm.ExecRequest{
		"no id":         {Argv: []string{"true"}},
		"short id":      {ID: "abc", Argv: []string{"true"}},
		"no argv":       {ID: id},
		"empty command": {ID: id, Argv: []string{""}},
		"NUL":           {ID: id, Argv: []string{"a\x00"}},
		"timeout":       {ID: id, Argv: []string{"true"}, TimeoutSeconds: podcvm.MaxExecTimeout + 1},
		"stdin":         {ID: id, Argv: []string{"true"}, Stdin: make([]byte, podcvm.MaxExecStdin+1)},
		"env name":      {ID: id, Argv: []string{"true"}, Env: map[string]string{"1X": "y"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := req.Validate(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	ok := podcvm.ExecRequest{ID: id, Argv: []string{"sh", "-c", "true"}, Env: map[string]string{"A": "b"}, TimeoutSeconds: 5}
	if err := ok.Validate(); err != nil {
		t.Fatalf("control: %v", err)
	}
}
