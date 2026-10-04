package keyservice_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/keyservice"
	"github.com/confidential-dot-ai/c8s/pkg/session/sessionsim"
)

// bundle writes a key service's launch bundle for one pool and returns its
// directory with the three files a guest boots from.
func bundle(t *testing.T) (dir string, pub, launch []byte, signature string) {
	t.Helper()
	pool, service := sessionsim.NewPool(t), sessionsim.NewPool(t)
	dir = filepath.Join(t.TempDir(), "key-service")
	err := keyservice.NewBundle(keyservice.BundleOptions{
		Dir: dir, ManifestPath: service.ManifestPath,
		Pools: []keyservice.PoolOptions{{ManifestPath: pool.ManifestPath, LaunchKeyPath: pool.LaunchKeyPath}},
	})
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(dir, session.OpkeyDir, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	return dir, read(session.PubkeyFile), read(session.DocumentFile), string(read(session.SignatureFile))
}

func TestLaunchDocument(t *testing.T) {
	dir, pub, launch, signature := bundle(t)
	doc, err := keyservice.VerifySigned(pub, launch, signature)
	if err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != keyservice.LaunchSchemaVersion || len(doc.Pools) != 1 || doc.Image.Platform != "tdx" {
		t.Fatalf("the document: %+v", doc)
	}
	if info, err := os.Stat(filepath.Join(dir, session.BundleKeyFile)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the launch key: %v, %v", info, err)
	}
	pin, err := keyservice.Pin(dir, "https://192.0.2.7:8443")
	if err != nil || pin.Validate() != nil || pin.LaunchKey != string(pub) || pin.Image.Measurement != doc.Image.Measurement {
		t.Fatalf("the pin: %+v, %v", pin, err)
	}

	// Another key did not sign it, and the signature fits no other bytes.
	_, otherPub, otherLaunch, _ := bundle(t)
	if _, err := keyservice.VerifySigned(otherPub, launch, signature); err == nil {
		t.Error("a document verified under another launch key")
	}
	if _, err := keyservice.VerifySigned(pub, otherLaunch, signature); err == nil {
		t.Error("a signature verified over another document")
	}

	text := string(launch)
	for name, changed := range map[string]string{
		"an unknown field":            text + "operators: []\n",
		"another schema version":      strings.Replace(text, keyservice.LaunchSchemaVersion, "c8s-key-service-launch/v2", 1),
		"a session's schema version":  strings.Replace(text, keyservice.LaunchSchemaVersion, session.LaunchSchemaVersion, 1),
		"no pool":                     text[:strings.Index(text, "pools:")] + "pools: []\n",
		"a pool for another platform": strings.Replace(text, "    - image:\n        platform: tdx", "    - image:\n        platform: snp", 1),
		"a second spelling":           strings.Replace(text, "schemaVersion: ", "schemaVersion:  ", 1),
		"two documents":               text + "---\n" + text,
		"nothing":                     "",
	} {
		if changed == text {
			t.Fatalf("%s: the change did not apply", name)
		}
		if _, err := keyservice.Parse([]byte(changed)); err == nil {
			t.Errorf("a document with %s was accepted", name)
		}
	}
	// A session pool's launch document is no key service's, and the reverse.
	if _, err := session.Parse(launch); err == nil {
		t.Error("a key service's document parsed as a session pool's")
	}
}

// A pool's entry may name the TCB statuses the key service accepts of that
// pool's guests, and whoever verifies the document reads them in it.
func TestLaunchDocumentNamesAcceptedTCBStatuses(t *testing.T) {
	pool, service := sessionsim.NewPool(t), sessionsim.NewPool(t)
	dir := filepath.Join(t.TempDir(), "key-service")
	accepted := []string{"OutOfDate", "SWHardeningNeeded"}
	if err := keyservice.NewBundle(keyservice.BundleOptions{
		Dir: dir, ManifestPath: service.ManifestPath,
		Pools: []keyservice.PoolOptions{{ManifestPath: pool.ManifestPath, LaunchKeyPath: pool.LaunchKeyPath, AcceptTCBStatus: accepted}},
	}); err != nil {
		t.Fatal(err)
	}
	launch, err := os.ReadFile(filepath.Join(dir, session.OpkeyDir, session.DocumentFile))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := keyservice.Parse(launch)
	if err != nil || !slices.Equal(doc.Pools[0].AcceptTCBStatus, accepted) {
		t.Fatalf("the document's pool accepts %v, %v", doc.Pools, err)
	}
	if !strings.Contains(string(launch), "acceptTCBStatus:") {
		t.Fatalf("the document does not say what it accepts:\n%s", launch)
	}
	// A document that names none says nothing of it.
	_, _, plain, _ := bundle(t)
	if strings.Contains(string(plain), "acceptTCBStatus") {
		t.Fatalf("a document that accepts nothing more says so:\n%s", plain)
	}
}

func TestBundleRefuses(t *testing.T) {
	pool := sessionsim.NewPool(t)
	for name, opts := range map[string]keyservice.BundleOptions{
		"a pool that accepts Revoked":     {ManifestPath: pool.ManifestPath, Pools: []keyservice.PoolOptions{{ManifestPath: pool.ManifestPath, LaunchKeyPath: pool.LaunchKeyPath, AcceptTCBStatus: []string{"Revoked"}}}},
		"a pool whose list is not sorted": {ManifestPath: pool.ManifestPath, Pools: []keyservice.PoolOptions{{ManifestPath: pool.ManifestPath, LaunchKeyPath: pool.LaunchKeyPath, AcceptTCBStatus: []string{"SWHardeningNeeded", "OutOfDate"}}}},
		"no pool":                         {ManifestPath: pool.ManifestPath},
		"no image":                        {Pools: []keyservice.PoolOptions{{ManifestPath: pool.ManifestPath, LaunchKeyPath: pool.LaunchKeyPath}}},
		"a pool with no key":              {ManifestPath: pool.ManifestPath, Pools: []keyservice.PoolOptions{{ManifestPath: pool.ManifestPath, LaunchKeyPath: "/nonexistent"}}},
		"a pool whose key is a manifest":  {ManifestPath: pool.ManifestPath, Pools: []keyservice.PoolOptions{{ManifestPath: pool.ManifestPath, LaunchKeyPath: pool.ManifestPath}}},
		"a key that is no key":            {ManifestPath: pool.ManifestPath, KeyPath: pool.LaunchKeyPath, Pools: []keyservice.PoolOptions{{ManifestPath: pool.ManifestPath, LaunchKeyPath: pool.LaunchKeyPath}}},
	} {
		opts.Dir = filepath.Join(t.TempDir(), "out")
		if err := keyservice.NewBundle(opts); err == nil {
			t.Errorf("a bundle with %s was written", name)
		}
		if _, err := os.Stat(opts.Dir); !os.IsNotExist(err) {
			t.Errorf("a refused bundle with %s left its directory behind", name)
		}
	}
}

// A release opens for the key, the guest, the bind and the name it was sealed
// for, and an encryption key is the guest's only under its instance key's
// signature.
func TestSealing(t *testing.T) {
	key, err := keyservice.NewEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := keyservice.Seal(key.Public(), "sha256:guest", "sha256:bind", "token", []byte("s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	if value, err := key.Open("sha256:guest", "sha256:bind", "token", sealed); err != nil || string(value) != "s3cret" {
		t.Fatalf("the release opens to %q, %v", value, err)
	}
	again, err := keyservice.Seal(key.Public(), "sha256:guest", "sha256:bind", "token", []byte("s3cret"))
	if err != nil || string(again) == string(sealed) {
		t.Fatal("two releases of one value are the same bytes")
	}
	flipped := append([]byte(nil), sealed...)
	flipped[len(flipped)-1] ^= 1
	other, err := keyservice.NewEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	for name, open := range map[string]func() ([]byte, error){
		"another guest":  func() ([]byte, error) { return key.Open("sha256:other", "sha256:bind", "token", sealed) },
		"another bind":   func() ([]byte, error) { return key.Open("sha256:guest", "sha256:other", "token", sealed) },
		"another name":   func() ([]byte, error) { return key.Open("sha256:guest", "sha256:bind", "other", sealed) },
		"a changed byte": func() ([]byte, error) { return key.Open("sha256:guest", "sha256:bind", "token", flipped) },
		"another key":    func() ([]byte, error) { return other.Open("sha256:guest", "sha256:bind", "token", sealed) },
		// The parts are framed by their lengths: one cannot run into the next.
		"parts joined differently": func() ([]byte, error) { return key.Open("sha256:guestsha256:bind", "", "token", sealed) },
	} {
		if _, err := open(); err == nil {
			t.Errorf("the release opened for %s", name)
		}
	}
	if _, err := keyservice.Seal([]byte("no key"), "g", "b", "n", []byte("v")); err == nil {
		t.Error("a release was sealed to bytes that are no key")
	}
}
