package session_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// pinOf is a pin of a key service that runs the image of td and was launched
// under key.
func pinOf(t *testing.T, td *sessiontest.TD) *session.KeyService {
	t.Helper()
	image, err := session.ImageFromManifest(td.WriteManifest(t), 0)
	if err != nil {
		t.Fatal(err)
	}
	return &session.KeyService{URL: "https://192.0.2.7:8443", Image: image, LaunchKey: keyPEM(t, newKey(t))}
}

func TestKeyServicePin(t *testing.T) {
	pin := pinOf(t, sessiontest.NewTD())
	if err := pin.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, url := range map[string]string{
		"plain HTTP":            "http://192.0.2.7:8443",
		"no port":               "https://192.0.2.7",
		"a path":                "https://192.0.2.7:8443/v1",
		"a trailing slash":      "https://192.0.2.7:8443/",
		"a query":               "https://192.0.2.7:8443?x=1",
		"a user":                "https://user@192.0.2.7:8443",
		"a port with a zero":    "https://192.0.2.7:08443",
		"a port that is none":   "https://192.0.2.7:0",
		"nothing":               "",
		"a very long host name": "https://" + strings.Repeat("a", 300) + ":8443",
	} {
		changed := *pin
		changed.URL = url
		if err := changed.Validate(); err == nil {
			t.Errorf("a pin with %s was accepted", name)
		}
	}
	noKey := *pin
	noKey.LaunchKey = "not a key"
	if err := noKey.Validate(); err == nil {
		t.Error("a pin with a launch key that is none was accepted")
	}

	same := *pin
	other := pinOf(t, sessiontest.NewTD())
	if !pin.Equal(&same) || pin.Equal(other) || pin.Equal(nil) || !(*session.KeyService)(nil).Equal(nil) {
		t.Error("Equal does not tell two pins from one")
	}
	moved := *pin
	moved.URL = "https://192.0.2.8:8443"
	if pin.Equal(&moved) {
		t.Error("a pin at another address is the same pin")
	}

	// What a pin accepts of the key service's platform is part of it: an
	// owner's bind equals its guest's pin only if it accepts the same.
	lenient := *pin
	lenient.AcceptTCBStatus = []string{"OutOfDate", "SWHardeningNeeded"}
	if err := lenient.Validate(); err != nil {
		t.Fatal(err)
	}
	alike := lenient
	alike.AcceptTCBStatus = []string{"OutOfDate", "SWHardeningNeeded"}
	fewer := lenient
	fewer.AcceptTCBStatus = []string{"OutOfDate"}
	if pin.Equal(&lenient) || lenient.Equal(pin) || lenient.Equal(&fewer) || !lenient.Equal(&alike) {
		t.Error("Equal does not tell what two pins accept apart")
	}
	for name, statuses := range map[string][]string{
		"Revoked":         {"Revoked"},
		"a made-up one":   {"Fine"},
		"an unsorted one": {"SWHardeningNeeded", "OutOfDate"},
		"one twice":       {"OutOfDate", "OutOfDate"},
	} {
		changed := *pin
		changed.AcceptTCBStatus = statuses
		if err := changed.Validate(); err == nil {
			t.Errorf("a pin that accepts %s was taken", name)
		}
	}

	// The file form, as 'c8s session key-service pin' writes it.
	path := filepath.Join(t.TempDir(), "pin.json")
	write := func(body string) {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"url":"https://192.0.2.7:8443","image":{"platform":"tdx","measurement":"` + pin.Image.Measurement +
		`","rtmrs":{"1":"` + pin.Image.RTMRs[1] + `","2":"` + pin.Image.RTMRs[2] + `"}},"launchKey":` + quoted(pin.LaunchKey) + `}`)
	loaded, err := session.LoadKeyServicePin(path)
	if err != nil || !loaded.Equal(pin) {
		t.Fatalf("the pin file reads %+v, %v", loaded, err)
	}
	write(`{"url":"https://192.0.2.7:8443","extra":1}`)
	if _, err := session.LoadKeyServicePin(path); err == nil {
		t.Error("a pin file with an unknown field was accepted")
	}
	write(`{"url":"https://192.0.2.7:8443","image":{"platform":"tdx","measurement":"` + pin.Image.Measurement +
		`","rtmrs":{"1":"` + pin.Image.RTMRs[1] + `","2":"` + pin.Image.RTMRs[2] + `"}},"launchKey":` + quoted(pin.LaunchKey) +
		`,"acceptTCBStatus":["OutOfDate","SWHardeningNeeded"]}`)
	if loaded, err := session.LoadKeyServicePin(path); err != nil || !loaded.Equal(&lenient) {
		t.Fatalf("the pin file with accepted statuses reads %+v, %v", loaded, err)
	}
	write(`{"url":"https://192.0.2.7:8443","image":{"platform":"tdx","measurement":"` + pin.Image.Measurement +
		`"},"launchKey":` + quoted(pin.LaunchKey) + `,"acceptTCBStatus":["Revoked"]}`)
	if _, err := session.LoadKeyServicePin(path); err == nil {
		t.Error("a pin file that accepts Revoked was taken")
	}
}

func quoted(s string) string {
	return `"` + strings.ReplaceAll(s, "\n", `\n`) + `"`
}

// An image pinned by a document's values is held to evidence as one pinned
// by its manifest is.
func TestImageIdentityFromADocument(t *testing.T) {
	td := sessiontest.NewTD()
	image, err := session.ImageFromManifest(td.WriteManifest(t), 0)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := image.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.Verify(td.Result()); err != nil {
		t.Fatalf("the image's own guest: %v", err)
	}
	for name, mutate := range map[string]func(td *sessiontest.TD){
		"another firmware": func(td *sessiontest.TD) { td.MRTD[0] ^= 1 },
		"another kernel":   func(td *sessiontest.TD) { td.RTMR[1][0] ^= 1 },
		"another rootfs":   func(td *sessiontest.TD) { td.RTMR[2][0] ^= 1 },
	} {
		twin := sessiontest.NewTD()
		twin.MRTD, twin.RTMR[1], twin.RTMR[2] = td.MRTD, td.RTMR[1], td.RTMR[2]
		mutate(twin)
		if err := identity.Verify(twin.Result()); err == nil {
			t.Errorf("a guest of %s passed as the pinned image", name)
		}
	}
	bad := image
	bad.Measurement = "zz"
	if _, err := bad.Identity(); err == nil {
		t.Error("an image with no measurement has an identity")
	}
}

// A launch document may pin a key service, and a bind may name stored
// credentials only with one.
func TestKeyServiceInDocuments(t *testing.T) {
	td := sessiontest.NewTD()
	pin := pinOf(t, sessiontest.NewTD())
	dir := filepath.Join(t.TempDir(), "bundle")
	if err := session.NewBundle(session.BundleOptions{Dir: dir, ManifestPath: td.WriteManifest(t), Pool: "agents", Class: "s-4x16", KeyService: pin}); err != nil {
		t.Fatal(err)
	}
	bundle, err := session.LoadBundle(dir)
	if err != nil || !bundle.Document.KeyService.Equal(pin) {
		t.Fatalf("the launch document pins %+v, %v", bundle.Document.KeyService, err)
	}
	wrong := *pin
	wrong.URL = "http://192.0.2.7:8443"
	if err := session.NewBundle(session.BundleOptions{Dir: filepath.Join(t.TempDir(), "b"), ManifestPath: td.WriteManifest(t), Pool: "agents", Class: "s-4x16", KeyService: &wrong}); err == nil {
		t.Error("a launch document with a pin that is none was written")
	}

	authority, instance := newKey(t), newKey(t)
	stored := session.BindPolicy{Credentials: []session.Credential{{Name: "token", Source: session.SourceKeyService}}}
	bind, err := session.NewBind(session.BindOptions{Authority: authority, InstanceKey: &instance.PublicKey, Tenant: "acme", Session: "s1", KeyService: pin, Policy: stored})
	if err != nil {
		t.Fatalf("a bind with a stored credential and a key service: %v", err)
	}
	if !bind.Doc.KeyService.Equal(pin) {
		t.Fatal("the bind lost its pin")
	}
	// A stored credential needs no key that hands it over, and a key service.
	if _, err := session.NewBind(session.BindOptions{Authority: authority, InstanceKey: &instance.PublicKey, Tenant: "acme", Session: "s1", Policy: stored}); err == nil {
		t.Error("a bind with a stored credential and no key service was signed")
	}
	unknown := session.BindPolicy{Credentials: []session.Credential{{Name: "token", Source: "vault"}}}
	if _, err := session.NewBind(session.BindOptions{Authority: authority, InstanceKey: &instance.PublicKey, Tenant: "acme", Session: "s1", KeyService: pin, Policy: unknown}); err == nil {
		t.Error("a bind with a credential from a source nobody knows was signed")
	}
	handed := session.BindPolicy{Credentials: []session.Credential{{Name: "token"}}}
	if _, err := session.NewBind(session.BindOptions{Authority: authority, InstanceKey: &instance.PublicKey, Tenant: "acme", Session: "s1", Policy: handed}); err == nil {
		t.Error("a bind with a handed credential and no key to hand it was signed")
	}
}
