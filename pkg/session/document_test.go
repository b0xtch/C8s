package session_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

func TestBundleRoundTrip(t *testing.T) {
	td := sessiontest.NewTD()
	dir, bundle := newBundle(t, td, func(o *session.BundleOptions) { o.Machines = nil })
	doc := bundle.Document
	if doc.SchemaVersion != session.LaunchSchemaVersion || doc.Pool != "agents" || doc.Class != "s-4x16" ||
		doc.Image.Platform != "tdx" || len(doc.Image.RTMRs) != 2 {
		t.Fatalf("unexpected document: %+v", doc)
	}
	if doc.AgeLimitSeconds != 0 || doc.Prestage != nil || doc.Machine != nil {
		t.Fatalf("a plain pool document carries more than it was given: %+v", doc)
	}
	info, err := os.Stat(filepath.Join(dir, session.BundleKeyFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("launch key mode = %v, %v", info.Mode(), err)
	}
	// The document grants nothing and names nobody: there is no place in it
	// for either.
	for _, word := range []string{"tenant", "access", "sandbox", "credentials"} {
		if bytes.Contains(bundle.Launch, []byte(word)) {
			t.Errorf("the launch document mentions %q:\n%s", word, bundle.Launch)
		}
	}
}

func TestNewBundleRefuses(t *testing.T) {
	td := sessiontest.NewTD()
	dir := t.TempDir()
	err := session.NewBundle(session.BundleOptions{Dir: dir, ManifestPath: td.WriteManifest(t), Pool: "agents", Class: "s-4x16"})
	if err == nil {
		t.Fatal("NewBundle reused an existing directory")
	}
	if _, statErr := os.Stat(dir); statErr != nil {
		t.Fatalf("a refused bundle must not remove a directory it did not create: %v", statErr)
	}
	manifest := td.WriteManifest(t)
	for name, opts := range map[string]session.BundleOptions{
		"no pool":                  {Class: "s-4x16"},
		"no class":                 {Pool: "agents"},
		"a pool that is no label":  {Pool: "Agents", Class: "s-4x16"},
		"a class that is no label": {Pool: "agents", Class: "s_4x16"},
		"an age limit in fractions": {
			Pool: "agents", Class: "s-4x16", AgeLimit: 90*time.Second + time.Millisecond,
		},
		"an age limit under the floor": {Pool: "agents", Class: "s-4x16", AgeLimit: time.Second},
	} {
		opts.Dir, opts.ManifestPath = filepath.Join(t.TempDir(), "b"), manifest
		if err := session.NewBundle(opts); err == nil {
			t.Errorf("a bundle with %s was written", name)
		}
		if _, statErr := os.Stat(opts.Dir); statErr == nil {
			t.Errorf("%s: a refused bundle left its directory behind", name)
		}
	}
}

func TestVerifySignedRejects(t *testing.T) {
	td := sessiontest.NewTD()
	_, bundle := newBundle(t, td, nil)
	other := newKey(t)
	otherPub := []byte(keyPEM(t, other))
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
		"appended document":   {bundle.LaunchKey, append(append([]byte(nil), bundle.Launch...), "pool: evil\n"...), bundle.Signature},
		"empty signature":     {bundle.LaunchKey, bundle.Launch, ""},
		"empty document":      {bundle.LaunchKey, nil, bundle.Signature},
		"unparseable pubkey":  {[]byte("not a key"), bundle.Launch, bundle.Signature},
		"two keys in the PEM": {append(append([]byte(nil), bundle.LaunchKey...), bundle.LaunchKey...), bundle.Launch, bundle.Signature},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := session.VerifySigned(tc.pub, tc.data, tc.sig); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := session.VerifySigned(bundle.LaunchKey, bundle.Launch, bundle.Signature); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func TestParseRejects(t *testing.T) {
	td := sessiontest.NewTD()
	_, bundle := newBundle(t, td, func(o *session.BundleOptions) { o.Prestage = []string{sandboxImage} })
	valid := string(bundle.Launch)
	replace := func(old, new string) string {
		t.Helper()
		if !strings.Contains(valid, old) {
			t.Fatalf("fixture lacks %q:\n%s", old, valid)
		}
		return strings.Replace(valid, old, new, 1)
	}
	for name, doc := range map[string]string{
		"unknown field":            valid + "extra: 1\n",
		"duplicate key":            valid + "pool: other\n",
		"second document":          valid + "---\npool: other\n",
		"wrong schema":             replace("c8s-session-launch/v1", "c8s-launch/v1"),
		"a later schema":           replace("c8s-session-launch/v1", "c8s-session-launch/v2"),
		"a bind's schema":          replace("c8s-session-launch/v1", "c8s-bind/v1"),
		"pool not a label":         replace("pool: agents", "pool: Agents_1"),
		"class not a label":        replace("class: s-4x16", "class: s.4x16"),
		"a tenant":                 replace("pool: agents", "pool: agents\ntenant: acme"),
		"an access area":           valid + "access:\n    exec: []\n",
		"a sandbox":                valid + "sandbox:\n    image: " + sandboxImage + "\n",
		"tag-pinned image":         replace(sandboxImage, "ghcr.io/acme/agent:latest"),
		"bare digest image":        replace(sandboxImage, "sha256:"+strings.Repeat("1", 64)),
		"uppercase measurement":    replace("measurement: ", "measurement: A"),
		"rtmr 3 pinned":            replace("    1: ", "    3: "),
		"noncanonical rtmr key":    replace("    1: ", "    01: "),
		"anchor":                   replace("pool: agents", "pool: &p agents"),
		"a hexadecimal number":     replace("prestage:", "ageLimitSeconds: 0xe10\nprestage:"),
		"a number with a fraction": replace("prestage:", "ageLimitSeconds: 3600.0\nprestage:"),
		"oversized":                valid + "#" + strings.Repeat("x", session.MaxDocumentSize),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := session.Parse([]byte(doc)); err == nil {
				t.Fatalf("accepted:\n%s", doc)
			}
		})
	}
	if _, err := session.Parse([]byte(valid)); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// A document has one spelling, the one it is written in when it is signed.
// Every other spelling of the same content is refused, so that no second
// reader of YAML can take a signed document for other content than the guest
// did.
func TestParseTakesOneSpellingOfADocument(t *testing.T) {
	td := sessiontest.NewTD()
	other := "registry.example/other@sha256:" + strings.Repeat("3", 64)
	_, bundle := newBundle(t, td, func(o *session.BundleOptions) { o.Prestage = []string{sandboxImage, other} })
	valid := string(bundle.Launch)
	replace := func(old, new string) string {
		t.Helper()
		if !strings.Contains(valid, old) {
			t.Fatalf("fixture lacks %q:\n%s", old, valid)
		}
		return strings.Replace(valid, old, new, 1)
	}
	list := "prestage:\n    - " + sandboxImage + "\n    - " + other + "\n"
	for name, doc := range map[string]string{
		"a comment":                  valid + "# reviewed\n",
		"a blank line":               valid + "\n",
		"no final newline":           strings.TrimSuffix(valid, "\n"),
		"a quoted plain string":      replace("pool: agents", `pool: "agents"`),
		"a list in flow style":       replace(list, "prestage: ["+sandboxImage+", "+other+"]\n"),
		"another indentation":        replace(list, "prestage:\n- "+sandboxImage+"\n- "+other+"\n"),
		"two members the other way":  replace("pool: agents\nclass: s-4x16\n", "class: s-4x16\npool: agents\n"),
		"a document start marker":    "---\n" + valid,
		"carriage returns":           strings.ReplaceAll(valid, "\n", "\r\n"),
		"a space at the end of line": replace("class: s-4x16\n", "class: s-4x16 \n"),
		"an explicit string tag":     replace("class: s-4x16", "class: !!str s-4x16"),
	} {
		_, err := session.Parse([]byte(doc))
		if err == nil || !strings.Contains(err.Error(), "canonical form") {
			t.Errorf("%s: %v, want a refusal for its form", name, err)
		}
	}
	if _, err := session.Parse([]byte(valid)); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// A launch document may bound how long its guests wait for a bind. The bound
// is part of the signed document, within limits that keep it meaningful.
func TestLaunchDocumentAgeLimit(t *testing.T) {
	_, plain := newBundle(t, sessiontest.NewTD(), nil)
	if plain.Document.AgeLimitSeconds != 0 || plain.Document.AgeLimit() != 0 {
		t.Fatalf("a document with no age limit carries one: %+v", plain.Document)
	}
	_, timed := newBundle(t, sessiontest.NewTD(), func(o *session.BundleOptions) { o.AgeLimit = time.Hour })
	if got := timed.Document.AgeLimit(); got != time.Hour {
		t.Fatalf("age limit = %s, want 1h", got)
	}
	if !bytes.Contains(timed.Launch, []byte("ageLimitSeconds: 3600")) {
		t.Fatalf("the document does not carry its age limit:\n%s", timed.Launch)
	}
	for name, value := range map[string]string{"under a minute": "59", "over a week": "604801", "negative": "-1", "not a number": "soon"} {
		edited := bytes.Replace(timed.Launch, []byte("ageLimitSeconds: 3600"), []byte("ageLimitSeconds: "+value), 1)
		if _, err := session.Parse(edited); err == nil {
			t.Errorf("a document with an age limit %s parsed", name)
		}
	}
}

// A launch document may list public images its guests unpack ahead of any
// bind. The list is in the signed document, a few images long, each pinned
// by its digest and named once.
func TestLaunchDocumentPrestageList(t *testing.T) {
	other := "registry.example/other@sha256:" + strings.Repeat("3", 64)
	_, listed := newBundle(t, sessiontest.NewTD(), func(o *session.BundleOptions) { o.Prestage = []string{sandboxImage, other} })
	if got := listed.Document.Prestage; len(got) != 2 || got[0] != sandboxImage || got[1] != other {
		t.Fatalf("the document lists %v", got)
	}
	if !bytes.Contains(listed.Launch, []byte("prestage:\n    - "+sandboxImage+"\n    - "+other)) {
		t.Fatalf("the document does not carry its list:\n%s", listed.Launch)
	}
	more := func(n int) string {
		var out strings.Builder
		for i := range n {
			out.WriteString("\n    - registry.example/n@sha256:" + strings.Repeat(string(rune('a'+i)), 64))
		}
		return out.String()
	}
	for name, edit := range map[string][2]string{
		"an image twice":           {other, sandboxImage},
		"an image under two names": {other, "registry.example/again@" + sandboxImage[strings.Index(sandboxImage, "sha256:"):]},
		"an image with no digest":  {other, "registry.example/other:latest"},
		"an image with a tag only": {other, "registry.example/other:v1@latest"},
		"more images than allowed": {"\n    - " + other, "\n    - " + other + more(session.MaxPrestage-1)},
	} {
		if !bytes.Contains(listed.Launch, []byte(edit[0])) {
			t.Fatalf("%s: fixture has no %q in\n%s", name, edit[0], listed.Launch)
		}
		if _, err := session.Parse(bytes.Replace(listed.Launch, []byte(edit[0]), []byte(edit[1]), 1)); err == nil {
			t.Errorf("a document that lists %s parsed", name)
		}
	}
	// As many as allowed is allowed.
	full := bytes.Replace(listed.Launch, []byte("\n    - "+other), []byte("\n    - "+other+more(session.MaxPrestage-2)), 1)
	if doc, err := session.Parse(full); err != nil || len(doc.Prestage) != session.MaxPrestage {
		t.Errorf("a document that lists %d images: %v", session.MaxPrestage, err)
	}
}

func TestExecRequestValidate(t *testing.T) {
	id := strings.Repeat("a", 32)
	for name, req := range map[string]session.ExecRequest{
		"no id":         {Argv: []string{"true"}},
		"short id":      {ID: "abc", Argv: []string{"true"}},
		"no argv":       {ID: id},
		"empty command": {ID: id, Argv: []string{""}},
		"NUL":           {ID: id, Argv: []string{"a\x00"}},
		"timeout":       {ID: id, Argv: []string{"true"}, TimeoutSeconds: session.MaxExecTimeout + 1},
		"stdin":         {ID: id, Argv: []string{"true"}, Stdin: make([]byte, session.MaxExecStdin+1)},
		"env name":      {ID: id, Argv: []string{"true"}, Env: map[string]string{"1X": "y"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := req.Validate(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	ok := session.ExecRequest{ID: id, Argv: []string{"sh", "-c", "true"}, Env: map[string]string{"A": "b"}, TimeoutSeconds: 5}
	if err := ok.Validate(); err != nil {
		t.Fatalf("control: %v", err)
	}
}
