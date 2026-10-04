package imagestore

import (
	"reflect"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// One digest must name one image to every reader. Go's readers take a member
// by its name in any case, and the last of two: each case here is a document
// another reader would take differently, or could.
func TestExactMembers(t *testing.T) {
	manifest := reflect.TypeFor[ocispec.Manifest]()
	config := reflect.TypeFor[ocispec.Image]()
	index := reflect.TypeFor[ocispec.Index]()
	descriptor := `{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:aa","size":1}`
	good := `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":` + descriptor +
		`,"layers":[` + descriptor + `],"annotations":{"a":"1","A":"2"},"somethingElse":{"x":1}}`
	if err := exactMembers([]byte(good), manifest); err != nil {
		t.Fatalf("a manifest as the specification spells it: %v", err)
	}
	for name, tc := range map[string]struct {
		doc  string
		into reflect.Type
		want string
	}{
		"a field under another case":              {`{"schemaVersion":2,"Config":` + descriptor + `}`, manifest, `"Config", which is read as "config"`},
		"a field twice":                           {`{"config":` + descriptor + `,"config":` + descriptor + `}`, manifest, `"config" twice`},
		"a field twice, in two cases":             {`{"config":` + descriptor + `,"CONFIG":` + descriptor + `}`, manifest, `twice`},
		"a field of an embedded struct":           {`{"SchemaVersion":2}`, manifest, `"SchemaVersion", which is read as "schemaVersion"`},
		"inside a list":                           {`{"layers":[` + descriptor + `,{"Digest":"sha256:bb"}]}`, manifest, `layers[1] holds a member "Digest"`},
		"inside a member behind a pointer":        {`{"manifests":[{"digest":"sha256:aa","platform":{"OS":"linux"}}]}`, index, `"OS", which is read as "os"`},
		"a map key twice":                         {`{"annotations":{"a":"1","a":"2"}}`, manifest, `annotations holds the member "a" twice`},
		"an unknown member twice":                 {`{"x":1,"x":2}`, manifest, `"x" twice`},
		"a member of the image's own config":      {`{"config":{"entrypoint":["/bin/sh"]}}`, config, `"entrypoint", which is read as "Entrypoint"`},
		"the platform a config embeds":            {`{"Architecture":"amd64","os":"linux"}`, config, `"Architecture", which is read as "architecture"`},
		"a name twice in a document of no type":   {`{"a":{"b":1,"b":2}}`, nil, `"b" twice`},
		"a name twice in a member nobody reads":   {`{"somethingElse":{"b":1,"b":2}}`, manifest, `"b" twice`},
		"more after the document":                 {`{"schemaVersion":2}{"schemaVersion":3}`, manifest, `followed by more`},
		"not a document":                          {`{"schemaVersion":`, manifest, ``},
		"a label twice in the image's own config": {`{"config":{"Labels":{"k":"1","k":"2"}}}`, config, `Labels holds the member "k" twice`},
		"a history entry under another case":      {`{"history":[{"Created_By":"x"}]}`, config, `"Created_By", which is read as "created_by"`},
		"the layer ids under another case":        {`{"rootfs":{"type":"layers","Diff_ids":[]}}`, config, `"Diff_ids", which is read as "diff_ids"`},
	} {
		err := exactMembers([]byte(tc.doc), tc.into)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want a refusal that says %q", name, err, tc.want)
		}
	}
	// Told apart by case where case tells them apart: the keys of a map, and
	// the names in a document that is read into no struct.
	for name, tc := range map[string]struct {
		doc  string
		into reflect.Type
	}{
		"labels in two cases":                {`{"config":{"Labels":{"k":"1","K":"2"},"Env":["A=1"]}}`, config},
		"names in two cases, read into none": {`{"a":1,"A":2,"list":[{"a":1},{"a":2}]}`, nil},
		"a scalar":                           {`"just a string"`, manifest},
		"an empty document":                  {`{}`, index},
	} {
		if err := exactMembers([]byte(tc.doc), tc.into); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The documents of an image are the index, the manifest and the config, in
// their OCI and their Docker media types.
func TestDocumentType(t *testing.T) {
	for mediaType, want := range map[string]reflect.Type{
		ocispec.MediaTypeImageIndex:                                 reflect.TypeFor[ocispec.Index](),
		"application/vnd.docker.distribution.manifest.list.v2+json": reflect.TypeFor[ocispec.Index](),
		ocispec.MediaTypeImageManifest:                              reflect.TypeFor[ocispec.Manifest](),
		"application/vnd.docker.distribution.manifest.v2+json":      reflect.TypeFor[ocispec.Manifest](),
		ocispec.MediaTypeImageConfig:                                reflect.TypeFor[ocispec.Image](),
		"application/vnd.docker.container.image.v1+json":            reflect.TypeFor[ocispec.Image](),
		ocispec.MediaTypeImageLayerGzip:                             nil,
		"":                                                          nil,
	} {
		if got := documentType(mediaType); got != want {
			t.Errorf("%q is read into %v, want %v", mediaType, got, want)
		}
	}
}

// The names a struct is read from are the decoder's: a tag's, the field's own
// where it has none, an embedded struct's fields as if they were its own, and
// none for a field the decoder leaves alone.
func TestExactMembersFollowsTheDecodersNames(t *testing.T) {
	type inner struct {
		Deep string `json:"deep"`
	}
	type apart struct {
		Far string `json:"far"`
	}
	type more struct {
		Wide string `json:"wide"`
	}
	type outer struct {
		// Tagged, and given no name by its tag: its fields are the struct's.
		more    `json:",omitempty"`
		Plain   int
		Tagged  int `json:"tagged,omitempty"`
		Skipped int `json:"-"`
		hidden  int
		*inner
		// Embedded under a name of its own: a member, with its fields inside.
		apart `json:"apart"`
		Named inner `json:"named"`
	}
	_ = outer{}.hidden
	into := reflect.TypeFor[outer]()
	for name, doc := range map[string]string{
		"as written":                   `{"Plain":1,"tagged":2,"deep":"x","named":{"deep":"y"}}`,
		"a name of an unexported one":  `{"Hidden":1}`,
		"the embedded struct's name":   `{"inner":{"Deep":"x"}}`,
		"a member the struct has none": `{"other":1}`,
		"the name of a skipped field":  `{"skipped":1}`,
		"the name of a hidden field":   `{"hidden":1}`,
		"a named embedded struct":      `{"apart":{"far":"x"},"Far":"its field's name, outside it"}`,
	} {
		if err := exactMembers([]byte(doc), into); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, tc := range map[string]struct{ doc, want string }{
		"an untagged field in another case":   {`{"plain":1}`, `"plain", which is read as "Plain"`},
		"a tagged field by its Go name":       {`{"Tagged":1}`, `"Tagged", which is read as "tagged"`},
		"an embedded field in another case":   {`{"Deep":"x"}`, `"Deep", which is read as "deep"`},
		"a named struct's field":              {`{"named":{"Deep":"y"}}`, `named holds a member "Deep"`},
		"a named embedded struct's field":     {`{"apart":{"Far":"y"}}`, `apart holds a member "Far"`},
		"a field embedded under no name":      {`{"Wide":"x"}`, `"Wide", which is read as "wide"`},
		"a name twice that no field takes":    {`{"skipped":1,"Skipped":2}`, `"Skipped" twice`},
		"a name twice that the decoder skips": {`{"other":1,"OTHER":2}`, `"OTHER" twice`},
	} {
		err := exactMembers([]byte(tc.doc), into)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want a refusal that says %q", name, err, tc.want)
		}
	}
}
