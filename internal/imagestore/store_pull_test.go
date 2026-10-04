//go:build unix

package imagestore

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/confidential-dot-ai/c8s/internal/imagestore/imagestoretest"
)

// stored is a store that holds the registry's blobs, less the ones named.
func stored(t *testing.T, r *imagestoretest.Registry, without ...digest.Digest) []byte {
	t.Helper()
	var blobs []StoreBlob
	for d, blob := range r.Blobs {
		skip := false
		for _, w := range without {
			skip = skip || w == d
		}
		if !skip {
			blobs = append(blobs, StoreBlob{Digest: d, Size: int64(len(blob.Data)), Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(blob.Data)), nil
			}})
		}
	}
	return written(t, blobs...)
}

func opened(t *testing.T, image []byte) *Store {
	t.Helper()
	store, err := OpenStore(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// nowhere is a reference to d at a registry that does not exist: a pull that
// asks it fails.
func nowhere(d digest.Digest) string { return "127.0.0.1:1/test/app@" + d.String() }

// An image the host's store holds is pulled without a registry: every blob
// from the store, each checked as a registry's would be.
func TestPullFromTheStoreAsksNoRegistry(t *testing.T) {
	r := imagestoretest.NewRegistry(t)
	manifest := r.Image(twoLayers(t), imagestoretest.ImageOptions{})
	p := puller(t, roomyPull)
	p.Images, p.ImagesOnly = opened(t, stored(t, r)), true
	// The reference names a registry that is there and answers. It is sent
	// nothing.
	img, err := p.Pull(context.Background(), r.Ref(manifest.Digest))
	if err != nil {
		t.Fatal(err)
	}
	// Manifest, config and two layers.
	if img.FromStore != 4 || img.FromRegistry != 0 || img.Digest != manifest.Digest {
		t.Fatalf("%d blobs from the store and %d from a registry", img.FromStore, img.FromRegistry)
	}
	if n := r.Requests.Load(); n != 0 {
		t.Fatalf("the registry was sent %d requests", n)
	}
	root, err := unpackTo(t, img)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "srv/new")); err != nil || string(got) != "3" {
		t.Fatalf("srv/new: %q, %v", got, err)
	}
	// Without the registry's leave, too: the store is asked first either way.
	p = puller(t, roomyPull)
	p.Images = opened(t, stored(t, r))
	if img, err = p.Pull(context.Background(), nowhere(manifest.Digest)); err != nil || img.FromRegistry != 0 {
		t.Fatalf("with a registry allowed and not needed: %v", err)
	}
}

// What a pull was made of is what a store of it holds: a store written from
// a pulled image serves that image again, through an index as well.
func TestAStoreWrittenFromAPullServesTheImage(t *testing.T) {
	r := imagestoretest.NewRegistry(t)
	arm := r.Image([][]byte{imagestoretest.Layer(file("arch", "arm64"))}, imagestoretest.ImageOptions{Arch: "arm64"})
	amd := r.Image([][]byte{imagestoretest.Layer(file("arch", "amd64"))}, imagestoretest.ImageOptions{})
	index := r.PutJSON(ocispec.MediaTypeImageIndex, ocispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{arm, amd},
	})
	ctx := context.Background()
	pulled, err := puller(t, roomyPull).Pull(ctx, r.Ref(index.Digest))
	if err != nil {
		t.Fatal(err)
	}
	// The index, this platform's manifest, its config and its layer.
	blobs := pulled.Blobs(ctx)
	if len(blobs) != 4 || blobs[0].Digest != index.Digest || pulled.FromRegistry != 4 || pulled.FromStore != 0 {
		t.Fatalf("the pull was made of %d blobs, %d from a registry", len(blobs), pulled.FromRegistry)
	}
	p := puller(t, roomyPull)
	p.Images, p.ImagesOnly = opened(t, written(t, blobs...)), true
	if _, ok := p.Images.Size(arm.Digest); ok {
		t.Fatal("the store holds another platform's manifest")
	}
	img, err := p.Pull(ctx, nowhere(index.Digest))
	if err != nil {
		t.Fatal(err)
	}
	root, err := unpackTo(t, img)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(root, "arch")); string(got) != "amd64" {
		t.Fatalf("unpacked the %q image", got)
	}
}

// What the store does not hold comes from the registry, unless the pull may
// ask none.
func TestPullTakesFromTheRegistryWhatTheStoreLacks(t *testing.T) {
	r := imagestoretest.NewRegistry(t)
	layers := twoLayers(t)
	manifest := r.Image(layers, imagestoretest.ImageOptions{})
	var layer digest.Digest
	for d, blob := range r.Blobs {
		if blob.MediaType == ocispec.MediaTypeImageLayerGzip {
			layer = d
		}
	}
	ctx := context.Background()
	for name, without := range map[string]digest.Digest{"a layer": layer, "the manifest": manifest.Digest} {
		t.Run(name, func(t *testing.T) {
			p := puller(t, roomyPull)
			p.Images = opened(t, stored(t, r, without))
			img, err := p.Pull(ctx, r.Ref(manifest.Digest))
			if err != nil {
				t.Fatal(err)
			}
			if img.FromRegistry != 1 || img.FromStore != 3 {
				t.Fatalf("%d blobs from the store and %d from the registry", img.FromStore, img.FromRegistry)
			}
			if _, err := unpackTo(t, img); err != nil {
				t.Fatal(err)
			}
			p = puller(t, roomyPull)
			p.Images, p.ImagesOnly = opened(t, stored(t, r, without)), true
			asked := r.Requests.Load()
			if _, err := p.Pull(ctx, r.Ref(manifest.Digest)); err == nil || !strings.Contains(err.Error(), "does not hold") {
				t.Fatalf("a pull that may ask no registry: %v", err)
			}
			if n := r.Requests.Load() - asked; n != 0 {
				t.Fatalf("a pull that may ask no registry sent it %d requests", n)
			}
		})
	}
}

// The store is the host's file. A blob it serves is taken only if it is the
// blob that was asked for: by its bytes, and by the size its verified parent
// gave it. Nothing of an image with a blob that is not is unpacked.
func TestPullRefusesWhatTheStoreChanged(t *testing.T) {
	r := imagestoretest.NewRegistry(t)
	manifest := r.Image(twoLayers(t), imagestoretest.ImageOptions{})
	var config, layer digest.Digest
	for d, blob := range r.Blobs {
		switch blob.MediaType {
		case ocispec.MediaTypeImageConfig:
			config = d
		case ocispec.MediaTypeImageLayerGzip:
			layer = d
		}
	}
	// entry finds the index entry of d in a store image.
	entry := func(image []byte, d digest.Digest) []byte {
		key, _ := storeKey(d)
		at := bytes.Index(image[storeBlock:], key[:])
		if at < 0 || at%storeEntryOn != 0 {
			t.Fatalf("no index entry for %s", d)
		}
		return image[storeBlock+at:][:storeEntryOn]
	}
	flip := func(image []byte, d digest.Digest) {
		image[binary.LittleEndian.Uint64(entry(image, d)[32:])] ^= 1
	}
	for name, tc := range map[string]struct {
		change func(image []byte)
		want   string
	}{
		"control":                       {func([]byte) {}, ""},
		"a bit of the manifest":         {func(b []byte) { flip(b, manifest.Digest) }, "where it lists"},
		"a bit of the config":           {func(b []byte) { flip(b, config) }, "digest"},
		"a bit of a layer":              {func(b []byte) { flip(b, layer) }, "digest"},
		"a layer's entry at the config": {func(b []byte) { copy(entry(b, layer)[32:], entry(b, config)[32:]) }, "bytes"},
		"a layer one byte short": {func(b []byte) {
			e := entry(b, layer)[40:]
			binary.LittleEndian.PutUint64(e, binary.LittleEndian.Uint64(e)-1)
		}, "bytes"},
		"the manifest's entry at a layer": {func(b []byte) { copy(entry(b, manifest.Digest)[32:], entry(b, layer)[32:]) }, "where it lists"},
	} {
		t.Run(name, func(t *testing.T) {
			image := stored(t, r)
			tc.change(image)
			p := puller(t, roomyPull)
			// The registry is there and is not asked: a store that holds a
			// blob wrongly does not hold it at all.
			p.Images = opened(t, image)
			img, err := p.Pull(context.Background(), r.Ref(manifest.Digest))
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("pulled %+v, %v, want an error that says %q", img, err, tc.want)
			}
		})
	}
}

// A reference names a manifest or an index. From the store the document says
// which it is, once it is known to be the document.
func TestRootType(t *testing.T) {
	for name, tc := range map[string]struct{ doc, want string }{
		"an OCI manifest":               {`{"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{}}`, ocispec.MediaTypeImageManifest},
		"an OCI index":                  {`{"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{}]}`, ocispec.MediaTypeImageIndex},
		"a Docker manifest":             {`{"mediaType":"application/vnd.docker.distribution.manifest.v2+json"}`, "application/vnd.docker.distribution.manifest.v2+json"},
		"a Docker manifest list":        {`{"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json"}`, "application/vnd.docker.distribution.manifest.list.v2+json"},
		"a manifest that names none":    {`{"config":{"digest":"sha256:00"},"layers":[]}`, ocispec.MediaTypeImageManifest},
		"an index that names none":      {`{"manifests":[{"digest":"sha256:00"}]}`, ocispec.MediaTypeImageIndex},
		"a config":                      {`{"mediaType":"application/vnd.oci.image.config.v1+json"}`, ""},
		"a config shaped as a manifest": {`{"mediaType":"application/vnd.oci.image.config.v1+json","config":{},"layers":[]}`, ""},
		"both":                          {`{"config":{},"manifests":[{}]}`, ""},
		"both, and it says a manifest":  {`{"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{},"manifests":[{}]}`, ""},
		"both, and it says an index":    {`{"mediaType":"application/vnd.oci.image.index.v1+json","config":{},"manifests":[{}]}`, ""},
		"an index that says a manifest": {`{"mediaType":"application/vnd.oci.image.manifest.v1+json","manifests":[{}]}`, ""},
		"a manifest that says an index": {`{"mediaType":"application/vnd.oci.image.index.v1+json","config":{}}`, ""},
		"an index's type over layers":   {`{"mediaType":"application/vnd.oci.image.index.v1+json","layers":[{}]}`, ""},
		"layers and an index's list":    {`{"layers":[{}],"manifests":[{}]}`, ""},
		"layers and no config":          {`{"layers":[{}]}`, ""},
		"schema 1":                      {`{"schemaVersion":1,"fsLayers":[{"blobSum":"sha256:00"}]}`, ""},
		"schema 1 that says a manifest": {`{"mediaType":"application/vnd.docker.distribution.manifest.v2+json","fsLayers":[{}]}`, ""},
		"neither":                       {`{"architecture":"amd64"}`, ""},
		"a layer":                       {"\x1f\x8b\x08\x00", ""},
		"nothing":                       {``, ""},
	} {
		got, err := rootType([]byte(tc.doc))
		if got != tc.want || (err == nil) != (tc.want != "") {
			t.Errorf("%s: %q, %v, want %q", name, got, err, tc.want)
		}
	}
}

// A layer is not what a reference names, whatever digest the reference
// carries, and the store is not read for more than a manifest's worth.
func TestPullRefusesARootThatIsNoManifest(t *testing.T) {
	r := imagestoretest.NewRegistry(t)
	r.Image(twoLayers(t), imagestoretest.ImageOptions{})
	var layer digest.Digest
	for d, blob := range r.Blobs {
		if blob.MediaType == ocispec.MediaTypeImageLayerGzip {
			layer = d
		}
	}
	p := puller(t, roomyPull)
	p.Images, p.ImagesOnly = opened(t, stored(t, r)), true
	if _, err := p.Pull(context.Background(), nowhere(layer)); err == nil || !strings.Contains(err.Error(), "neither a manifest nor an index") {
		t.Fatalf("a layer as an image: %v", err)
	}

	big := strings.Repeat(" ", maxRootBytes) + "{}"
	image := written(t, blobOf(big))
	p = puller(t, PullLimits{Layers: 8, BlobBytes: 64 << 20, TotalBytes: 128 << 20})
	p.Images, p.ImagesOnly = opened(t, image), true
	if _, err := p.Pull(context.Background(), nowhere(digest.FromString(big))); err == nil || !strings.Contains(err.Error(), "no manifest") {
		t.Fatalf("a root larger than any manifest: %v", err)
	}
}

// The limits of a pull hold for what comes from the store.
func TestPullFromTheStoreKeepsItsLimits(t *testing.T) {
	r := imagestoretest.NewRegistry(t)
	manifest := r.Image(twoLayers(t), imagestoretest.ImageOptions{})
	for name, limits := range map[string]PullLimits{
		"layers":      {Layers: 1, BlobBytes: 1 << 20, TotalBytes: 4 << 20},
		"blob bytes":  {Layers: 8, BlobBytes: 64, TotalBytes: 4 << 20},
		"total bytes": {Layers: 8, BlobBytes: 1 << 20, TotalBytes: 700},
	} {
		p := puller(t, limits)
		p.Images, p.ImagesOnly = opened(t, stored(t, r)), true
		if _, err := p.Pull(context.Background(), nowhere(manifest.Digest)); err == nil {
			t.Errorf("%s: pulled past the limit", name)
		}
	}
}
