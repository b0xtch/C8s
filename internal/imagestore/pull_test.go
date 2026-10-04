//go:build unix

package imagestore

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/confidential-dot-ai/c8s/internal/imagestore/imagestoretest"
)

var roomyPull = PullLimits{Layers: 8, BlobBytes: 1 << 20, TotalBytes: 4 << 20}

func puller(t *testing.T, limits PullLimits) *Puller {
	return &Puller{StoreDir: filepath.Join(t.TempDir(), "store"), Limits: limits, PlainHTTP: func(string) bool { return true }}
}

func twoLayers(t *testing.T) [][]byte {
	return [][]byte{
		imagestoretest.Layer(dir("srv"), file("srv/old", "1"), file("srv/kept", "2")),
		imagestoretest.Layer(file("srv/.wh.old", ""), file("srv/new", "3")),
	}
}

func unpackTo(t *testing.T, img *Image) (string, error) {
	t.Helper()
	u := newUnpacker(t, roomy, false)
	if err := img.Unpack(context.Background(), u); err != nil {
		return "", err
	}
	_, err := u.Finish()
	return u.root, err
}

func TestPullAndUnpack(t *testing.T) {
	r := imagestoretest.NewRegistry(t)
	manifest := r.Image(twoLayers(t), imagestoretest.ImageOptions{})
	img, err := puller(t, roomyPull).Pull(context.Background(), r.Ref(manifest.Digest))
	if err != nil {
		t.Fatal(err)
	}
	if img.Digest != manifest.Digest {
		t.Fatalf("image digest %s, pinned %s", img.Digest, manifest.Digest)
	}
	if img.Resolved <= 0 || img.Fetched <= 0 {
		t.Fatalf("the pull took %s to resolve and %s to fetch", img.Resolved, img.Fetched)
	}
	if got := img.Config.Config; got.WorkingDir != "/srv" || len(got.Entrypoint) != 1 || got.Entrypoint[0] != "/bin/app" || got.Env[0] != "A=b" {
		t.Fatalf("config %+v", got)
	}
	root, err := unpackTo(t, img)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"srv/kept": "2", "srv/new": "3"} {
		if got, err := os.ReadFile(filepath.Join(root, name)); err != nil || string(got) != want {
			t.Fatalf("%s: %q, %v", name, got, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "srv/old")); !os.IsNotExist(err) {
		t.Fatalf("srv/old survived the second layer: %v", err)
	}
}

func TestPullThroughAnIndexTakesTheGuestPlatform(t *testing.T) {
	r := imagestoretest.NewRegistry(t)
	arm := r.Image([][]byte{imagestoretest.Layer(file("arch", "arm64"))}, imagestoretest.ImageOptions{Arch: "arm64"})
	amd := r.Image([][]byte{imagestoretest.Layer(file("arch", "amd64"))}, imagestoretest.ImageOptions{})
	index := r.PutJSON(ocispec.MediaTypeImageIndex, ocispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{arm, amd},
	})
	img, err := puller(t, roomyPull).Pull(context.Background(), r.Ref(index.Digest))
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

func TestPullRefusesAReferenceWithoutADigest(t *testing.T) {
	r := imagestoretest.NewRegistry(t)
	ref := r.Host + "/test/app:latest"
	if _, err := puller(t, roomyPull).Pull(context.Background(), ref); err == nil || !strings.Contains(err.Error(), "not pinned") {
		t.Fatalf("err = %v", err)
	}
}

func TestPullRefusesContentThatDoesNotMatchItsDigest(t *testing.T) {
	for _, target := range []string{"manifest", "config", "layer"} {
		t.Run(target, func(t *testing.T) {
			r := imagestoretest.NewRegistry(t)
			manifest := r.Image(twoLayers(t), imagestoretest.ImageOptions{})
			var m ocispec.Manifest
			if err := json.Unmarshal(r.Blobs[manifest.Digest].Data, &m); err != nil {
				t.Fatal(err)
			}
			victim := map[string]digest.Digest{"manifest": manifest.Digest, "config": m.Config.Digest, "layer": m.Layers[1].Digest}[target]
			// Same length, one byte changed: only the digest can tell.
			b := r.Blobs[victim]
			b.Data = bytes.Clone(b.Data)
			b.Data[len(b.Data)/2] ^= 1
			r.Blobs[victim] = b
			// The refusal must be the content store's digest check. Any other
			// error could hide bytes that were committed unverified.
			_, err := puller(t, roomyPull).Pull(context.Background(), r.Ref(manifest.Digest))
			if err == nil || !strings.Contains(err.Error(), "unexpected commit digest") {
				t.Fatalf("a %s with one flipped byte: err = %v", target, err)
			}
		})
	}
}

// countingTransport counts the body bytes the puller reads off the network.
type countingTransport struct {
	read *atomic.Int64
}

type countingBody struct {
	io.ReadCloser
	read *atomic.Int64
}

func (b countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.read.Add(int64(n))
	return n, err
}

func (c countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err == nil {
		resp.Body = countingBody{resp.Body, c.read}
	}
	return resp, err
}

func TestPullCutsOffABlobLongerThanDeclared(t *testing.T) {
	r := imagestoretest.NewRegistry(t)
	manifest := r.Image(twoLayers(t), imagestoretest.ImageOptions{})
	r.Padding = make([]byte, 8<<20)
	var read atomic.Int64
	p := puller(t, roomyPull)
	p.Client = &http.Client{Transport: countingTransport{&read}}
	if _, err := p.Pull(context.Background(), r.Ref(manifest.Digest)); err == nil {
		t.Fatal("a padded body was accepted")
	}
	// The first blob is the manifest. One byte past its declared size is all
	// the puller may take of the eight megabytes on offer.
	if got := read.Load(); got > manifest.Size+1 {
		t.Fatalf("the puller read %d bytes of a body declared as %d", got, manifest.Size)
	}
}

func TestPullBoundsABodyOfUndeclaredLength(t *testing.T) {
	r := imagestoretest.NewRegistry(t)
	manifest := r.Image(twoLayers(t), imagestoretest.ImageOptions{})
	r.Padding = make([]byte, 8<<20)
	r.HeadWithoutLength = true
	var read atomic.Int64
	limits := PullLimits{Layers: 8, BlobBytes: 4096, TotalBytes: 1 << 20}
	p := puller(t, limits)
	p.Client = &http.Client{Transport: countingTransport{&read}}
	_, err := p.Pull(context.Background(), r.Ref(manifest.Digest))
	if err == nil || !strings.Contains(err.Error(), errNetworkBudget.Error()) {
		t.Fatalf("err = %v", err)
	}
	// The resolver reads this body itself, before any size is known to it.
	if got := read.Load(); got > limits.BlobBytes+1 {
		t.Fatalf("the puller read %d bytes with a %d byte limit per blob", got, limits.BlobBytes)
	}
}

func TestPullEnforcesItsLimits(t *testing.T) {
	r := imagestoretest.NewRegistry(t)
	manifest := r.Image(twoLayers(t), imagestoretest.ImageOptions{})
	for _, c := range []struct {
		name   string
		limits PullLimits
		want   string
	}{
		{"one blob", PullLimits{Layers: 8, BlobBytes: 64, TotalBytes: 4 << 20}, "limit 64"},
		{"all blobs", PullLimits{Layers: 8, BlobBytes: 1 << 20, TotalBytes: 600}, "larger than 600 bytes"},
		{"layer count", PullLimits{Layers: 1, BlobBytes: 1 << 20, TotalBytes: 4 << 20}, "image has 2 layers"},
	} {
		_, err := puller(t, c.limits).Pull(context.Background(), r.Ref(manifest.Digest))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to say %q", c.name, err, c.want)
		}
	}
}

func TestPullRefusesAnotherPlatform(t *testing.T) {
	r := imagestoretest.NewRegistry(t)
	manifest := r.Image(twoLayers(t), imagestoretest.ImageOptions{Arch: "arm64"})
	if _, err := puller(t, roomyPull).Pull(context.Background(), r.Ref(manifest.Digest)); err == nil || !strings.Contains(err.Error(), "arm64") {
		t.Fatalf("err = %v", err)
	}
}

// An image is refused if one of its documents would be another image to a
// reader that takes member names exactly: here a manifest whose config is
// named in another case, and a config with a second entrypoint that only a
// reader as lenient as Go's would overlook.
func TestPullRefusesDocumentsTwoReadersCouldTakeDifferently(t *testing.T) {
	r := imagestoretest.NewRegistry(t)
	honest := r.Image(twoLayers(t), imagestoretest.ImageOptions{})
	manifestJSON := r.Blobs[honest.Digest].Data
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		t.Fatal(err)
	}
	configJSON := r.Blobs[manifest.Config.Digest].Data
	replaced := func(doc []byte, old, new string) []byte {
		t.Helper()
		if !bytes.Contains(doc, []byte(old)) {
			t.Fatalf("fixture lacks %s:\n%s", old, doc)
		}
		return bytes.Replace(doc, []byte(old), []byte(new), 1)
	}

	twisted := r.Put(ocispec.MediaTypeImageManifest, replaced(manifestJSON, `"config":`, `"Config":`))
	if _, err := puller(t, roomyPull).Pull(context.Background(), r.Ref(twisted.Digest)); err == nil || !strings.Contains(err.Error(), `"Config", which is read as "config"`) {
		t.Fatalf("a manifest that names its config in another case: %v", err)
	}

	manifest.Config = r.Put(ocispec.MediaTypeImageConfig, replaced(configJSON, `"Entrypoint":`, `"entrypoint":["/bin/other"],"Entrypoint":`))
	second := r.PutJSON(ocispec.MediaTypeImageManifest, manifest)
	if _, err := puller(t, roomyPull).Pull(context.Background(), r.Ref(second.Digest)); err == nil || !strings.Contains(err.Error(), `"entrypoint", which is read as "Entrypoint"`) {
		t.Fatalf("a config with an entrypoint under each spelling: %v", err)
	}

	// The honest image, whose documents are spelled as the readers expect.
	if _, err := puller(t, roomyPull).Pull(context.Background(), r.Ref(honest.Digest)); err != nil {
		t.Fatal(err)
	}
}

func TestPullRefusesLayersItCannotUnpack(t *testing.T) {
	for _, mediaType := range []string{
		"application/vnd.oci.image.layer.v1.tar+gzip+encrypted",
		"application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
		"application/vnd.erofs.layer.v1",
	} {
		r := imagestoretest.NewRegistry(t)
		manifest := r.Image(twoLayers(t), imagestoretest.ImageOptions{LayerType: mediaType})
		if _, err := puller(t, roomyPull).Pull(context.Background(), r.Ref(manifest.Digest)); err == nil || !strings.Contains(err.Error(), "unsupported media type") {
			t.Errorf("%s: err = %v", mediaType, err)
		}
	}
}

func TestUnpackRefusesALayerThatIsNotTheOneTheConfigNames(t *testing.T) {
	r := imagestoretest.NewRegistry(t)
	layers := twoLayers(t)
	manifest := r.Image(layers, imagestoretest.ImageOptions{DiffIDs: []digest.Digest{digest.FromBytes(layers[0]), digest.FromString("another layer")}})
	img, err := puller(t, roomyPull).Pull(context.Background(), r.Ref(manifest.Digest))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unpackTo(t, img); err == nil || !strings.Contains(err.Error(), "layer 1: uncompressed layer is") {
		t.Fatalf("err = %v", err)
	}
}

// TestPullFromARegistry pulls and unpacks a real image. It is opt-in: set
// C8S_PODIMAGE_REF to name@sha256:<digest> and allow network access.
func TestPullFromARegistry(t *testing.T) {
	ref := os.Getenv("C8S_PODIMAGE_REF")
	if ref == "" {
		t.Skip("set C8S_PODIMAGE_REF to pull a real image")
	}
	p := &Puller{StoreDir: filepath.Join(t.TempDir(), "store"), Limits: PullLimits{Layers: 64, BlobBytes: 1 << 30, TotalBytes: 4 << 30}}
	img, err := p.Pull(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	u := newUnpacker(t, UnpackLimits{Entries: 1 << 20, Bytes: 8 << 30}, os.Geteuid() == 0)
	if err := img.Unpack(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	stats, err := u.Finish()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s: %d layers, %+v, entrypoint %v, cmd %v", img.Digest, len(img.layers), stats, img.Config.Config.Entrypoint, img.Config.Config.Cmd)
}

func TestUnpackBoundsWhatFollowsTheArchive(t *testing.T) {
	r := imagestoretest.NewRegistry(t)
	padded := append(imagestoretest.Layer(file("f", "x")), make([]byte, maxTrailingBytes+4096)...)
	manifest := r.Image([][]byte{padded}, imagestoretest.ImageOptions{})
	img, err := puller(t, roomyPull).Pull(context.Background(), r.Ref(manifest.Digest))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unpackTo(t, img); err == nil || !strings.Contains(err.Error(), "follow the archive") {
		t.Fatalf("err = %v", err)
	}
}
