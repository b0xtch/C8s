//go:build unix

package imagestore

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/confidential-dot-ai/c8s/internal/imagestore/imagestoretest"
)

const changedVolume = "the volume under it was changed"

// kept is where the content store of p keeps d.
func kept(p *Puller, d digest.Digest) string { return blobPath(p.StoreDir, d) }

// respell changes one letter of a member's name in the JSON document at
// path. A Go reader takes the document for what it was, since it matches a
// member's name in any case, and the bytes are no longer the digest's.
func respell(t *testing.T, path, member string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	at := bytes.Index(data, []byte(`"`+member+`"`))
	if at < 0 {
		t.Fatalf("%s has no member %s", path, member)
	}
	data[at+1] ^= 0x20
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The content store checks a blob as it is written, onto a volume the host
// can change afterwards. What an image is, its manifest and its config, is
// checked again when it is read back.
func TestPullChecksItsDocumentsAgainWhenItReadsThemBack(t *testing.T) {
	for name, member := range map[string]string{
		"control":      "",
		"the manifest": "schemaVersion",
		"the config":   "architecture",
	} {
		t.Run(name, func(t *testing.T) {
			r := imagestoretest.NewRegistry(t)
			manifest := r.Image(twoLayers(t), imagestoretest.ImageOptions{})
			var config digest.Digest
			for d, blob := range r.Blobs {
				if blob.MediaType == ocispec.MediaTypeImageConfig {
					config = d
				}
			}
			p := puller(t, roomyPull)
			changed := false
			// Both documents are in the content store by the time a layer is
			// asked for, and both are read again after the last layer.
			r.Serving = func(d digest.Digest) {
				if member == "" || changed || r.Blobs[d].MediaType != ocispec.MediaTypeImageLayerGzip {
					return
				}
				changed = true
				target := manifest.Digest
				if member == "architecture" {
					target = config
				}
				respell(t, kept(p, target), member)
			}
			img, err := p.Pull(context.Background(), r.Ref(manifest.Digest))
			switch {
			case member == "" && err != nil:
				t.Fatal(err)
			case member != "" && (err == nil || !strings.Contains(err.Error(), changedVolume)):
				t.Fatalf("pulled %+v, %v, with %s changed on the volume", img, err, name)
			}
		})
	}
}

// A document the store already holds is not fetched again, and is not acted
// on either before it is checked: the pull asks for nothing it names.
func TestPullFollowsNoDocumentTheVolumeChanged(t *testing.T) {
	r := imagestoretest.NewRegistry(t)
	manifest := r.Image(twoLayers(t), imagestoretest.ImageOptions{})
	p := puller(t, roomyPull)
	if _, err := p.Pull(context.Background(), r.Ref(manifest.Digest)); err != nil {
		t.Fatal(err)
	}
	respell(t, kept(p, manifest.Digest), "schemaVersion")
	// The first pull left every blob in the store, so a second one asks for
	// none. Without the config and the layers it has to ask, if it goes on.
	for d, blob := range r.Blobs {
		if blob.MediaType != ocispec.MediaTypeImageManifest {
			if err := os.Remove(kept(p, d)); err != nil {
				t.Fatal(err)
			}
		}
	}
	var served []digest.Digest
	r.Serving = func(d digest.Digest) { served = append(served, d) }
	if _, err := p.Pull(context.Background(), r.Ref(manifest.Digest)); err == nil || !strings.Contains(err.Error(), changedVolume) {
		t.Fatalf("the second pull: %v", err)
	}
	if len(served) != 0 {
		t.Fatalf("the pull went on to fetch %v, named by a manifest it had not checked", served)
	}
}

// A descriptor's digest comes from a document, so it may name an algorithm
// this build has not. That is an error, as for any digest that cannot be
// checked.
func TestCheckedRefusesADigestItCannotCompute(t *testing.T) {
	_, err := checked{}.ReaderAt(context.Background(), ocispec.Descriptor{Digest: "md5:d41d8cd98f00b204e9800998ecf8427e", Size: 1})
	if err == nil {
		t.Fatal("read a blob named by an MD5 digest")
	}
}

// A manifest, an index and a config are read whole into memory, so each is
// bounded before it is fetched. A layer is not: it is streamed to the volume.
func TestPullBoundsADocument(t *testing.T) {
	limits := PullLimits{Layers: 8, BlobBytes: 64 << 20, TotalBytes: 128 << 20}
	r := imagestoretest.NewRegistry(t)
	env := "PAD=" + strings.Repeat("x", maxRootBytes)
	manifest := r.Image(twoLayers(t), imagestoretest.ImageOptions{Config: &ocispec.ImageConfig{Env: []string{env}}})
	if _, err := puller(t, limits).Pull(context.Background(), r.Ref(manifest.Digest)); err == nil || !strings.Contains(err.Error(), "a manifest, index or config is at most") {
		t.Fatalf("a config of %d bytes and more: %v", maxRootBytes, err)
	}

	// Random bytes, so the layer is as large compressed.
	noise := make([]byte, maxRootBytes+4096)
	if _, err := rand.Read(noise); err != nil {
		t.Fatal(err)
	}
	manifest = r.Image([][]byte{imagestoretest.Layer(file("noise", string(noise)))}, imagestoretest.ImageOptions{})
	if _, err := puller(t, limits).Pull(context.Background(), r.Ref(manifest.Digest)); err != nil {
		t.Fatalf("a layer of %d bytes and more: %v", maxRootBytes, err)
	}
}
