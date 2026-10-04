//go:build unix

package sessioncli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/imagestore"
	"github.com/confidential-dot-ai/c8s/internal/imagestore/imagestoretest"
)

// The store the command writes is the one a guest pulls from: every image
// named, whole, with no registry behind it.
func TestImageStoreCommand(t *testing.T) {
	registry := imagestoretest.NewRegistry(t)
	shared := imagestoretest.Layer(imagestoretest.File("shared", "by both"))
	one := registry.Image([][]byte{shared, imagestoretest.Layer(imagestoretest.File("which", "one"))}, imagestoretest.ImageOptions{})
	two := registry.Image([][]byte{shared, imagestoretest.Layer(imagestoretest.File("which", "two"))}, imagestoretest.ImageOptions{})
	dir := t.TempDir()
	out := filepath.Join(dir, "images.store")
	plain := func(string) bool { return true }
	ctx := context.Background()

	var stdout bytes.Buffer
	if err := writeImageStore(ctx, out, []string{registry.Ref(one.Digest), registry.Ref(two.Digest)}, plain, &stdout); err != nil {
		t.Fatal(err)
	}
	if got := stdout.String(); strings.Count(got, "4 blobs") != 2 || !strings.Contains(got, "wrote "+out) || !strings.Contains(got, "sha256:") {
		t.Fatalf("the command said:\n%s", got)
	}
	info, err := os.Stat(out)
	if err != nil || info.Mode().Perm() != 0o644 || info.Size()%4096 != 0 {
		t.Fatalf("the store file: %v, %v", info, err)
	}
	// Nothing else is left beside it.
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("the directory holds %v", entries)
	}
	file, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	store, err := imagestore.OpenStore(file, info.Size())
	if err != nil {
		t.Fatal(err)
	}
	// Two manifests, two configs, the layer they share and one more each.
	if store.Len() != 7 {
		t.Fatalf("the store holds %d blobs", store.Len())
	}
	for name, manifest := range map[string]string{"one": one.Digest.String(), "two": two.Digest.String()} {
		guest := &imagestore.Puller{
			StoreDir: filepath.Join(t.TempDir(), "content"), Images: store, ImagesOnly: true,
			Limits: imagestore.PullLimits{Layers: 8, BlobBytes: 1 << 20, TotalBytes: 4 << 20},
		}
		img, err := guest.Pull(ctx, "registry.invalid/app@"+manifest)
		if err != nil || img.FromRegistry != 0 {
			t.Fatalf("a guest pulling image %s from the store: %v", name, err)
		}
	}

	// The same images in another order are the same store.
	first, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeImageStore(ctx, out, []string{registry.Ref(two.Digest), registry.Ref(one.Digest)}, plain, &stdout); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(out); !bytes.Equal(first, again) {
		t.Fatal("the store depends on the order its images were named in")
	}

	// An image that cannot be pulled leaves the store that was there, whole,
	// and nothing beside it.
	for name, ref := range map[string]string{
		"no digest":       registry.Host + "/test/app:latest",
		"not in registry": registry.Host + "/test/app@sha256:" + strings.Repeat("0", 64),
	} {
		if err := writeImageStore(ctx, out, []string{registry.Ref(one.Digest), ref}, plain, &stdout); err == nil {
			t.Errorf("%s: a store was written", name)
		}
		if after, _ := os.ReadFile(out); !bytes.Equal(first, after) {
			t.Errorf("%s: the store that was there changed", name)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 1 {
			t.Errorf("%s: the directory holds %v", name, entries)
		}
	}
}

func TestImageStoreCommandsAreRegistered(t *testing.T) {
	cmd, _, err := NewCmd().Find([]string{"image-store", "write"})
	if err != nil || cmd.Name() != "write" || cmd.Flags().Lookup("out") == nil || cmd.Flags().Lookup("plain-http") == nil {
		t.Fatalf("c8s session image-store write: %v, %v", cmd, err)
	}
	if err := cmd.Args(cmd, nil); err == nil {
		t.Fatal("a store of no images is accepted")
	}
	cmd, _, err = NewCmd().Find([]string{"image-store", "check"})
	if err != nil || cmd.Name() != "check" {
		t.Fatalf("c8s session image-store check: %v, %v", cmd, err)
	}
	if cmd.Args(cmd, nil) == nil || cmd.Args(cmd, []string{"a", "b"}) == nil || cmd.Args(cmd, []string{"a"}) != nil {
		t.Fatal("check takes one store file")
	}
}

// The check a host runs over its store before it hands it out: the whole
// file read, through the command, with its exit status the verdict.
func TestImageStoreCheckCommand(t *testing.T) {
	registry := imagestoretest.NewRegistry(t)
	image := registry.Image([][]byte{imagestoretest.Layer(imagestoretest.File("f", "x"))}, imagestoretest.ImageOptions{})
	out := filepath.Join(t.TempDir(), "images.store")
	if err := writeImageStore(context.Background(), out, []string{registry.Ref(image.Digest)}, func(string) bool { return true }, io.Discard); err != nil {
		t.Fatal(err)
	}
	run := func(path string) (string, error) {
		cmd := NewCmd()
		var stdout bytes.Buffer
		cmd.SetOut(&stdout)
		cmd.SetErr(io.Discard)
		cmd.SetArgs([]string{"image-store", "check", path})
		err := cmd.Execute()
		return stdout.String(), err
	}
	if said, err := run(out); err != nil || !strings.Contains(said, out+"  3 blobs, ") {
		t.Fatalf("check of a store as it was written: %q, %v", said, err)
	}
	// One bit of the last block, which a blob ends in or pads.
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	last := bytes.LastIndexFunc(data, func(r rune) bool { return r != 0 })
	data[last] ^= 1
	if err := os.WriteFile(out, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if said, err := run(out); err == nil || !strings.Contains(err.Error(), "are not it") || said != "" {
		t.Fatalf("check of a store with a bit changed: %q, %v", said, err)
	}
	for name, path := range map[string]string{"no file": out + ".absent", "another file": filepath.Join(filepath.Dir(out), "other")} {
		if name == "another file" {
			if err := os.WriteFile(path, make([]byte, 8192), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if said, err := run(path); err == nil || said != "" {
			t.Errorf("%s: %q, %v", name, said, err)
		}
	}
}
