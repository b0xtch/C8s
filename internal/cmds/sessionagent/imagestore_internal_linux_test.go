package sessionagent

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/opencontainers/go-digest"

	"github.com/confidential-dot-ai/c8s/internal/imagestore"
	"github.com/confidential-dot-ai/c8s/internal/imagestore/imagestoretest"
)

// The agent reads each blob of its host's store once. What a read leaves in
// the page cache is memory the host backs for as long as the guest lives, so
// the agent has the kernel drop it behind the read.
func TestTheImageStoreDiskLeavesNoPageCacheBehind(t *testing.T) {
	path := filepath.Join(imagestoretest.OnDisk(t), "images.store")
	data := make([]byte, 12<<20)
	data[0] = 1
	d := digest.FromBytes(data)
	var image bytes.Buffer
	err := imagestore.WriteStore(&image, []imagestore.StoreBlob{{Digest: d, Size: int64(len(data)), Open: func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, image.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	cold := func() {
		t.Helper()
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := f.Sync(); err != nil {
			t.Fatal(err)
		}
		imagestore.ForgetFile(f, 0, 0)
	}
	read := func(store *imagestore.Store) {
		t.Helper()
		blob, ok := store.Blob(d)
		if !ok {
			t.Fatal("the store does not hold the blob")
		}
		if n, err := io.Copy(io.Discard, blob); err != nil || n != int64(len(data)) {
			t.Fatalf("read %d bytes: %v", n, err)
		}
	}
	pages := len(data) / os.Getpagesize()

	// The control: a store read plainly stays in the page cache.
	cold()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	plain, err := imagestore.OpenStore(f, int64(image.Len()))
	if err != nil {
		t.Fatal(err)
	}
	read(plain)
	if in, of := imagestoretest.Resident(t, path); in < pages*9/10 {
		t.Fatalf("after a plain read the kernel holds %d of %d pages: this test would show nothing", in, of)
	}

	cold()
	store, size, err := openStoreDisk(path)
	if err != nil || size != int64(image.Len()) {
		t.Fatalf("open the store: %d bytes, %v", size, err)
	}
	read(store)
	// The index and some read-ahead may stay.
	if in, of := imagestoretest.Resident(t, path); in > 1024 {
		t.Fatalf("after the agent's read the kernel still holds %d of %d pages", in, of)
	}
}
