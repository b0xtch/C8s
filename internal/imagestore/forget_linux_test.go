package imagestore

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/opencontainers/go-digest"

	"github.com/confidential-dot-ai/c8s/internal/imagestore/imagestoretest"
)

// synced writes a file of size bytes and has it written out, so that every
// page of it is clean and in the page cache.
func synced(t *testing.T, path string, size int) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(make([]byte, size)); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
}

// What a layer's read leaves in the page cache is gone when the read is: the
// kernel is asked for real here, and asked what it still holds.
func TestALayerReadBackLeavesNothingInThePageCache(t *testing.T) {
	path := filepath.Join(imagestoretest.OnDisk(t), "blob")
	const size = 24 << 20
	synced(t, path, size)
	read := func(wrap func(io.Reader) (io.Reader, func())) {
		t.Helper()
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		r, done := wrap(f)
		defer done()
		if n, err := io.Copy(io.Discard, r); err != nil || n != size {
			t.Fatalf("read %d bytes: %v", n, err)
		}
	}
	// The control: read plainly, the file stays.
	read(func(r io.Reader) (io.Reader, func()) { return r, func() {} })
	if in, of := imagestoretest.Resident(t, path); in < of*9/10 {
		t.Fatalf("after a plain read the kernel holds %d of %d pages: this test would show nothing", in, of)
	}
	read(func(r io.Reader) (io.Reader, func()) { return forgetting(r, path) })
	if in, of := imagestoretest.Resident(t, path); in > 16 {
		t.Fatalf("after a read that forgets, the kernel still holds %d of %d pages", in, of)
	}
	// And a file kept by a writer that synced it, as the content store's is.
	synced(t, path, size)
	if in, of := imagestoretest.Resident(t, path); in < of*9/10 {
		t.Fatalf("after a write the kernel holds %d of %d pages", in, of)
	}
	forgetPath(path)
	if in, of := imagestoretest.Resident(t, path); in > 16 {
		t.Fatalf("forgetPath left %d of %d pages", in, of)
	}
}

// A store's blob, read with the store's holder forgetting behind it, leaves
// nothing, and what the reader has not reached is left alone.
func TestAStoreBlobLeavesNothingInThePageCache(t *testing.T) {
	path := filepath.Join(imagestoretest.OnDisk(t), "images.store")
	first, second := make([]byte, 12<<20), make([]byte, 6<<20)
	first[0], second[0] = 1, 2
	blob := func(data []byte) StoreBlob {
		return StoreBlob{Digest: digest.FromBytes(data), Size: int64(len(data)), Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(data)), nil
		}}
	}
	image := written(t, blob(first), blob(second))
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	forgetPath(path)
	store, err := OpenStore(f, int64(len(image)))
	if err != nil {
		t.Fatal(err)
	}
	store.Forget = func(off, n int64) { ForgetFile(f, off, n) }
	// The second blob is read plainly first: its pages are the control.
	plain := &Store{r: store.r, entries: store.entries}
	for _, read := range []struct {
		from *Store
		data []byte
	}{{plain, second}, {store, first}} {
		r, ok := read.from.Blob(digest.FromBytes(read.data))
		if !ok {
			t.Fatal("the store does not hold the blob")
		}
		if n, err := io.Copy(io.Discard, r); err != nil || n != int64(len(read.data)) {
			t.Fatalf("read %d bytes: %v", n, err)
		}
	}
	in, of := imagestoretest.Resident(t, path)
	kept, dropped := len(second)/os.Getpagesize(), len(first)/os.Getpagesize()
	if in < kept*9/10 {
		t.Fatalf("the kernel holds %d of %d pages, and the blob read plainly is %d: this test would show nothing", in, of, kept)
	}
	// Some read-ahead past a blob's end may stay.
	if in > kept+1024 {
		t.Fatalf("the kernel holds %d of %d pages: the blob read plainly is %d, and the one forgotten %d", in, of, kept, dropped)
	}
}
