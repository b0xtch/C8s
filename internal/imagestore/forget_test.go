//go:build unix

package imagestore

import (
	"bytes"
	"context"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/imagestore/imagestoretest"
)

// A reader that is forgotten behind says how far it has read every 4 MiB,
// from the start each time, and that it is done when its source ends.
func TestSpentSaysHowFarItHasReadFromTheStart(t *testing.T) {
	var said []int64
	r := &spent{r: bytes.NewReader(make([]byte, 9<<20+5)), done: func(n int64) { said = append(said, n) }}
	if n, err := io.CopyBuffer(io.Discard, struct{ io.Reader }{r}, make([]byte, 1<<20)); err != nil || n != 9<<20+5 {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	if want := []int64{4 << 20, 8 << 20, -1}; !slices.Equal(said, want) {
		t.Fatalf("said %v, want %v", said, want)
	}
	// One that fails says so too: what it read is not read again.
	said = nil
	failing := &spent{r: io.MultiReader(strings.NewReader("abc"), failingReader{}), done: func(n int64) { said = append(said, n) }}
	if _, err := io.ReadAll(failing); err == nil {
		t.Fatal("the failure was lost")
	}
	if !slices.Equal(said, []int64{-1}) {
		t.Fatalf("a reader that failed said %v", said)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, os.ErrClosed }

// A store whose holder asks for it says which of its bytes a blob's reader
// is done with: from the blob's first block, and at the end through its
// last, which no other blob shares.
func TestStoreSaysWhichBytesABlobsReaderIsDoneWith(t *testing.T) {
	big, small := strings.Repeat("0123456789abcdef", (5<<20)/16)+"tail", "next"
	image := written(t, blobOf(big), blobOf(small))
	store := opened(t, image)
	bigKey, _ := storeKey(blobOf(big).Digest)
	smallKey, _ := storeKey(blobOf(small).Digest)
	at, next := store.entries[bigKey], store.entries[smallKey]

	// Nobody asked: the blob is read as it always was.
	plain, _ := store.Blob(blobOf(big).Digest)
	if _, ok := plain.(*spent); ok {
		t.Fatal("a store nobody asked to forget wraps its readers")
	}

	type call struct{ off, n int64 }
	var calls []call
	store.Forget = func(off, n int64) { calls = append(calls, call{off, n}) }
	blob, ok := store.Blob(blobOf(big).Digest)
	if !ok {
		t.Fatal("the store does not hold the blob")
	}
	got, err := io.ReadAll(blob)
	if err != nil || string(got) != big {
		t.Fatalf("read %d bytes of %d: %v", len(got), len(big), err)
	}
	if len(calls) < 2 {
		t.Fatalf("calls: %v", calls)
	}
	for i, c := range calls {
		if c.off != at.offset || c.off%storeBlock != 0 {
			t.Fatalf("call %d starts at %d, the blob at %d", i, c.off, at.offset)
		}
		if i > 0 && c.n < calls[i-1].n {
			t.Fatalf("call %d covers less than the one before: %v", i, calls)
		}
	}
	if first := calls[0]; first.n < forgetEvery || first.n > int64(len(big)) {
		t.Fatalf("the first call covers %d bytes", first.n)
	}
	last := calls[len(calls)-1]
	if last.n != align(at.length) || last.n < at.length || last.n%storeBlock != 0 {
		t.Fatalf("the last call covers %d bytes of a blob of %d", last.n, at.length)
	}
	// The other blob's bytes are its own reader's to give up.
	if at.offset < next.offset+next.length && next.offset < at.offset+last.n {
		t.Fatalf("the range %d+%d reaches into the other blob at %d+%d", at.offset, last.n, next.offset, next.length)
	}
}

// recorded replaces forgetFile for a test, and returns what it was asked.
func recorded(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var asked []string
	was := forgetFile
	forgetFile = func(f *os.File, off, n int64) {
		mu.Lock()
		defer mu.Unlock()
		if off != 0 {
			t.Errorf("asked to forget %s from %d", f.Name(), off)
		}
		if n == 0 {
			asked = append(asked, f.Name())
		}
	}
	t.Cleanup(func() { forgetFile = was })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(asked)
	}
}

// A pull has the kernel drop each layer once the content store has kept it,
// and again when the unpack has read it. The image's documents, which are
// read more than once, are left.
func TestPullForgetsEachLayerOnceItIsKeptAndOnceItIsUnpacked(t *testing.T) {
	asked := recorded(t)
	r := imagestoretest.NewRegistry(t)
	manifest := r.Image(twoLayers(t), imagestoretest.ImageOptions{})
	p := puller(t, roomyPull)
	img, err := p.Pull(context.Background(), r.Ref(manifest.Digest))
	if err != nil {
		t.Fatal(err)
	}
	var layers []string
	for _, layer := range img.layers {
		layers = append(layers, kept(p, layer.Digest))
	}
	if got := asked(); len(layers) != 2 || !slices.Equal(got, layers) {
		t.Fatalf("after the pull, asked to forget %v, and the layers are %v", got, layers)
	}
	for _, path := range layers {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("the content store keeps no layer at %s: %v", path, err)
		}
	}
	if _, err := unpackTo(t, img); err != nil {
		t.Fatal(err)
	}
	if got := asked(); !slices.Equal(got, append(layers, layers...)) {
		t.Fatalf("after the unpack, asked to forget %v", got)
	}
}

// A layer that is read back is forgotten as it is read, a stretch at a time
// and each time from its start.
func TestForgettingDropsWhatWasReadFromTheStart(t *testing.T) {
	path := t.TempDir() + "/blob"
	if err := os.WriteFile(path, make([]byte, 9<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	type call struct{ off, n int64 }
	var calls []call
	was := forgetFile
	forgetFile = func(f *os.File, off, n int64) {
		if f.Name() != path {
			t.Errorf("asked to forget %s", f.Name())
		}
		calls = append(calls, call{off, n})
	}
	t.Cleanup(func() { forgetFile = was })
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	r, done := forgetting(struct{ io.Reader }{source}, path)
	if _, err := io.CopyBuffer(io.Discard, r, make([]byte, 1<<20)); err != nil {
		t.Fatal(err)
	}
	done()
	if want := []call{{0, 4 << 20}, {0, 8 << 20}, {0, 0}}; !slices.Equal(calls, want) {
		t.Fatalf("calls %v, want %v", calls, want)
	}
	// A file that is not there is read as it was, and nothing is asked.
	calls = nil
	r, done = forgetting(strings.NewReader("abc"), path+"-gone")
	if got, err := io.ReadAll(r); err != nil || string(got) != "abc" {
		t.Fatalf("read %q, %v", got, err)
	}
	done()
	if len(calls) != 0 {
		t.Fatalf("asked %v of a file that is not there", calls)
	}
	forgetPath(path + "-gone")
	if len(calls) != 0 {
		t.Fatalf("asked %v of a file that is not there", calls)
	}
	forgetPath(path)
	if want := []call{{0, 0}}; !slices.Equal(calls, want) {
		t.Fatalf("forgetPath asked %v", calls)
	}
}
