//go:build unix

package imagestore

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
)

func blobOf(data string) StoreBlob {
	return StoreBlob{
		Digest: digest.FromString(data), Size: int64(len(data)),
		Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(data)), nil },
	}
}

func written(t *testing.T, blobs ...StoreBlob) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := WriteStore(&out, blobs); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestStoreHoldsWhatWasWritten(t *testing.T) {
	contents := []string{"a manifest", strings.Repeat("a layer ", 4000), "c"}
	var blobs []StoreBlob
	for _, data := range contents {
		blobs = append(blobs, blobOf(data))
	}
	image := written(t, blobs...)
	if len(image)%storeBlock != 0 {
		t.Fatalf("the store is %d bytes, which is no whole number of blocks", len(image))
	}
	// The same set in another order, and with one blob twice, is the same store.
	if again := written(t, blobs[2], blobs[0], blobs[1], blobs[0]); !bytes.Equal(again, image) {
		t.Fatal("the store depends on the order its blobs were given in")
	}
	store, err := OpenStore(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		t.Fatal(err)
	}
	if store.Len() != len(contents) {
		t.Fatalf("the store lists %d blobs", store.Len())
	}
	for _, data := range contents {
		d := digest.FromString(data)
		size, ok := store.Size(d)
		r, found := store.Blob(d)
		if !ok || !found || size != int64(len(data)) {
			t.Fatalf("%s: size %d, %v, %v", d, size, ok, found)
		}
		if got, err := io.ReadAll(r); err != nil || string(got) != data {
			t.Fatalf("%s reads as %d bytes, %v", d, len(got), err)
		}
	}
	absent := digest.FromString("absent")
	if _, ok := store.Size(absent); ok {
		t.Fatal("the store holds a blob nobody wrote")
	}
	if _, ok := store.Blob(absent); ok {
		t.Fatal("the store reads a blob nobody wrote")
	}
	// Only SHA-256 names a blob here: not a digest of another kind that
	// begins as a blob's does.
	longer := digest.Digest("sha512:" + digest.FromString("c").Encoded() + strings.Repeat("0", 64))
	if err := longer.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, d := range []digest.Digest{longer, "sha256:xyz", ""} {
		if _, ok := store.Size(d); ok {
			t.Fatalf("the store holds %q", d)
		}
		if _, ok := store.Blob(d); ok {
			t.Fatalf("the store reads %q", d)
		}
	}
	// No store holds nothing, and says so.
	var none *Store
	if _, ok := none.Size(digest.FromString("a manifest")); ok || none.Len() != 0 {
		t.Fatal("a nil store holds a blob")
	}
	if _, ok := none.Blob(digest.FromString("a manifest")); ok {
		t.Fatal("a nil store reads a blob")
	}
}

func TestWriteStoreRefusesBlobsThatAreNotTheirDigest(t *testing.T) {
	good := blobOf("content")
	for name, blob := range map[string]StoreBlob{
		"other bytes":  {Digest: good.Digest, Size: good.Size, Open: blobOf("CONTENT").Open},
		"longer":       {Digest: good.Digest, Size: good.Size, Open: blobOf("content and more").Open},
		"shorter":      {Digest: good.Digest, Size: good.Size + 1, Open: good.Open},
		"no bytes":     blobOf(""),
		"not a sha256": {Digest: "sha512:" + digest.Digest(strings.Repeat("0", 128)), Size: good.Size, Open: good.Open},
	} {
		if err := WriteStore(io.Discard, []StoreBlob{blob}); err == nil {
			t.Errorf("%s: written", name)
		}
	}
}

// The file is the host's. Whatever its header and index say, a guest reads
// only inside the file, and a blob is found only where an entry of an ordered
// index puts it.
func TestOpenStoreRefusesAnIndexThatLies(t *testing.T) {
	image := written(t, blobOf("one"), blobOf("two"))
	entry := func(i int) []byte { return image[storeBlock+i*storeEntryOn:][:storeEntryOn] }
	for name, damage := range map[string]func(b []byte) []byte{
		"control":                       func(b []byte) []byte { return b },
		"too short for a header":        func(b []byte) []byte { return b[:storeBlock-1] },
		"another file":                  func(b []byte) []byte { b[0] ^= 1; return b },
		"a later version":               func(b []byte) []byte { binary.LittleEndian.PutUint64(b[16:], 2); return b },
		"an earlier version":            func(b []byte) []byte { binary.LittleEndian.PutUint64(b[16:], 0); return b },
		"more blobs than a store holds": func(b []byte) []byte { binary.LittleEndian.PutUint64(b[24:], MaxStoreBlobs+1); return b },
		"more blobs than the file":      func(b []byte) []byte { binary.LittleEndian.PutUint64(b[24:], 1000); return b },
		"entries out of order": func(b []byte) []byte {
			first := bytes.Clone(entry(0))
			copy(entry(0), entry(1))
			copy(entry(1), first)
			return b
		},
		"the same blob twice": func(b []byte) []byte { copy(entry(1), entry(0)); return b },
		"a blob in the index": func(b []byte) []byte { binary.LittleEndian.PutUint64(entry(0)[32:], storeBlock); return b },
		"a blob past the end": func(b []byte) []byte { binary.LittleEndian.PutUint64(entry(0)[40:], uint64(len(b))); return b },
		"an offset past the end": func(b []byte) []byte {
			binary.LittleEndian.PutUint64(entry(0)[32:], uint64(len(b))+1)
			return b
		},
		"an offset that wraps": func(b []byte) []byte {
			binary.LittleEndian.PutUint64(entry(0)[32:], 1<<63)
			binary.LittleEndian.PutUint64(entry(0)[40:], 1<<63)
			return b
		},
		"a length that wraps": func(b []byte) []byte { binary.LittleEndian.PutUint64(entry(0)[40:], ^uint64(0)); return b },
		"an empty blob":       func(b []byte) []byte { binary.LittleEndian.PutUint64(entry(0)[40:], 0); return b },
	} {
		t.Run(name, func(t *testing.T) {
			saved := bytes.Clone(image)
			defer copy(image, saved)
			damaged := damage(image)
			_, err := OpenStore(bytes.NewReader(damaged), int64(len(damaged)))
			if (err == nil) != (name == "control") {
				t.Fatalf("OpenStore: %v", err)
			}
		})
	}
}

// What an entry points at is whatever the host put there. The store hands it
// over as it is: the pull that asked checks it.
func TestStoreReadsWhateverItsEntryPointsAt(t *testing.T) {
	image := written(t, blobOf("one"), blobOf("two"))
	first, second := image[storeBlock:][:storeEntryOn], image[storeBlock+storeEntryOn:][:storeEntryOn]
	// The first blob's entry now points at the second blob's bytes.
	copy(first[32:], second[32:])
	store, err := OpenStore(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		t.Fatal(err)
	}
	var names []digest.Digest
	for _, data := range []string{"one", "two"} {
		names = append(names, digest.FromString(data))
	}
	// Ascending by digest: which of the two is first depends on their digests.
	swapped := names[0]
	if names[1] < names[0] {
		swapped = names[1]
	}
	r, ok := store.Blob(swapped)
	if !ok {
		t.Fatal("the blob is gone")
	}
	got, err := io.ReadAll(r)
	if err != nil || digest.FromBytes(got) == swapped {
		t.Fatalf("read %q, %v: the entry was not redirected", got, err)
	}
}

// An index is read into the guest's memory whole, so it is bounded, however
// well formed the rest of the store is.
func TestOpenStoreBoundsItsIndex(t *testing.T) {
	for count, want := range map[int]bool{MaxStoreBlobs: true, MaxStoreBlobs + 1: false} {
		blobsFrom := storeBlock + count*storeEntryOn
		image := make([]byte, blobsFrom+storeBlock)
		copy(image, storeMagic)
		binary.LittleEndian.PutUint64(image[16:], storeVersion)
		binary.LittleEndian.PutUint64(image[24:], uint64(count))
		for i := range count {
			entry := image[storeBlock+i*storeEntryOn:]
			// Ascending keys, and every entry at the one block of blobs.
			binary.BigEndian.PutUint64(entry, uint64(i+1))
			binary.LittleEndian.PutUint64(entry[32:], uint64(blobsFrom))
			binary.LittleEndian.PutUint64(entry[40:], 1)
		}
		store, err := OpenStore(bytes.NewReader(image), int64(len(image)))
		if (err == nil) != want || (want && store.Len() != count) {
			t.Errorf("a store that lists %d blobs: %v", count, err)
		}
	}
}

// A host checks its own store before it hands it out: every blob read, and
// each the blob its entry names.
func TestStoreCheck(t *testing.T) {
	image := written(t, blobOf("one"), blobOf("two"), blobOf("three"))
	entry := func(i int) []byte { return image[storeBlock+i*storeEntryOn:][:storeEntryOn] }
	at := func(i int) uint64 { return binary.LittleEndian.Uint64(entry(i)[32:]) }
	length := func(i int) uint64 { return binary.LittleEndian.Uint64(entry(i)[40:]) }
	for name, tc := range map[string]struct {
		damage func()
		wrong  int
	}{
		"control":                         {func() {}, -1},
		"a bit of the first blob":         {func() { image[at(0)] ^= 1 }, 0},
		"a bit of the last blob":          {func() { image[at(2)] ^= 1 }, 2},
		"the last byte of a blob":         {func() { image[at(1)+length(1)-1] ^= 1 }, 1},
		"an entry at another blob":        {func() { copy(entry(1)[32:], entry(2)[32:]) }, 1},
		"an entry one byte short":         {func() { binary.LittleEndian.PutUint64(entry(2)[40:], length(2)-1) }, 2},
		"the first and the last, changed": {func() { image[at(0)] ^= 1; image[at(2)] ^= 1 }, 0},
	} {
		t.Run(name, func(t *testing.T) {
			saved := bytes.Clone(image)
			defer copy(image, saved)
			tc.damage()
			blobs, size, err := opened(t, image).Check()
			if tc.wrong < 0 {
				if err != nil || blobs != 3 || size != int64(len("one")+len("two")+len("three")) {
					t.Fatalf("Check = %d blobs, %d bytes, %v", blobs, size, err)
				}
				return
			}
			want := hex.EncodeToString(entry(tc.wrong)[:sha256.Size])
			if err == nil || !strings.Contains(err.Error(), "sha256:"+want+" are not it") {
				t.Fatalf("Check = %v, want the blob sha256:%s named", err, want)
			}
		})
	}
	if blobs, size, err := (*Store)(nil).Check(); blobs != 0 || size != 0 || err != nil {
		t.Fatalf("a nil store checks as %d blobs, %d bytes, %v", blobs, size, err)
	}
}
