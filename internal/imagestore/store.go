//go:build unix

package imagestore

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"

	"github.com/opencontainers/go-digest"
)

// A Store is a set of OCI blobs in one file, which a host fills outside any
// guest and hands, read-only, to every guest it launches. A guest that finds
// an image's blobs there asks no registry for them.
//
// The file is the host's and is trusted for nothing. Its index says where a
// blob is; whether the bytes there are the blob is decided by their digest,
// as it is for a registry's answer. A wrong index entry or changed bytes cost
// the guest its pull and nothing else.
//
//	bytes 0..4095   "c8s-image-store\n", the version and the number of
//	                blobs, both 64-bit little-endian; the rest zero
//	bytes 4096..    one 48-byte entry per blob, ascending by digest:
//	                its SHA-256, its offset and its length
//	then            the blobs, each at a multiple of 4096
type Store struct {
	r       io.ReaderAt
	entries map[[sha256.Size]byte]storeEntry
	// Forget, if set, is told which bytes of the store a blob's reader is
	// done with, as it reads: n bytes from off, both multiples of the
	// store's block but for the n of a blob still being read. A guest has
	// the kernel drop them, since it reads each blob once.
	Forget func(off, n int64)
}

type storeEntry struct{ offset, length int64 }

const (
	storeMagic   = "c8s-image-store\n"
	storeVersion = 1
	storeBlock   = 4096
	storeEntryOn = sha256.Size + 16
	// MaxStoreBlobs bounds the index a guest reads into memory: 3 MiB of it.
	MaxStoreBlobs = 1 << 16
)

// OpenStore reads the index of the store in r, which is size bytes long. It
// reads nothing else: a blob is read when a pull asks for it.
func OpenStore(r io.ReaderAt, size int64) (*Store, error) {
	header := make([]byte, storeBlock)
	if _, err := r.ReadAt(header, 0); err != nil {
		return nil, fmt.Errorf("image store: read header: %w", err)
	}
	if string(header[:len(storeMagic)]) != storeMagic {
		return nil, errors.New("image store: not an image store")
	}
	if version := binary.LittleEndian.Uint64(header[16:]); version != storeVersion {
		return nil, fmt.Errorf("image store: version %d, this guest reads version %d", version, storeVersion)
	}
	count := binary.LittleEndian.Uint64(header[24:])
	if count > MaxStoreBlobs {
		return nil, fmt.Errorf("image store: lists %d blobs, at most %d", count, MaxStoreBlobs)
	}
	blobsFrom := int64(storeBlock + count*storeEntryOn)
	index := make([]byte, count*storeEntryOn)
	if _, err := r.ReadAt(index, storeBlock); err != nil && len(index) > 0 {
		return nil, fmt.Errorf("image store: read index: %w", err)
	}
	s := &Store{r: r, entries: make(map[[sha256.Size]byte]storeEntry, count)}
	var last []byte
	for ; len(index) > 0; index = index[storeEntryOn:] {
		sum, offset, length := index[:sha256.Size], binary.LittleEndian.Uint64(index[sha256.Size:]), binary.LittleEndian.Uint64(index[sha256.Size+8:])
		if last != nil && bytes.Compare(last, sum) >= 0 {
			return nil, errors.New("image store: index is not in ascending order")
		}
		last = sum
		// In this order no sum overflows.
		if length == 0 || offset < uint64(blobsFrom) || offset > uint64(size) || length > uint64(size)-offset {
			return nil, fmt.Errorf("image store: the entry for sha256:%x lies outside the store", sum)
		}
		s.entries[[sha256.Size]byte(sum)] = storeEntry{offset: int64(offset), length: int64(length)}
	}
	return s, nil
}

// Len is the number of blobs the store lists.
func (s *Store) Len() int {
	if s == nil {
		return 0
	}
	return len(s.entries)
}

func storeKey(d digest.Digest) (key [sha256.Size]byte, ok bool) {
	// Validate first: Algorithm panics on a digest without one.
	if d.Validate() != nil || d.Algorithm() != digest.SHA256 {
		return key, false
	}
	// A valid SHA-256 digest is 64 hex characters.
	raw, _ := hex.DecodeString(d.Encoded())
	return [sha256.Size]byte(raw), true
}

// Size is how many bytes the store says it holds for d. A nil store holds
// nothing.
func (s *Store) Size(d digest.Digest) (int64, bool) {
	if s == nil {
		return 0, false
	}
	key, ok := storeKey(d)
	if !ok {
		return 0, false
	}
	entry, ok := s.entries[key]
	return entry.length, ok
}

// Blob reads what the store holds for d. The caller checks it against d.
func (s *Store) Blob(d digest.Digest) (io.Reader, bool) {
	if s == nil {
		return nil, false
	}
	key, ok := storeKey(d)
	if !ok {
		return nil, false
	}
	entry, ok := s.entries[key]
	if !ok {
		return nil, false
	}
	blob := io.NewSectionReader(s.r, entry.offset, entry.length)
	if s.Forget == nil {
		return blob, true
	}
	return &spent{r: blob, done: func(n int64) {
		if n < 0 {
			// The blob's last block is its own: the next one starts on a
			// block of its own.
			n = align(entry.length)
		}
		s.Forget(entry.offset, n)
	}}, true
}

// Check reads every blob the store lists, and returns how many there are and
// how many bytes, or the first, by digest, whose bytes are not the blob its
// entry names. A host runs it over its own store before it hands the store
// out: a guest that meets a wrong blob at a bind ends, and its tenant waits
// for another guest.
func (s *Store) Check() (blobs int, size int64, err error) {
	if s == nil {
		return 0, 0, nil
	}
	keys := slices.SortedFunc(maps.Keys(s.entries), func(a, b [sha256.Size]byte) int { return bytes.Compare(a[:], b[:]) })
	for _, key := range keys {
		entry := s.entries[key]
		hash := sha256.New()
		if _, err := io.Copy(hash, io.NewSectionReader(s.r, entry.offset, entry.length)); err != nil {
			return 0, 0, fmt.Errorf("image store: read sha256:%x: %w", key, err)
		}
		if !bytes.Equal(hash.Sum(nil), key[:]) {
			return 0, 0, fmt.Errorf("image store: the bytes listed for sha256:%x are not it", key)
		}
		size += entry.length
	}
	return len(keys), size, nil
}

// StoreBlob is one blob for WriteStore.
type StoreBlob struct {
	Digest digest.Digest
	Size   int64
	// Open returns the blob's bytes.
	Open func() (io.ReadCloser, error)
}

// WriteStore writes a store that holds blobs, each once. What it writes
// depends on the set of blobs alone. A blob whose bytes are not its digest or
// its size is an error: a store is written from blobs that were verified, and
// stays so.
func WriteStore(w io.Writer, blobs []StoreBlob) error {
	type keyed struct {
		key [sha256.Size]byte
		StoreBlob
	}
	var all []keyed
	seen := map[[sha256.Size]byte]bool{}
	for _, blob := range blobs {
		key, ok := storeKey(blob.Digest)
		if !ok {
			return fmt.Errorf("image store: %s is not a SHA-256 digest", blob.Digest)
		}
		if blob.Size <= 0 {
			return fmt.Errorf("image store: %s has no bytes", blob.Digest)
		}
		if !seen[key] {
			seen[key] = true
			all = append(all, keyed{key, blob})
		}
	}
	if len(all) > MaxStoreBlobs {
		return fmt.Errorf("image store: %d blobs, at most %d", len(all), MaxStoreBlobs)
	}
	slices.SortFunc(all, func(a, b keyed) int { return bytes.Compare(a.key[:], b.key[:]) })

	header := make([]byte, storeBlock)
	copy(header, storeMagic)
	binary.LittleEndian.PutUint64(header[16:], storeVersion)
	binary.LittleEndian.PutUint64(header[24:], uint64(len(all)))
	index := make([]byte, 0, len(all)*storeEntryOn)
	at := align(int64(storeBlock + len(all)*storeEntryOn))
	for _, blob := range all {
		index = append(index, blob.key[:]...)
		index = binary.LittleEndian.AppendUint64(index, uint64(at))
		index = binary.LittleEndian.AppendUint64(index, uint64(blob.Size))
		at = align(at + blob.Size)
	}
	written := int64(0)
	write := func(p []byte) error {
		n, err := w.Write(p)
		written += int64(n)
		return err
	}
	pad := func() error { return write(make([]byte, align(written)-written)) }
	if err := write(header); err != nil {
		return err
	}
	if err := write(index); err != nil {
		return err
	}
	for _, blob := range all {
		if err := pad(); err != nil {
			return err
		}
		rc, err := blob.Open()
		if err != nil {
			return fmt.Errorf("image store: %s: %w", blob.Digest, err)
		}
		hash := sha256.New()
		// One byte past the size, so a longer blob is seen to be longer.
		n, err := io.Copy(io.MultiWriter(w, hash), io.LimitReader(rc, blob.Size+1))
		_ = rc.Close()
		written += n
		if err != nil {
			return fmt.Errorf("image store: %s: %w", blob.Digest, err)
		}
		if n != blob.Size || !bytes.Equal(hash.Sum(nil), blob.key[:]) {
			return fmt.Errorf("image store: the bytes given for %s are not it", blob.Digest)
		}
	}
	// A whole number of blocks, as a block device has.
	return pad()
}

func align(n int64) int64 { return (n + storeBlock - 1) / storeBlock * storeBlock }
