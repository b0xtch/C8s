//go:build unix

package imagestore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/containerd/v2/pkg/archive/compression"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/platforms"
	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// maxTrailingBytes is how much a layer may carry after its last tar entry.
// A well-formed archive ends in a few kilobytes of zero padding.
const maxTrailingBytes = 1 << 20

// Platform is the one platform a session guest runs.
var Platform = ocispec.Platform{OS: "linux", Architecture: "amd64"}

// tarLayerTypes are the layers the unpacker understands: a tar stream, plain
// or compressed.
var tarLayerTypes = map[string]bool{
	ocispec.MediaTypeImageLayer:            true,
	ocispec.MediaTypeImageLayerGzip:        true,
	ocispec.MediaTypeImageLayerZstd:        true,
	images.MediaTypeDockerSchema2Layer:     true,
	images.MediaTypeDockerSchema2LayerGzip: true,
	images.MediaTypeDockerSchema2LayerZstd: true,
}

// PullLimits bounds one pull. A blob larger than BlobBytes, or an image whose
// blobs add up to more than TotalBytes, is refused from its declared size
// before it is fetched. The network read is bounded separately, at one byte
// past BlobBytes per response and TotalBytes plus BlobBytes in all, because
// the registry client reads some bodies before it knows their size.
type PullLimits struct {
	Layers     int
	BlobBytes  int64
	TotalBytes int64
}

var errNetworkBudget = errors.New("the registry sent more than this pull may read")

// Puller fetches images into a content store on the guest's scratch volume.
type Puller struct {
	StoreDir string
	Limits   PullLimits
	// PlainHTTP reports whether host is reached without TLS. Transport gives
	// no integrity either way: every blob is checked against its digest.
	PlainHTTP func(host string) bool
	Client    *http.Client
	// Images, when set, is the host's image store. A blob it holds is read
	// from there, and checked as one from a registry is. A nil store holds
	// nothing.
	Images *Store
	// ImagesOnly asks no registry: what the store does not hold fails the
	// pull. A guest that belongs to nobody yet has no business on a network.
	ImagesOnly bool
}

// maxRootBytes bounds each document of an image: its index, its manifest and
// its config. They are read whole into memory, the first of them before it is
// known to be one.
const maxRootBytes = 4 << 20

// Image is a fetched image whose every blob matched the digest that named it,
// starting from the digest in the reference.
type Image struct {
	// Digest is the digest the reference pinned.
	Digest digest.Digest
	Config ocispec.Image
	// Resolved is how long the registry took to say what it holds under the
	// reference, and Fetched how long its blobs took to arrive and be checked.
	Resolved, Fetched time.Duration
	// FromStore and FromRegistry count the blobs each of them supplied.
	FromStore, FromRegistry int

	// blobs are all of the image's blobs, in the order they were reached.
	blobs  []ocispec.Descriptor
	layers []ocispec.Descriptor
	store  content.Store
	// dir is the content store's directory.
	dir string
}

// blobPath is where a content store in dir keeps the blob d.
func blobPath(dir string, d digest.Digest) string {
	return filepath.Join(dir, "blobs", d.Algorithm().String(), d.Encoded())
}

// Blobs returns everything the image is made of, as a store holds it: the
// manifest or index its reference names, and all that follows from it for
// this platform.
func (img *Image) Blobs(ctx context.Context) []StoreBlob {
	out := make([]StoreBlob, len(img.blobs))
	for i, desc := range img.blobs {
		out[i] = StoreBlob{Digest: desc.Digest, Size: desc.Size, Open: func() (io.ReadCloser, error) {
			at, err := img.store.ReaderAt(ctx, desc)
			if err != nil {
				return nil, err
			}
			return struct {
				io.Reader
				io.Closer
			}{content.NewReader(at), at}, nil
		}}
	}
	return out
}

// Pull fetches ref, which must be pinned as name@sha256:<digest>.
func (p *Puller) Pull(ctx context.Context, ref string) (*Image, error) {
	if p.Limits.Layers <= 0 || p.Limits.BlobBytes <= 0 || p.Limits.TotalBytes <= 0 {
		return nil, errors.New("pull limits must be positive")
	}
	named, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return nil, fmt.Errorf("image reference: %w", err)
	}
	pinned, ok := named.(reference.Canonical)
	if !ok {
		return nil, fmt.Errorf("image reference %q is not pinned by digest", ref)
	}
	base := p.Client
	if base == nil {
		base = &http.Client{Timeout: 10 * time.Minute}
	}
	left := new(atomic.Int64)
	left.Store(p.Limits.TotalBytes + p.Limits.BlobBytes)
	client := *base
	client.Transport = budgetTransport{next: base.Transport, perBody: p.Limits.BlobBytes + 1, left: left}
	resolver := docker.NewResolver(docker.ResolverOptions{Hosts: docker.ConfigureDefaultRegistries(
		docker.WithClient(&client),
		docker.WithAuthorizer(docker.NewDockerAuthorizer(docker.WithAuthClient(&client))),
		docker.WithPlainHTTP(func(host string) (bool, error) { return p.PlainHTTP != nil && p.PlainHTTP(host), nil }),
	)})
	store, err := local.NewStore(p.StoreDir)
	if err != nil {
		return nil, fmt.Errorf("open content store: %w", err)
	}
	// name is what the registry is asked for blobs under.
	name := named.String()
	source := &blobSource{images: p.Images, only: p.ImagesOnly}
	source.registry = sync.OnceValues(func() (remotes.Fetcher, error) { return resolver.Fetcher(ctx, name) })
	began := time.Now()
	var root ocispec.Descriptor
	if size, ok := p.Images.Size(pinned.Digest()); ok {
		// The reference names its manifest by digest, so nobody has to be
		// asked what it is.
		if root, err = p.rootFromImages(ctx, store, pinned.Digest(), size); err != nil {
			return nil, err
		}
		source.fromStore.Add(1)
	} else if p.ImagesOnly {
		return nil, fmt.Errorf("the host's image store does not hold %s", named)
	} else {
		if name, root, err = resolver.Resolve(ctx, named.String()); err != nil {
			return nil, fmt.Errorf("resolve %s: %w", named, err)
		}
		if root.Digest != pinned.Digest() {
			return nil, fmt.Errorf("registry answered %s for an image pinned at %s", root.Digest, pinned.Digest())
		}
	}
	resolved := time.Since(began)

	matcher := platforms.OnlyStrict(Platform)
	budget := &pullBudget{limits: p.Limits}
	docs := checked{store}
	handler := images.Handlers(
		images.HandlerFunc(budget.admit),
		remotes.FetchHandler(store, boundedFetcher{source}),
		// The store synced the layer as it kept it. It is read once more, to
		// be unpacked, and the pages its writing left are of no use to that.
		images.HandlerFunc(func(_ context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
			if tarLayerTypes[desc.MediaType] {
				forgetPath(blobPath(p.StoreDir, desc.Digest))
			}
			return nil, nil
		}),
		images.LimitManifests(images.FilterPlatforms(images.ChildrenHandler(docs), matcher), matcher, 1),
	)
	// Walk is sequential, so the budget needs no lock and a refusal stops the
	// pull at the first blob that exceeds it.
	began = time.Now()
	if err := images.Walk(ctx, handler, root); err != nil {
		return nil, fmt.Errorf("fetch %s: %w", named, err)
	}
	fetched := time.Since(began)

	manifest, err := images.Manifest(ctx, docs, root, matcher)
	if err != nil {
		return nil, fmt.Errorf("image manifest: %w", err)
	}
	if len(manifest.Layers) == 0 || len(manifest.Layers) > p.Limits.Layers {
		return nil, fmt.Errorf("image has %d layers, want 1..%d", len(manifest.Layers), p.Limits.Layers)
	}
	raw, err := content.ReadBlob(ctx, docs, manifest.Config)
	if err != nil {
		return nil, fmt.Errorf("image config: %w", err)
	}
	var config ocispec.Image
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, fmt.Errorf("image config: %w", err)
	}
	if !matcher.Match(config.Platform) {
		return nil, fmt.Errorf("image is built for %s/%s, the guest runs %s/%s", config.OS, config.Architecture, Platform.OS, Platform.Architecture)
	}
	if config.RootFS.Type != "layers" || len(config.RootFS.DiffIDs) != len(manifest.Layers) {
		return nil, fmt.Errorf("image config lists %d layer ids for %d layers", len(config.RootFS.DiffIDs), len(manifest.Layers))
	}
	return &Image{
		Digest: pinned.Digest(), Config: config, Resolved: resolved, Fetched: fetched,
		FromStore: int(source.fromStore.Load()), FromRegistry: int(source.fromRegistry.Load()),
		blobs: budget.admitted, layers: manifest.Layers, store: store, dir: p.StoreDir,
	}, nil
}

// rootFromImages takes the manifest or index named d from the host's store:
// read once, checked against d, and only then looked at, to see which of the
// two it is. It is put into the content store, so the walk reads it there.
func (p *Puller) rootFromImages(ctx context.Context, cs content.Store, d digest.Digest, size int64) (ocispec.Descriptor, error) {
	if size > min(maxRootBytes, p.Limits.BlobBytes) {
		return ocispec.Descriptor{}, fmt.Errorf("the image store holds %d bytes for %s, which is no manifest", size, d)
	}
	blob, _ := p.Images.Blob(d)
	data, err := io.ReadAll(blob)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("read %s from the image store: %w", d, err)
	}
	if got := digest.FromBytes(data); got != d {
		return ocispec.Descriptor{}, fmt.Errorf("the image store holds %s where it lists %s", got, d)
	}
	mediaType, err := rootType(data)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("%s: %w", d, err)
	}
	root := ocispec.Descriptor{MediaType: mediaType, Digest: d, Size: int64(len(data))}
	if err := content.WriteBlob(ctx, cs, "root-"+d.String(), bytes.NewReader(data), root); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("keep %s: %w", d, err)
	}
	return root, nil
}

// rootType tells a manifest from an index. A registry says which in a header;
// here the document says it itself, by its mediaType or else by its shape.
// One that could be read either way is neither: the same digest must not name
// an index to this guest and a manifest to whoever verifies it. The rule is
// containerd's for a document whose type it was told.
func rootType(data []byte) (string, error) {
	var doc struct {
		MediaType string            `json:"mediaType"`
		Manifests []json.RawMessage `json:"manifests"`
		Config    json.RawMessage   `json:"config"`
		Layers    []json.RawMessage `json:"layers"`
		FSLayers  []json.RawMessage `json:"fsLayers"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return "", fmt.Errorf("neither a manifest nor an index: %w", err)
	}
	manifest, index := len(doc.Config) > 0 || len(doc.Layers) > 0, len(doc.Manifests) > 0
	switch {
	case len(doc.FSLayers) > 0:
		return "", errors.New("a schema 1 manifest, which names its layers by no verified id")
	case manifest && index:
		return "", errors.New("it has a manifest's members and an index's")
	case images.IsManifestType(doc.MediaType) && index, images.IsIndexType(doc.MediaType) && manifest:
		return "", fmt.Errorf("it says it is %s and has the members of the other kind", doc.MediaType)
	case images.IsManifestType(doc.MediaType), images.IsIndexType(doc.MediaType):
		return doc.MediaType, nil
	case doc.MediaType != "":
		return "", fmt.Errorf("unsupported media type %q", doc.MediaType)
	case len(doc.Config) > 0:
		return ocispec.MediaTypeImageManifest, nil
	case index:
		return ocispec.MediaTypeImageIndex, nil
	}
	return "", errors.New("neither a manifest nor an index")
}

// checked reads an image's documents back from the content store: its index,
// its manifest and its config. The store checked each against its digest as
// it was written, onto a volume whose sectors the host can change afterwards,
// so each is checked again when it is read, and only then believed. What it
// reads, the pull's budget admitted as a document.
type checked struct{ content.Provider }

func (c checked) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	if err := desc.Digest.Validate(); err != nil {
		return nil, err
	}
	at, err := c.Provider.ReaderAt(ctx, desc)
	if err != nil {
		return nil, err
	}
	defer at.Close()
	data := make([]byte, desc.Size)
	if n, err := at.ReadAt(data, 0); n != len(data) {
		return nil, fmt.Errorf("the content store holds %d bytes of %s, which is %d bytes: %v", n, desc.Digest, desc.Size, err)
	}
	if got := desc.Digest.Algorithm().FromBytes(data); got != desc.Digest {
		return nil, fmt.Errorf("the content store holds %s where it kept %s: the volume under it was changed", got, desc.Digest)
	}
	// The digest fixes the bytes, and the bytes must mean one thing: to this
	// guest and to whoever else reads the image under that digest.
	if err := exactMembers(data, documentType(desc.MediaType)); err != nil {
		return nil, fmt.Errorf("%s: %w", desc.Digest, err)
	}
	return document{bytes.NewReader(data)}, nil
}

// document is a blob held in memory.
type document struct{ *bytes.Reader }

func (document) Close() error { return nil }

// blobSource fetches a blob from the host's image store when the store holds
// it, and from the registry otherwise. Either way the content store checks
// what arrives against the digest that named it.
type blobSource struct {
	images *Store
	only   bool
	// registry is made on the first blob that needs it.
	registry func() (remotes.Fetcher, error)

	fromStore, fromRegistry atomic.Int64
}

func (s *blobSource) Fetch(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	if size, ok := s.images.Size(desc.Digest); ok {
		// The size is the one the blob's parent declared, and the parent is
		// verified. A store that says otherwise does not hold this blob.
		if size != desc.Size {
			return nil, fmt.Errorf("the image store holds %d bytes for %s, which is %d bytes", size, desc.Digest, desc.Size)
		}
		blob, _ := s.images.Blob(desc.Digest)
		s.fromStore.Add(1)
		return io.NopCloser(blob), nil
	}
	if s.only {
		return nil, fmt.Errorf("the host's image store does not hold %s", desc.Digest)
	}
	fetcher, err := s.registry()
	if err != nil {
		return nil, err
	}
	s.fromRegistry.Add(1)
	return fetcher.Fetch(ctx, desc)
}

// Unpack applies the image's layers in order. Each layer's uncompressed bytes
// must hash to the id the image config gives it.
func (img *Image) Unpack(ctx context.Context, u *Unpacker) error {
	for i, desc := range img.layers {
		if err := img.unpackLayer(ctx, u, desc, img.Config.RootFS.DiffIDs[i]); err != nil {
			return fmt.Errorf("layer %d: %w", i, err)
		}
	}
	return nil
}

func (img *Image) unpackLayer(ctx context.Context, u *Unpacker, desc ocispec.Descriptor, diffID digest.Digest) error {
	if err := diffID.Validate(); err != nil {
		return fmt.Errorf("layer id: %w", err)
	}
	blob, err := img.store.ReaderAt(ctx, desc)
	if err != nil {
		return err
	}
	defer blob.Close()
	// Read once, and dropped from the page cache as it goes.
	read, done := forgetting(content.NewReader(blob), blobPath(img.dir, desc.Digest))
	defer done()
	stream, err := compression.DecompressStream(read)
	if err != nil {
		return err
	}
	defer stream.Close()
	hash := diffID.Algorithm().Hash()
	tee := io.TeeReader(stream, hash)
	if err := u.Apply(ctx, tee); err != nil {
		return err
	}
	// The tar reader stops at the end-of-archive marker. The id covers the
	// whole stream, so read out what follows, within a bound.
	n, err := io.Copy(io.Discard, io.LimitReader(tee, maxTrailingBytes+1))
	if err != nil {
		return err
	}
	if n > maxTrailingBytes {
		return fmt.Errorf("more than %d bytes follow the archive", maxTrailingBytes)
	}
	if got := digest.NewDigest(diffID.Algorithm(), hash); got != diffID {
		return fmt.Errorf("uncompressed layer is %s, the image config says %s", got, diffID)
	}
	return nil
}

// pullBudget refuses a blob before it is fetched, from the size and type its
// parent declared.
type pullBudget struct {
	limits PullLimits
	total  int64
	// admitted are the blobs let through, in order.
	admitted []ocispec.Descriptor
}

func (b *pullBudget) admit(_ context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	switch {
	case images.IsIndexType(desc.MediaType), images.IsManifestType(desc.MediaType),
		images.IsConfigType(desc.MediaType), tarLayerTypes[desc.MediaType]:
	default:
		// Among the refused: encrypted, EROFS and non-distributable layers.
		return nil, fmt.Errorf("unsupported media type %q", desc.MediaType)
	}
	if len(desc.URLs) > 0 {
		return nil, fmt.Errorf("%s is to be fetched from outside the registry", desc.Digest)
	}
	if !tarLayerTypes[desc.MediaType] && desc.Size > maxRootBytes {
		return nil, fmt.Errorf("%s declares %d bytes, and a manifest, index or config is at most %d", desc.Digest, desc.Size, maxRootBytes)
	}
	if desc.Size <= 0 || desc.Size > b.limits.BlobBytes {
		return nil, fmt.Errorf("%s declares %d bytes, limit %d", desc.Digest, desc.Size, b.limits.BlobBytes)
	}
	if desc.Size > b.limits.TotalBytes-b.total {
		return nil, fmt.Errorf("image is larger than %d bytes", b.limits.TotalBytes)
	}
	b.total += desc.Size
	b.admitted = append(b.admitted, desc)
	return nil, nil
}

// budgetTransport caps what a pull reads off the network, whichever part of
// the registry client does the reading. The resolver, for one, reads a whole
// manifest body before checking its size when a HEAD carries no length.
type budgetTransport struct {
	next    http.RoundTripper
	perBody int64
	left    *atomic.Int64
}

func (t budgetTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	next := t.next
	if next == nil {
		next = http.DefaultTransport
	}
	resp, err := next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &budgetBody{ReadCloser: resp.Body, room: t.perBody, left: t.left}
	return resp, nil
}

type budgetBody struct {
	io.ReadCloser
	room int64
	left *atomic.Int64
}

func (b *budgetBody) Read(p []byte) (int, error) {
	if b.room <= 0 || b.left.Load() <= 0 {
		return 0, errNetworkBudget
	}
	if int64(len(p)) > b.room {
		p = p[:b.room]
	}
	n, err := b.ReadCloser.Read(p)
	b.room -= int64(n)
	b.left.Add(-int64(n))
	return n, err
}

// boundedFetcher cuts a body off one byte past its declared size. The content
// store checks size and digest only after it has written everything it was
// sent, so an unbounded body would fill the disk first.
type boundedFetcher struct{ remotes.Fetcher }

func (f boundedFetcher) Fetch(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	rc, err := f.Fetcher.Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}
	return struct {
		io.Reader
		io.Closer
	}{io.LimitReader(rc, desc.Size+1), rc}, nil
}
