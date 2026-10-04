// Package imagestoretest builds small OCI images and serves them from a registry
// that holds them in memory, for tests of the pull, the unpack and the runner
// and for the hardware test's image. A fixture that cannot be built is a bug
// in the caller, so these panic instead of returning errors.
package imagestoretest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Entry is one member of a layer tar.
type Entry struct {
	Header tar.Header
	Body   string
}

// Dir is a directory entry.
func Dir(name string) Entry {
	return Entry{Header: tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0o755}}
}

// File is a regular file entry holding body.
func File(name, body string) Entry {
	return Entry{Header: tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644}, Body: body}
}

// CharDevice is a character device entry. 10:257 is a number the TDX guest
// device has been seen under.
func CharDevice(name string) Entry {
	return Entry{Header: tar.Header{Name: name, Typeflag: tar.TypeChar, Mode: 0o666, Devmajor: 10, Devminor: 257}}
}

// Layer is an uncompressed layer tar holding entries.
func Layer(entries ...Entry) []byte {
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for _, e := range entries {
		e.Header.Size = int64(len(e.Body))
		must(w.WriteHeader(&e.Header))
		_, err := io.WriteString(w, e.Body)
		must(err)
	}
	must(w.Close())
	return buf.Bytes()
}

// SocketProbe is a static linux/amd64 program that asks the kernel for a
// stream socket of one address family and exits with 0, or with the error
// number the kernel answered. It is 160 bytes with no dependency, so an image
// made of one busybox can carry it and a test can tell a refused family from
// a kernel that has none: a seccomp refusal is EPERM (1), a family the kernel
// lacks is EAFNOSUPPORT (97).
func SocketProbe(family uint32) []byte {
	const base, headers = 0x400000, 64 + 56
	code := []byte{
		0xbf, 0, 0, 0, 0, // mov edi, family
		0xbe, 1, 0, 0, 0, // mov esi, SOCK_STREAM
		0x31, 0xd2, // xor edx, edx
		0xb8, 41, 0, 0, 0, // mov eax, SYS_socket
		0x0f, 0x05, // syscall
		0x48, 0x85, 0xc0, // test rax, rax
		0x78, 0x04, // js failed
		0x31, 0xff, // xor edi, edi
		0xeb, 0x05, // jmp exit
		0x48, 0xf7, 0xd8, // failed: neg rax
		0x89, 0xc7, // mov edi, eax
		0xb8, 60, 0, 0, 0, // exit: mov eax, SYS_exit
		0x0f, 0x05, // syscall
	}
	binary.LittleEndian.PutUint32(code[1:], family)
	size := uint64(headers + len(code))

	elf := make([]byte, 0, size)
	elf = append(elf, 0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0) // 64-bit, little-endian, System V
	le := binary.LittleEndian
	elf = le.AppendUint16(elf, 2)            // e_type: executable
	elf = le.AppendUint16(elf, 0x3e)         // e_machine: x86-64
	elf = le.AppendUint32(elf, 1)            // e_version
	elf = le.AppendUint64(elf, base+headers) // e_entry
	elf = le.AppendUint64(elf, 64)           // e_phoff
	elf = le.AppendUint64(elf, 0)            // e_shoff
	elf = le.AppendUint32(elf, 0)            // e_flags
	elf = le.AppendUint16(elf, 64)           // e_ehsize
	elf = le.AppendUint16(elf, 56)           // e_phentsize
	elf = le.AppendUint16(elf, 1)            // e_phnum
	elf = le.AppendUint16(elf, 64)           // e_shentsize
	elf = le.AppendUint16(elf, 0)            // e_shnum
	elf = le.AppendUint16(elf, 0)            // e_shstrndx
	elf = le.AppendUint32(elf, 1)            // p_type: load
	elf = le.AppendUint32(elf, 5)            // p_flags: read, execute
	elf = le.AppendUint64(elf, 0)            // p_offset
	elf = le.AppendUint64(elf, base)         // p_vaddr
	elf = le.AppendUint64(elf, base)         // p_paddr
	elf = le.AppendUint64(elf, size)         // p_filesz
	elf = le.AppendUint64(elf, size)         // p_memsz
	elf = le.AppendUint64(elf, 0x1000)       // p_align
	return append(elf, code...)
}

// Address families a SocketProbe in a BusyboxLayer asks for.
const (
	afInet  = 2
	afVsock = 40
)

// BusyboxApplets are the commands a BusyboxLayer links to its one binary.
var BusyboxApplets = []string{
	"sh", "sleep", "cat", "id", "ls", "ps", "stat", "mknod", "hostname", "grep", "kill", "true", "pwd", "env", "wc",
	"mount", "unshare", "nc", "wget", "ip", "mkdir",
}

// BusyboxLayer is a root filesystem made of one static busybox, plus what
// isolation tests look for: a file owned by another user, two device entries
// carrying the TDX guest device's number, and two socket probes, one for a
// family every sandbox has (bin/socket-inet) and one for vsock, which leads
// to the host (bin/socket-vsock). extra entries come last.
func BusyboxLayer(busybox []byte, extra ...Entry) []byte {
	entries := []Entry{
		Dir("bin"),
		{Header: tar.Header{Name: "bin/busybox", Typeflag: tar.TypeReg, Mode: 0o755}, Body: string(busybox)},
		{Header: tar.Header{Name: "bin/socket-inet", Typeflag: tar.TypeReg, Mode: 0o755}, Body: string(SocketProbe(afInet))},
		{Header: tar.Header{Name: "bin/socket-vsock", Typeflag: tar.TypeReg, Mode: 0o755}, Body: string(SocketProbe(afVsock))},
	}
	for _, applet := range BusyboxApplets {
		entries = append(entries, Entry{Header: tar.Header{Name: "bin/" + applet, Typeflag: tar.TypeSymlink, Linkname: "busybox", Mode: 0o777}})
	}
	entries = append(entries,
		Dir("etc"),
		File("etc/passwd", "root:x:0:0:root:/:/bin/sh\napp:x:1000:1000:app:/home/app:/bin/sh\n"),
		Dir("srv"), CharDevice("srv/tdx_guest"),
		Dir("dev"), CharDevice("dev/tdx_guest"),
		Entry{Header: tar.Header{Name: "tmp", Typeflag: tar.TypeDir, Mode: 0o1777}},
		Dir("home"),
		Entry{Header: tar.Header{Name: "home/app", Typeflag: tar.TypeDir, Mode: 0o750, Uid: 1000, Gid: 1000}},
		Entry{Header: tar.Header{Name: "home/app/data", Typeflag: tar.TypeReg, Mode: 0o600, Uid: 1000, Gid: 1000}, Body: "mine\n"},
	)
	return Layer(append(entries, extra...)...)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// Blob is what the registry serves for one digest.
type Blob struct {
	MediaType string
	Data      []byte
}

// Registry is an OCI registry over plain HTTP that holds its blobs in memory.
// It serves whatever bytes it holds for a digest, which is how a test plays a
// registry that lies.
type Registry struct {
	// Host is the registry's address as its client reaches it.
	Host  string
	Blobs map[digest.Digest]Blob
	// Padding is appended to every GET body, past the blob's real length.
	Padding []byte
	// HeadWithoutLength leaves Content-Length off HEAD responses, which sends
	// the resolver down its fetch-to-find-out path.
	HeadWithoutLength bool
	// Requests counts the requests the registry was sent.
	Requests atomic.Int64
	// Serving, when set, is called before the body of a blob is sent.
	Serving func(digest.Digest)
}

// NewRegistry starts a registry on a loopback port for the life of the test.
func NewRegistry(t testing.TB) *Registry {
	r := &Registry{Blobs: map[digest.Digest]Blob{}}
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	r.Host = strings.TrimPrefix(srv.URL, "http://")
	return r
}

func (r *Registry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.Requests.Add(1)
	if req.URL.Path == "/v2/" {
		w.WriteHeader(http.StatusOK)
		return
	}
	i := strings.LastIndex(req.URL.Path, "/")
	b, ok := r.Blobs[digest.Digest(req.URL.Path[i+1:])]
	if !ok || !strings.HasPrefix(req.URL.Path, "/v2/") {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", b.MediaType)
	w.Header().Set("Docker-Content-Digest", req.URL.Path[i+1:])
	if req.Method == http.MethodHead {
		if !r.HeadWithoutLength {
			w.Header().Set("Content-Length", strconv.Itoa(len(b.Data)))
		}
		return
	}
	if r.Serving != nil {
		r.Serving(digest.Digest(req.URL.Path[i+1:]))
	}
	if len(r.Padding) == 0 {
		w.Header().Set("Content-Length", strconv.Itoa(len(b.Data)))
	}
	_, _ = w.Write(b.Data)
	_, _ = w.Write(r.Padding)
}

// Ref is a reference to the image at d, pinned by that digest.
func (r *Registry) Ref(d digest.Digest) string { return r.Host + "/test/app@" + d.String() }

// Put stores data under its own digest.
func (r *Registry) Put(mediaType string, data []byte) ocispec.Descriptor {
	d := digest.FromBytes(data)
	r.Blobs[d] = Blob{mediaType, data}
	return ocispec.Descriptor{MediaType: mediaType, Digest: d, Size: int64(len(data))}
}

// PutJSON stores v's JSON encoding under its own digest.
func (r *Registry) PutJSON(mediaType string, v any) ocispec.Descriptor {
	data, err := json.Marshal(v)
	must(err)
	return r.Put(mediaType, data)
}

// ImageOptions departs from the truthful linux/amd64 image Image builds.
type ImageOptions struct {
	Arch      string
	LayerType string
	// DiffIDs replaces the layer ids the config would truthfully carry.
	DiffIDs []digest.Digest
	// Config replaces the default process settings.
	Config *ocispec.ImageConfig
}

// Image stores a one-manifest image built from uncompressed layer tars and
// returns the manifest's descriptor.
func (r *Registry) Image(layers [][]byte, o ImageOptions) ocispec.Descriptor {
	if o.Arch == "" {
		o.Arch = "amd64"
	}
	if o.LayerType == "" {
		o.LayerType = ocispec.MediaTypeImageLayerGzip
	}
	config := ocispec.Image{
		Platform: ocispec.Platform{OS: "linux", Architecture: o.Arch},
		Config:   ocispec.ImageConfig{Env: []string{"A=b"}, Entrypoint: []string{"/bin/app"}, Cmd: []string{"serve"}, WorkingDir: "/srv"},
		RootFS:   ocispec.RootFS{Type: "layers"},
	}
	if o.Config != nil {
		config.Config = *o.Config
	}
	var descs []ocispec.Descriptor
	for _, tarBytes := range layers {
		config.RootFS.DiffIDs = append(config.RootFS.DiffIDs, digest.FromBytes(tarBytes))
		descs = append(descs, r.Put(o.LayerType, gzipped(tarBytes)))
	}
	if o.DiffIDs != nil {
		config.RootFS.DiffIDs = o.DiffIDs
	}
	desc := r.PutJSON(ocispec.MediaTypeImageManifest, ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    r.PutJSON(ocispec.MediaTypeImageConfig, config),
		Layers:    descs,
	})
	desc.Platform = &ocispec.Platform{OS: "linux", Architecture: o.Arch}
	return desc
}

func gzipped(data []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err := w.Write(data)
	must(err)
	must(w.Close())
	return buf.Bytes()
}
