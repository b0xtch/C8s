// Command sandboximage serves the sandbox images of the session TD hardware
// suite: a static busybox, from memory, over plain HTTP. It writes the pinned
// reference of each image to a file and serves until it is killed.
//
//	sandboximage -busybox /usr/bin/busybox -listen 127.0.0.1:5000 -host 10.0.2.2:5000 -out <dir>
//
// <dir>/ref names an image the registry serves truthfully. <dir>/ref-changed
// names one whose layer was changed after its digest was taken, as a registry
// substituting content would serve it. A guest must run the first and refuse
// the second.
//
// With -store <file> it also writes both images as an image store, the file a
// launcher hands its guests with --image-store, and changes the same layer
// there once the store is written, as a host would change its own file. With
// -serve=false it writes the files and serves nothing: a guest then has the
// store alone.
package main

import (
	"archive/tar"
	"bytes"
	"debug/elf"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/confidential-dot-ai/c8s/internal/imagestore"
	"github.com/confidential-dot-ai/c8s/internal/imagestore/imagestoretest"
)

// echoPort is where the sandbox answers what it is sent. The suite reaches
// it from inside the guest and must fail to reach it from outside.
const echoPort = "9000"

func main() {
	busybox := flag.String("busybox", "/usr/bin/busybox", "static linux/amd64 busybox to build the image from")
	listen := flag.String("listen", "127.0.0.1:5000", "address to serve on")
	host := flag.String("host", "10.0.2.2:5000", "the registry's address as the guest reaches it")
	out := flag.String("out", ".", "directory for the reference files")
	store := flag.String("store", "", "also write the images as an image store, to this file")
	serve := flag.Bool("serve", true, "serve the images; false writes the files and exits")
	flag.Parse()
	if err := run(*busybox, *listen, *host, *out, *store, *serve); err != nil {
		fmt.Fprintln(os.Stderr, "sandboximage:", err)
		os.Exit(1)
	}
}

// newStore is an image store that holds blobs. A store is written from blobs
// that are what their digests say, so these are.
func newStore(blobs map[digest.Digest]imagestoretest.Blob) ([]byte, error) {
	var all []imagestore.StoreBlob
	for d, blob := range blobs {
		all = append(all, imagestore.StoreBlob{Digest: d, Size: int64(len(blob.Data)), Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(blob.Data)), nil
		}})
	}
	var store bytes.Buffer
	if err := imagestore.WriteStore(&store, all); err != nil {
		return nil, err
	}
	return store.Bytes(), nil
}

// change flips one bit in the middle of blob, where a written store holds it.
func change(store, blob []byte) error {
	at := bytes.Index(store, blob)
	if at < 0 || bytes.Contains(store[at+1:], blob) {
		return errors.New("the store does not hold the layer to change exactly once")
	}
	store[at+len(blob)/2] ^= 1
	return nil
}

func run(busyboxPath, listen, host, out, store string, serve bool) error {
	bin, err := elf.Open(busyboxPath)
	if err != nil {
		return err
	}
	dynamic := bin.Section(".interp") != nil
	bin.Close()
	if dynamic {
		return fmt.Errorf("%s is dynamically linked: the image holds nothing else", busyboxPath)
	}
	busybox, err := os.ReadFile(busyboxPath)
	if err != nil {
		return err
	}
	registry := &imagestoretest.Registry{Host: host, Blobs: map[digest.Digest]imagestoretest.Blob{}}
	config := &ocispec.ImageConfig{
		// One connection at a time, each echoed back and its end recorded.
		Cmd:        []string{"/bin/sh", "-c", "echo up > /tmp/started; : > /tmp/endings; while true; do nc -l -p " + echoPort + " -e /bin/echo-once; done"},
		Env:        []string{"FROM_IMAGE=1"},
		WorkingDir: "/srv",
	}
	// cat ends with 0 when its input ended in order, and with something else
	// when the connection failed under it. The suite reads which.
	echo := imagestoretest.Entry{
		Header: tar.Header{Name: "bin/echo-once", Typeflag: tar.TypeReg, Mode: 0o755},
		Body:   "#!/bin/sh\ncat\necho $? >> /tmp/endings\n",
	}
	good := registry.Image([][]byte{imagestoretest.BusyboxLayer(busybox, echo)}, imagestoretest.ImageOptions{Config: config})
	whole := maps.Clone(registry.Blobs)

	// A layer of its own, so changing it leaves the first image whole.
	layer := imagestoretest.BusyboxLayer(busybox, echo, imagestoretest.File("srv/marker", "changed\n"))
	changed := registry.Image([][]byte{layer}, imagestoretest.ImageOptions{Config: config})
	var held []byte
	if store != "" {
		var err error
		if held, err = newStore(registry.Blobs); err != nil {
			return fmt.Errorf("write the image store: %w", err)
		}
	}
	for d, blob := range registry.Blobs {
		if _, keep := whole[d]; keep || blob.MediaType != ocispec.MediaTypeImageLayerGzip {
			continue
		}
		if held != nil {
			if err := change(held, blob.Data); err != nil {
				return err
			}
		}
		// Same length, one bit changed: only the digest can tell.
		blob.Data = bytes.Clone(blob.Data)
		blob.Data[len(blob.Data)/2] ^= 1
		registry.Blobs[d] = blob
	}
	if held != nil {
		if err := os.WriteFile(store, held, 0o644); err != nil {
			return err
		}
	}

	refs := func() error {
		for name, desc := range map[string]ocispec.Descriptor{"ref": good, "ref-changed": changed} {
			if err := os.WriteFile(filepath.Join(out, name), []byte(registry.Ref(desc.Digest)+"\n"), 0o644); err != nil {
				return err
			}
		}
		return nil
	}
	if !serve {
		return refs()
	}
	// Listening comes first: the reference files tell the suite that the
	// images are being served.
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	if err := refs(); err != nil {
		return err
	}
	fmt.Printf("sandboximage: serving %s and %s on %s as %s\n", good.Digest, changed.Digest, ln.Addr(), host)
	srv := &http.Server{Handler: registry, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
