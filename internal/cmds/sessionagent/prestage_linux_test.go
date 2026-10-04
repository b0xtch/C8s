//go:build linux

package sessionagent_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
	"github.com/confidential-dot-ai/c8s/internal/imagestore"
	"github.com/confidential-dot-ai/c8s/internal/imagestore/imagestoretest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// These run a guest's agent with a real container runtime and a host's
// image store, as root: see containerFixtures.

// elsewhere names an image at a registry that does not exist. An agent that
// reaches for the registry fails.
func elsewhere(d digest.Digest) string { return "127.0.0.1:1/staged/app@" + d.String() }

// staged is a guest whose agent runs sandbox images under crun, in front
// of a registry that holds two images, "a" and "b".
type staged struct {
	*pool
	registry *imagestoretest.Registry
	image    map[string]ocispec.Descriptor
	stateDir string
	// cgroup is the agent's delegated cgroup: the container's is below it.
	cgroup string
	images *sessionagent.ImageRunner
}

type stagedOptions struct {
	// stored names the images the host's store holds. None means no store.
	stored []string
	// prestage names the images the pool document lists.
	prestage []string
	// reachable lists them under the registry's own name, where an agent
	// that asked would get them.
	reachable bool
	// damage changes the store's bytes before the guest gets it.
	damage func(store []byte, s *staged)
	// hold keeps the store from answering the guest until it is closed.
	hold <-chan struct{}
}

// heldStore is a store whose reads wait for its host, once the store has
// been opened.
type heldStore struct {
	io.ReaderAt
	opened atomic.Bool
	hold   <-chan struct{}
}

func (h *heldStore) ReadAt(p []byte, off int64) (int, error) {
	if h.opened.Load() {
		<-h.hold
	}
	return h.ReaderAt.ReadAt(p, off)
}

func newStaged(t *testing.T, o stagedOptions) *staged {
	t.Helper()
	crun, busybox := containerFixtures(t)
	s := &staged{registry: imagestoretest.NewRegistry(t), image: map[string]ocispec.Descriptor{}}
	for _, name := range []string{"a", "b"} {
		config := ocispec.ImageConfig{Cmd: []string{"/bin/sleep", "100000"}, Env: []string{"WHICH=" + name}}
		s.image[name] = s.registry.Image([][]byte{imagestoretest.BusyboxLayer(busybox, imagestoretest.File("which", name))}, imagestoretest.ImageOptions{Config: &config})
	}
	var images *imagestore.Store
	if len(o.stored) > 0 {
		// A store is written from what a pull of each image was made of.
		var blobs []imagestore.StoreBlob
		content := filepath.Join(t.TempDir(), "content")
		for _, name := range o.stored {
			puller := &imagestore.Puller{StoreDir: content, PlainHTTP: func(string) bool { return true }, Limits: imagestore.PullLimits{Layers: 4, BlobBytes: 64 << 20, TotalBytes: 128 << 20}}
			img, err := puller.Pull(context.Background(), s.registry.Ref(s.image[name].Digest))
			if err != nil {
				t.Fatal(err)
			}
			blobs = append(blobs, img.Blobs(context.Background())...)
		}
		var store bytes.Buffer
		if err := imagestore.WriteStore(&store, blobs); err != nil {
			t.Fatal(err)
		}
		data := store.Bytes()
		if o.damage != nil {
			o.damage(data, s)
		}
		var err error
		reader := &heldStore{ReaderAt: bytes.NewReader(data), hold: o.hold}
		if images, err = imagestore.OpenStore(reader, int64(len(data))); err != nil {
			t.Fatal(err)
		}
		reader.opened.Store(o.hold != nil)
	}
	s.pool = newPoolWith(t, func(b *session.BundleOptions) {
		for _, name := range o.prestage {
			ref := elsewhere(s.image[name].Digest)
			if o.reachable {
				ref = s.registry.Ref(s.image[name].Digest)
			}
			b.Prestage = append(b.Prestage, ref)
		}
	})
	s.images, s.stateDir, s.cgroup = imageRunner(t, s.harness, crun, images)
	// What the registry was sent to build the store is not the guest's doing.
	s.registry.Requests.Store(0)
	s.start(t)
	return s
}

// settled waits for the unpacking ahead to end by itself and returns what it
// left on the guest's disk, by digest.
func (s *staged) settled(t *testing.T) []string {
	t.Helper()
	if done := s.images.AheadDone(); done != nil {
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatal("the unpacking ahead did not end")
		}
	}
	trees, err := filepath.Glob(filepath.Join(s.stateDir, "prestaged", "*"))
	if err != nil {
		t.Fatal(err)
	}
	for i, tree := range trees {
		trees[i] = "sha256:" + filepath.Base(tree)
	}
	return trees
}

// bound binds the guest to an image, by the reference given, and returns the
// guest's account of the admission and the tenant's client.
func (s *staged) bound(t *testing.T, image string) (string, *session.Client) {
	t.Helper()
	client := s.client(t, s.access)
	ready, err := client.Ready(ctxT(t))
	if err != nil {
		t.Fatalf("Unbound: %v", err)
	}
	bind := s.bindFor(t, ready, func(o *session.BindOptions) { o.Policy.Sandbox = &session.Sandbox{Image: image} })
	resp, err := client.Bind(ctxT(t), bind)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	return stepNames(resp.Admission), s.boundClient(t, ready, bind)
}

func (s *staged) which(t *testing.T, tenant *session.Client) string {
	t.Helper()
	out, err := tenant.Exec(ctxT(t), session.ExecRequest{Argv: []string{"/bin/sh", "-c", `cat /which; echo " $WHICH"`}})
	if err != nil || out.ExitCode != 0 {
		t.Fatalf("exec = %+v, %v", out, err)
	}
	return strings.TrimSpace(string(out.Stdout))
}

// gone waits for what was unpacked ahead and not bound to be removed.
func (s *staged) gone(t *testing.T) {
	t.Helper()
	dir := filepath.Join(s.stateDir, "prestaged")
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return
		}
	}
	t.Errorf("%s is still there after the bind", dir)
}

// A guest says when it is done with the images its document lists, and not
// before: its host offers it to a tenant on that word, so that the tenant's
// bind waits for no unpack.
func TestGuestSaysWhenItsImagesAreUnpacked(t *testing.T) {
	hold := make(chan struct{})
	release := sync.OnceFunc(func() { close(hold) })
	// Whatever happens, the guest is let go before it is torn down.
	defer release()
	s := newStaged(t, stagedOptions{stored: []string{"a", "b"}, prestage: []string{"a", "b"}, hold: hold})
	if s.state(t).Prepared {
		t.Fatal("the guest says it is done with images its host has not let it read")
	}
	release()
	for deadline := time.Now().Add(30 * time.Second); !s.state(t).Prepared; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the guest never said it was done with its images")
		}
	}
	// Said, both trees are there and nothing is still under way: the first
	// image's under the container made for it, the other where it was
	// unpacked.
	trees, err := filepath.Glob(filepath.Join(s.stateDir, "prestaged", "*", "rootfs", "which"))
	if err != nil || len(trees) != 1 {
		t.Fatalf("the guest said it was done with %v unpacked ahead, %v", trees, err)
	}
	if _, err := os.Stat(filepath.Join(s.stateDir, "rootfs", "which")); err != nil {
		t.Fatalf("the guest said it was done, and the first image's container has no root: %v", err)
	}
}

// An image the pool document lists is unpacked from the host's store before
// any tenant arrives. A bind that names it has nothing to fetch and nothing
// to unpack: it measures the image and starts it. No registry is asked,
// before the bind or at it: the references here lead to none. The bind comes
// at once, while the unpacking is under way, and waits for the tree it names:
// the second of two.
func TestImageUnpackedAheadStartsAtTheBind(t *testing.T) {
	s := newStaged(t, stagedOptions{stored: []string{"a", "b"}, prestage: []string{"a", "b"}})
	// Asked a second time, the runner goes on with what it began.
	s.images.Prestage(context.Background(), []string{elsewhere(s.image["a"].Digest)})
	steps, tenant := s.bound(t, elsewhere(s.image["b"].Digest))
	if steps != "prestaged,measure,start" {
		t.Errorf("admission steps: %s", steps)
	}
	if got := s.which(t, tenant); got != "b b" {
		t.Errorf("the sandbox is image %q", got)
	}
	// What the bind measured is the image it named.
	att, err := tenant.Attest(ctxT(t))
	if err != nil || len(att.Events) != 3 || att.Events[2] != s.image["b"].Digest.String() {
		t.Fatalf("attestation events %v, %v", att, err)
	}
	// The other image's tree was nobody's and is removed.
	s.gone(t)
	if entries, _ := os.ReadDir(s.stateDir); len(entries) != 1 || entries[0].Name() != "rootfs" {
		t.Errorf("the state directory holds %v", entries)
	}
}

// first is the first process of the guest's container: its id on this
// machine and what it runs.
func (s *staged) first(t *testing.T) (pid int, command string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(s.cgroup, "sandbox", "cgroup.procs"))
	if err != nil {
		t.Fatalf("the container's cgroup: %v", err)
	}
	// The kernel lists a cgroup's processes in the order they came.
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		t.Fatal("the container holds no process")
	}
	if pid, err = strconv.Atoi(fields[0]); err != nil {
		t.Fatal(err)
	}
	line, err := os.ReadFile(filepath.Join("/proc", fields[0], "cmdline"))
	if err != nil {
		t.Fatal(err)
	}
	return pid, strings.TrimSpace(strings.ReplaceAll(string(line), "\x00", " "))
}

// The container of the first image a pool lists is made before any bind,
// with the sandbox's init as its process. A bind that names that image has a
// process to start and nothing else: the init becomes the image's command in
// place, or the command the bind gives, in the bind's environment, and what
// it becomes inherits nothing of the init's.
func TestContainerMadeAheadBecomesTheSandbox(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(*session.Sandbox)
		want   string
	}{
		"the image's own command": {func(*session.Sandbox) {}, "/bin/sleep 100000"},
		"a command of the bind's": {func(w *session.Sandbox) {
			w.Command, w.Args, w.Env = []string{"sleep"}, []string{"4242"}, map[string]string{"GREETING": "hello"}
		}, "sleep 4242"},
	} {
		t.Run(name, func(t *testing.T) {
			s := newStaged(t, stagedOptions{stored: []string{"a", "b"}, prestage: []string{"a", "b"}})
			s.settled(t)
			made, waiting := s.first(t)
			if !strings.HasPrefix(waiting, "/proc/self/fd/") {
				t.Fatalf("before any bind the container's first process runs %q, want the sandbox's init", waiting)
			}
			client := s.client(t, s.access)
			ready, err := client.Ready(ctxT(t))
			if err != nil {
				t.Fatal(err)
			}
			sandbox := &session.Sandbox{Image: elsewhere(s.image["a"].Digest)}
			tc.change(sandbox)
			bind := s.bindFor(t, ready, func(o *session.BindOptions) { o.Policy.Sandbox = sandbox })
			resp, err := client.Bind(ctxT(t), bind)
			if err != nil {
				t.Fatalf("Bind: %v", err)
			}
			if steps := stepNames(resp.Admission); steps != "prestaged,measure,start" {
				t.Errorf("admission steps: %s", steps)
			}
			if pid, command := s.first(t); pid != made || command != tc.want {
				t.Fatalf("after the bind the container's first process is %d running %q, want %d running %q", pid, command, made, tc.want)
			}
			tenant := s.boundClient(t, ready, bind)
			if got := s.which(t, tenant); got != "a a" {
				t.Errorf("the sandbox is image %q", got)
			}
			out, err := tenant.Exec(ctxT(t), session.ExecRequest{Argv: []string{"/bin/sh", "-c", `ls /proc/1/fd | tr '\n' ' '; tr '\0' '\n' < /proc/1/environ | grep -c GREETING`}})
			if err != nil {
				t.Fatal(err)
			}
			fields := strings.Fields(string(out.Stdout))
			greeted := "0"
			if sandbox.Env != nil {
				greeted = "1"
			}
			if want := []string{"0", "1", "2", greeted}; !slices.Equal(fields, want) {
				t.Errorf("the sandbox's process holds descriptors and a greeting %v, want %v", fields, want)
			}
			if n := s.registry.Requests.Load(); n != 0 {
				t.Errorf("the registry was sent %d requests", n)
			}
		})
	}
}

// A guest nobody binds ends with nothing of its container left: the init
// that waited is gone, and so is the tree it was made over.
func TestContainerMadeAheadEndsWithItsGuest(t *testing.T) {
	s := newStaged(t, stagedOptions{stored: []string{"a"}, prestage: []string{"a"}})
	s.settled(t)
	if _, waiting := s.first(t); !strings.HasPrefix(waiting, "/proc/self/fd/") {
		t.Fatalf("the container's first process runs %q", waiting)
	}
	if err := s.images.Close(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(s.cgroup, "sandbox", "cgroup.procs")); err == nil && len(strings.Fields(string(data))) != 0 {
		t.Fatalf("after the runner closed its container still holds %q", data)
	}
	if _, err := os.Stat(filepath.Join(s.stateDir, "rootfs")); err == nil {
		t.Error("the tree of a container nobody used is still there")
	}
}

// A bind may name any image. One that was not unpacked ahead is fetched as
// ever, and what was unpacked ahead is removed.
func TestBindOfAnImageThatWasNotUnpackedAhead(t *testing.T) {
	for name, o := range map[string]stagedOptions{
		"another image was": {stored: []string{"a"}, prestage: []string{"a"}},
		// A guest nobody has bound asks no registry, even one that would
		// answer: what its host's store lacks is not unpacked ahead.
		"the store does not hold it":   {stored: []string{"a"}, prestage: []string{"b"}, reachable: true},
		"the host gave no store":       {prestage: []string{"b"}, reachable: true},
		"the pool document lists none": {stored: []string{"a"}},
		"no store and no list":         {},
	} {
		t.Run(name, func(t *testing.T) {
			s := newStaged(t, o)
			if o.reachable {
				if left := s.settled(t); len(left) != 0 || s.registry.Requests.Load() != 0 {
					t.Fatalf("before any bind the guest unpacked %v and sent the registry %d requests", left, s.registry.Requests.Load())
				}
			}
			steps, tenant := s.bound(t, s.registry.Ref(s.image["b"].Digest))
			if steps != "resolve,fetch,unpack,own,clear,measure,start" {
				t.Errorf("admission steps: %s", steps)
			}
			if got := s.which(t, tenant); got != "b b" {
				t.Errorf("the sandbox is image %q", got)
			}
			s.gone(t)
		})
	}
}

// An image the store holds and the pool document does not list is not
// unpacked ahead. A bind that names it reads it from the store.
func TestBindOfAnImageInTheStore(t *testing.T) {
	s := newStaged(t, stagedOptions{stored: []string{"a", "b"}, prestage: []string{"a"}})
	steps, tenant := s.bound(t, elsewhere(s.image["b"].Digest))
	if steps != "store,unpack,own,clear,measure,start" {
		t.Errorf("admission steps: %s", steps)
	}
	if got := s.which(t, tenant); got != "b b" {
		t.Errorf("the sandbox is image %q", got)
	}
	s.gone(t)
}

// The store is the host's file. If what it holds for an image is not the
// image, nothing of it is unpacked, ahead or at the bind, and nothing runs:
// the bind fails and the guest ends, as it does for a registry that lies.
func TestStoreThatWasChangedCostsTheBind(t *testing.T) {
	s := newStaged(t, stagedOptions{stored: []string{"a"}, prestage: []string{"a"}, damage: func(store []byte, s *staged) {
		// One bit of the layer the store holds: image a's.
		at := -1
		for d, blob := range s.registry.Blobs {
			key, err := hex.DecodeString(d.Encoded())
			if err != nil {
				t.Fatal(err)
			}
			if found := bytes.Index(store[4096:], key); found >= 0 && blob.MediaType == ocispec.MediaTypeImageLayerGzip {
				at = found
			}
		}
		if at < 0 {
			t.Fatal("no layer in the store's index")
		}
		store[binary.LittleEndian.Uint64(store[4096+at+32:])] ^= 1
	}})
	// The unpack ahead failed and left nothing behind.
	if left := s.settled(t); len(left) != 0 {
		t.Fatalf("a changed image was unpacked ahead: %v", left)
	}
	client := s.client(t, s.access)
	ready, err := client.Ready(ctxT(t))
	if err != nil {
		t.Fatalf("Unbound: %v", err)
	}
	bind := s.bindFor(t, ready, func(o *session.BindOptions) {
		o.Policy.Sandbox = &session.Sandbox{Image: elsewhere(s.image["a"].Digest)}
	})
	if resp, err := client.Bind(ctxT(t), bind); err == nil {
		t.Fatalf("a changed image was admitted: %+v", resp)
	}
	select {
	case err := <-s.agent.Fatal():
		if err == nil || !strings.Contains(err.Error(), "digest") {
			t.Errorf("the guest ends over: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("the guest did not end")
	}
	if _, err := os.Stat(filepath.Join(s.stateDir, "rootfs")); err == nil {
		t.Error("the guest holds a tree of the changed image")
	}
}

// What is unpacked ahead stays until a bind. The first image listed is the
// root of the container made for it, whose init waits for a bind. Every
// other is a tree under its digest.
func TestImagesUnpackedAheadWaitForABind(t *testing.T) {
	s := newStaged(t, stagedOptions{stored: []string{"a", "b"}, prestage: []string{"a", "b"}})
	left := s.settled(t)
	if want := []string{s.image["b"].Digest.String()}; !slices.Equal(left, want) {
		t.Fatalf("unpacked ahead and waiting as trees: %v, want %v", left, want)
	}
	for _, d := range left {
		dir := filepath.Join(s.stateDir, "prestaged", strings.TrimPrefix(d, "sha256:"))
		if entries, _ := os.ReadDir(dir); len(entries) != 1 || entries[0].Name() != "rootfs" {
			t.Errorf("%s holds %v, want the tree alone", dir, entries)
		}
	}
	if _, err := os.Stat(filepath.Join(s.stateDir, "rootfs", "which")); err != nil {
		t.Fatalf("the first image's container has no root: %v", err)
	}
	if n := s.registry.Requests.Load(); n != 0 {
		t.Errorf("the registry was sent %d requests", n)
	}
}
