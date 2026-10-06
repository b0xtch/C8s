package sessionagent

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"

	"github.com/confidential-dot-ai/c8s/internal/imagestore"
	"github.com/confidential-dot-ai/c8s/internal/imagestore/imagestoretest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

func namesOf(steps []session.AdmissionStep) []string {
	names := make([]string, len(steps))
	for i, step := range steps {
		names[i] = step.Name
	}
	return names
}

func TestStepsAreRecordedInOrderForTheirAdmission(t *testing.T) {
	ctx, first := withAdmission(context.Background())
	other, second := withAdmission(context.Background())
	recordStep(ctx, stepFetch, 1500*time.Microsecond)
	recordStep(other, stepUnpack, time.Second)
	recordStep(ctx, stepStart, 2*time.Millisecond)
	// Outside an admission there is nothing to record into.
	recordStep(context.Background(), stepClear, time.Second)

	got := first.list()
	if len(got) != 2 || got[0] != (session.AdmissionStep{Name: stepFetch, Micros: 1500}) || got[1] != (session.AdmissionStep{Name: stepStart, Micros: 2000}) {
		t.Fatalf("first admission: %+v", got)
	}
	if got := second.list(); len(got) != 1 || got[0].Name != stepUnpack {
		t.Fatalf("second admission: %+v", got)
	}
}

func testPuller(t *testing.T) *imagestore.Puller {
	return &imagestore.Puller{
		StoreDir: t.TempDir(), PlainHTTP: func(string) bool { return true },
		Limits: imagestore.PullLimits{Layers: 4, BlobBytes: 1 << 20, TotalBytes: 4 << 20},
	}
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// A registry that answers the first time costs no wait.
func TestPullReportsItsSteps(t *testing.T) {
	registry := imagestoretest.NewRegistry(t)
	manifest := registry.Image([][]byte{imagestoretest.Layer(imagestoretest.File("a", "1"))}, imagestoretest.ImageOptions{})
	ctx, steps := withAdmission(context.Background())
	if _, err := pullWaiting(ctx, testPuller(t), registry.Ref(manifest.Digest), quiet); err != nil {
		t.Fatal(err)
	}
	got := steps.list()
	if names := namesOf(got); len(names) != 2 || names[0] != stepResolve || names[1] != stepFetch || got[0].Micros <= 0 || got[1].Micros <= 0 {
		t.Fatalf("steps: %+v", got)
	}
}

// The agent serves before the guest's network is up. A pull then waits for
// its registry, a moment at first, and says what the wait cost.
func TestPullWaitsOutARegistryThatIsNotUpYet(t *testing.T) {
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := reserved.Addr().String()
	reserved.Close()
	registry := &imagestoretest.Registry{Host: addr, Blobs: map[digest.Digest]imagestoretest.Blob{}}
	manifest := registry.Image([][]byte{imagestoretest.Layer(imagestoretest.File("a", "1"))}, imagestoretest.ImageOptions{})

	// Up after 150 ms: a guest's network is there a moment after its agent.
	const upAfter = 150 * time.Millisecond
	began := time.Now()
	go func() {
		time.Sleep(upAfter)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Errorf("the reserved address was taken: %v", err)
			return
		}
		srv := &http.Server{Handler: registry, ReadHeaderTimeout: time.Second}
		t.Cleanup(func() { _ = srv.Close() })
		_ = srv.Serve(ln)
	}()

	ctx, steps := withAdmission(context.Background())
	if _, err := pullWaiting(ctx, testPuller(t), registry.Ref(manifest.Digest), quiet); err != nil {
		t.Fatal(err)
	}
	took := time.Since(began)
	got := steps.list()
	if names := namesOf(got); len(names) != 3 || names[0] != stepRegistryWait || names[1] != stepResolve || names[2] != stepFetch {
		t.Fatalf("steps: %+v", got)
	}
	// What was lost is at least the time the registry was not there.
	lost := time.Duration(got[0].Micros) * time.Microsecond
	if lost < upAfter || lost > took {
		t.Errorf("the wait is reported as %s of a pull that took %s", lost, took)
	}
	// A first wait of a second would have cost a second.
	if took > 900*time.Millisecond {
		t.Errorf("a registry that was up after %s was reached after %s", upAfter, took)
	}
}

// What is not an unreachable registry is not waited out: the registry is
// asked what one pull asks of it, and no more.
func TestPullDoesNotWaitOutARefusal(t *testing.T) {
	registry := imagestoretest.NewRegistry(t)
	ref := registry.Ref(digest.FromString("no such image"))
	if _, err := testPuller(t).Pull(context.Background(), ref); err == nil {
		t.Fatal("a registry without the image handed one over")
	}
	once := registry.Requests.Load()
	ctx, steps := withAdmission(context.Background())
	_, err := pullWaiting(ctx, testPuller(t), ref, quiet)
	if asked := registry.Requests.Load() - once; err == nil || asked != once || len(steps.list()) != 0 {
		t.Fatalf("a registry without the image: %v, asked %d times where one pull asks %d, steps %+v", err, asked, once, steps.list())
	}
}

// storeOf is a host's image store that holds the registry's blobs, less one.
func storeOf(t *testing.T, registry *imagestoretest.Registry, without digest.Digest) []byte {
	t.Helper()
	var blobs []imagestore.StoreBlob
	for d, blob := range registry.Blobs {
		if d != without {
			blobs = append(blobs, imagestore.StoreBlob{Digest: d, Size: int64(len(blob.Data)), Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(blob.Data)), nil
			}})
		}
	}
	var out bytes.Buffer
	if err := imagestore.WriteStore(&out, blobs); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// An image the host's store holds whole is one step, and no registry's: the
// reference here names a registry that does not exist.
func TestPullFromTheStoreIsOneStep(t *testing.T) {
	registry := imagestoretest.NewRegistry(t)
	manifest := registry.Image([][]byte{imagestoretest.Layer(imagestoretest.File("a", "1"))}, imagestoretest.ImageOptions{})
	image := storeOf(t, registry, "")
	store, err := imagestore.OpenStore(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		t.Fatal(err)
	}
	puller := testPuller(t)
	puller.Images = store
	ctx, steps := withAdmission(context.Background())
	if _, err := pullWaiting(ctx, puller, "127.0.0.1:1/test/app@"+manifest.Digest.String(), quiet); err != nil {
		t.Fatal(err)
	}
	if got := steps.list(); len(got) != 1 || got[0].Name != stepStore || got[0].Micros <= 0 {
		t.Fatalf("steps: %+v", got)
	}

	// With one blob missing from the store the registry is asked, and the
	// steps are a registry's.
	var layer digest.Digest
	for d, blob := range registry.Blobs {
		if blob.MediaType == "application/vnd.oci.image.layer.v1.tar+gzip" {
			layer = d
		}
	}
	image = storeOf(t, registry, layer)
	if store, err = imagestore.OpenStore(bytes.NewReader(image), int64(len(image))); err != nil {
		t.Fatal(err)
	}
	puller = testPuller(t)
	puller.Images = store
	ctx, steps = withAdmission(context.Background())
	if _, err := pullWaiting(ctx, puller, registry.Ref(manifest.Digest), quiet); err != nil {
		t.Fatal(err)
	}
	if names := namesOf(steps.list()); len(names) != 2 || names[0] != stepResolve || names[1] != stepFetch {
		t.Fatalf("steps with a blob from the registry: %v", names)
	}
}

// The guest finds its host's image store by the disk's serial, whatever name
// the disk got, and goes on without one that is not there or is no store.
func TestOpenImageStore(t *testing.T) {
	registry := imagestoretest.NewRegistry(t)
	manifest := registry.Image([][]byte{imagestoretest.Layer(imagestoretest.File("a", "1"))}, imagestoretest.ImageOptions{})
	image := storeOf(t, registry, "")
	guest := func(t *testing.T, disks map[string][2]string) (sys, dev string) {
		sys, dev = t.TempDir(), t.TempDir()
		for name, disk := range disks {
			if err := os.MkdirAll(filepath.Join(sys, name), 0o755); err != nil {
				t.Fatal(err)
			}
			if disk[0] != "" {
				if err := os.WriteFile(filepath.Join(sys, name, "serial"), []byte(disk[0]), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(dev, name), []byte(disk[1]), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return sys, dev
	}
	for name, tc := range map[string]struct {
		disks map[string][2]string
		want  bool
	}{
		"the store among the guest's disks": {map[string][2]string{
			"vda": {"", "root"}, "vdb": {"confai-scratch\n", "scratch"}, "vdc": {"", "launch"}, "vdd": {"c8s-images\n", string(image)},
		}, true},
		"under another name":           {map[string][2]string{"vda": {"c8s-images", string(image)}}, true},
		"no store":                     {map[string][2]string{"vda": {"", "root"}, "vdb": {"confai-scratch\n", "scratch"}}, false},
		"a disk with a serial like it": {map[string][2]string{"vdb": {"c8s-images-2\n", string(image)}}, false},
		"a disk that is no store":      {map[string][2]string{"vdd": {"c8s-images\n", "not a store"}}, false},
		"a store cut short":            {map[string][2]string{"vdd": {"c8s-images\n", string(image[:len(image)/2])}}, false},
	} {
		t.Run(name, func(t *testing.T) {
			sys, dev := guest(t, tc.disks)
			store := OpenImageStore(sys, dev, quiet)
			if (store != nil) != tc.want {
				t.Fatalf("store: %v", store)
			}
			if _, ok := store.Size(manifest.Digest); ok != tc.want {
				t.Fatalf("the store holds the image: %v", ok)
			}
		})
	}
	// A serial the guest cannot read is no store, and no failure.
	sys, dev := guest(t, map[string][2]string{"vdd": {"c8s-images\n", string(image)}})
	if err := os.Remove(filepath.Join(dev, "vdd")); err != nil {
		t.Fatal(err)
	}
	if store := OpenImageStore(sys, dev, quiet); store != nil {
		t.Fatal("a store on a disk that is not there")
	}
}
