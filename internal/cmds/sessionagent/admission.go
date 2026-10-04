package sessionagent

import (
	"context"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// The steps of admitting a sandbox that a guest reports, in the order they
// happen. A guest with no sandbox image reports none of the first six.
const (
	// stepRegistryWait is what was lost before a registry answered: the
	// attempts that reached none and the waits between them.
	stepRegistryWait = "registry_wait"
	// stepResolve: the registry was asked what it holds under the reference.
	stepResolve = "resolve"
	// stepFetch: manifest, config and layers, each checked against its digest.
	stepFetch = "fetch"
	// stepStore stands in for both when no registry was asked: every blob
	// was read from the host's image store, and checked the same.
	stepStore = "store"
	// stepPrestaged stands in for every step before this one when the image
	// was unpacked ahead of the bind: what it took to wait for an unpack
	// still under way, and to take the tree.
	stepPrestaged = "prestaged"
	// stepUnpack: the layers decompressed and applied.
	stepUnpack = "unpack"
	// stepOwn: the tree handed to the sandbox's id range.
	stepOwn = "own"
	// stepClear: the fetched blobs removed.
	stepClear = "clear"
	// stepMeasure: the sandbox extended into the register.
	stepMeasure = "measure"
	stepStart   = "start"
)

// admission collects how long each step of one admission took.
type admission struct {
	mu    sync.Mutex
	steps []session.AdmissionStep
}

type admissionKey struct{}

// withAdmission returns a context under which recordStep records.
func withAdmission(ctx context.Context) (context.Context, *admission) {
	rec := &admission{}
	return context.WithValue(ctx, admissionKey{}, rec), rec
}

// recordStep notes that a step of the admission ctx belongs to took this
// long. Outside an admission it notes nothing.
func recordStep(ctx context.Context, name string, took time.Duration) {
	rec, _ := ctx.Value(admissionKey{}).(*admission)
	if rec == nil {
		return
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.steps = append(rec.steps, session.AdmissionStep{Name: name, Micros: took.Microseconds()})
}

func (r *admission) list() []session.AdmissionStep {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.steps
}
