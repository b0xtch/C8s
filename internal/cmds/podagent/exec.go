package podagent

import (
	"container/list"
	"context"
	"errors"
	"sync"

	"github.com/confidential-dot-ai/c8s/pkg/podcvm"
)

// Runner runs the workload and commands in its context. Only the agent's
// authenticated API reaches it; the host has no path to a Runner.
type Runner interface {
	// Prepare fetches and verifies the workload image. It starts nothing: the
	// image is measured between Prepare and Start.
	Prepare(ctx context.Context, w *podcvm.Workload) error
	// Start runs the prepared workload.
	Start(ctx context.Context, credentialDir string) error
	// Exec runs one command in the workload context and returns its bounded
	// result. A command that ran and failed is a result, not an error.
	Exec(ctx context.Context, req *podcvm.ExecRequest) (*podcvm.ExecResponse, error)
	// CredentialOwner is the uid and gid credential files are handed to, or
	// -1 to leave ownership alone.
	CredentialOwner() (uid, gid int)
}

const (
	maxConcurrentExecs = 8
	// retainedResults bounds replayable results; retainedIDs bounds how far
	// back a repeated ID is still recognised and refused.
	retainedResults = 128
	retainedIDs     = 65536
)

var (
	errExecBusy    = errors.New("too many commands are running")
	errExecEvicted = errors.New("this exec id already ran and its result is no longer retained")
)

type execEntry struct {
	done   chan struct{}
	result *podcvm.ExecResponse
	err    error
	elem   *list.Element
}

// execService makes exec at-most-once per ID. A retried call joins the run in
// flight or replays its result; an ID whose result has aged out is refused.
type execService struct {
	runner  Runner
	slots   chan struct{}
	mu      sync.Mutex
	entries map[string]*execEntry
	// order holds IDs oldest first; finished counts entries holding a result.
	order    *list.List
	finished *list.List
}

func newExecService(runner Runner) *execService {
	return &execService{
		runner:   runner,
		slots:    make(chan struct{}, maxConcurrentExecs),
		entries:  make(map[string]*execEntry),
		order:    list.New(),
		finished: list.New(),
	}
}

func (s *execService) run(ctx context.Context, req *podcvm.ExecRequest) (*podcvm.ExecResponse, error) {
	s.mu.Lock()
	if entry, ok := s.entries[req.ID]; ok {
		s.mu.Unlock()
		select {
		case <-entry.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		s.mu.Lock()
		result, err := entry.result, entry.err
		s.mu.Unlock()
		if result == nil && err == nil {
			return nil, errExecEvicted
		}
		return result, err
	}
	select {
	case s.slots <- struct{}{}:
	default:
		s.mu.Unlock()
		return nil, errExecBusy
	}
	entry := &execEntry{done: make(chan struct{})}
	entry.elem = s.order.PushBack(req.ID)
	s.entries[req.ID] = entry
	s.trimLocked()
	s.mu.Unlock()

	// The command outlives a caller that disconnects: the ID is spent either
	// way, and a retry must find a finished result.
	result, err := s.runner.Exec(context.WithoutCancel(ctx), req)
	<-s.slots

	s.mu.Lock()
	entry.result, entry.err = result, err
	s.finished.PushBack(entry)
	for s.finished.Len() > retainedResults {
		old := s.finished.Remove(s.finished.Front()).(*execEntry)
		old.result, old.err = nil, nil
	}
	s.mu.Unlock()
	close(entry.done)
	return result, err
}

// trimLocked forgets the oldest finished IDs past retainedIDs. An ID still
// running is never forgotten.
func (s *execService) trimLocked() {
	for e := s.order.Front(); e != nil && s.order.Len() > retainedIDs; {
		next := e.Next()
		id := e.Value.(string)
		select {
		case <-s.entries[id].done:
			delete(s.entries, id)
			s.order.Remove(e)
		default:
		}
		e = next
	}
}
