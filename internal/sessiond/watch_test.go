package sessiond_test

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/confidential-dot-ai/c8s/internal/sessiond"
	"github.com/confidential-dot-ai/c8s/internal/sessiond/sessiondtest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/daemon"
)

// watched is what a stream that watches a pool has shown so far.
type watched struct {
	mu    sync.Mutex
	shown []*session.Relayed
	ended chan error
	stop  context.CancelFunc
}

// watch opens a stream on the host's pool as c.
func watch(t *testing.T, c *daemon.Client, pool string) *watched {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx(t))
	w := &watched{ended: make(chan error, 1), stop: cancel}
	go func() {
		w.ended <- c.WatchReady(ctx, pool, func(r *session.Relayed) {
			w.mu.Lock()
			defer w.mu.Unlock()
			w.shown = append(w.shown, r)
		})
	}()
	t.Cleanup(cancel)
	return w
}

func (w *watched) seen() []*session.Relayed {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]*session.Relayed(nil), w.shown...)
}

// refused is the code a stream that was not let in ended with.
func (w *watched) refused(t *testing.T) codes.Code {
	t.Helper()
	select {
	case err := <-w.ended:
		return status.Code(err)
	case <-time.After(10 * time.Second):
		t.Fatal("the stream was neither served nor refused")
		return codes.OK
	}
}

// A binder the pool names is shown the pool's ready TDs: those ready when it
// asks, then each as it becomes ready, each once and each as its claim is
// answered. What it is shown verifies as a guest nobody has bound, and a
// claim then finds its guest judged.
func TestWatchReadyShowsABinderThePoolsReadyTDs(t *testing.T) {
	h := newHost(t, 2, nil)
	c, o := h.AsOrchestrator(), newOwner(t)
	w := watch(t, c, sessiondtest.Pool)
	eventually(t, "both ready TDs are shown", func() bool { return len(w.seen()) == 2 })

	policy := session.Policy{Image: h.Identity, LaunchKey: h.LaunchKey, Authority: o.authorityPub, AllowReady: true}
	verdicts, err := session.NewReadyVerdicts(policy, h.Engine)
	if err != nil {
		t.Fatal(err)
	}
	for i, shown := range w.seen() {
		if shown.Phase != session.PhaseReady || len(shown.Bind) != 0 {
			t.Fatalf("TD %d was shown as %s", i, shown.Phase)
		}
		if err := verdicts.Judge(ctx(t), shown); err != nil {
			t.Fatalf("what TD %d was shown as does not verify: %v", i, err)
		}
	}
	// The claim is answered with a TD that was shown, under the certificate
	// it was shown under, and finds it judged.
	claimed, err := c.Claim(ctx(t), requestID(t), sessiondtest.Pool, "s1", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if shown := w.seen(); !bytes.Equal(claimed.Evidence.Certificate, shown[0].Certificate) && !bytes.Equal(claimed.Evidence.Certificate, shown[1].Certificate) {
		t.Fatal("the claim was answered with a TD the stream did not show, or under another certificate")
	}
	judged, err := verdicts.Claimed(ctx(t), claimed.Evidence)
	if err != nil || !judged.Ahead {
		t.Fatalf("the claimed TD was not found judged: %v", err)
	}
	// The pool refills, and the new TD is shown: no other is shown again.
	eventually(t, "the TD that refilled the pool is shown", func() bool { return len(w.seen()) == 3 })
	seen := w.seen()
	if bytes.Equal(seen[2].Certificate, seen[0].Certificate) || bytes.Equal(seen[2].Certificate, seen[1].Certificate) {
		t.Fatal("a TD was shown twice under one certificate")
	}
	if err := verdicts.Judge(ctx(t), seen[2]); err != nil {
		t.Fatalf("the TD that refilled the pool does not verify: %v", err)
	}
	// A second stream starts from what is ready now: the claimed TD is not
	// among it.
	again := watch(t, c, sessiondtest.Pool)
	eventually(t, "a second stream is shown the ready TDs", func() bool { return len(again.seen()) == 2 })
	for _, shown := range again.seen() {
		if bytes.Equal(shown.Certificate, claimed.Evidence.Certificate) {
			t.Fatal("a claimed TD was shown as ready")
		}
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(w.seen()); n != 3 {
		t.Fatalf("the first stream was shown %d TDs, want 3", n)
	}
	// The stream ends with its caller.
	w.stop()
	if code := w.refused(t); code != codes.Canceled {
		t.Fatalf("a stream whose caller left ended with %s", code)
	}
}

// A pool's stream is open to the binders its configuration names and to
// nobody else: it shows how fast the pool refills, which is every tenant's
// starts together.
func TestWatchReadyIsForThePoolsBindersAlone(t *testing.T) {
	h := newHost(t, 1, nil)
	for name, tc := range map[string]struct {
		client *daemon.Client
		pool   string
		want   codes.Code
	}{
		"an orchestrator the pool does not name": {h.Client(&h.Other), sessiondtest.Pool, codes.PermissionDenied},
		"a stranger the pool does not name":      {h.Client(&h.Stranger), sessiondtest.Pool, codes.PermissionDenied},
		"a caller with no certificate":           {h.Client(nil), sessiondtest.Pool, codes.Unauthenticated},
		"a pool the host does not have":          {h.AsOrchestrator(), "another", codes.NotFound},
	} {
		w := watch(t, tc.client, tc.pool)
		if code := w.refused(t); code != tc.want {
			t.Errorf("%s: the stream ended with %s, want %s", name, code, tc.want)
		}
		if n := len(w.seen()); n != 0 {
			t.Errorf("%s was shown %d TDs", name, n)
		}
	}

	// A pool that names nobody is watched by nobody.
	closed := newHost(t, 1, func(c *sessiond.Config) { c.Pools[0].Binders = nil })
	if code := watch(t, closed.AsOrchestrator(), sessiondtest.Pool).refused(t); code != codes.PermissionDenied {
		t.Errorf("a pool that names no binder was watched: %s", code)
	}
}

// A pool's binder is named by its key, and needs no certificate of the
// orchestrators' authority: one of its own making opens the pool's stream.
// That key opens no orchestrator call.
func TestWatchReadyIsOpenedByThePinnedKeyAlone(t *testing.T) {
	h := newHost(t, 1, nil)
	binder := h.Client(&h.Binder)
	w := watch(t, binder, sessiondtest.Pool)
	eventually(t, "a binder with a certificate of its own is shown the pool's ready TD", func() bool { return len(w.seen()) == 1 })
	w.stop()
	_, err := binder.Claim(ctx(t), requestID(t), sessiondtest.Pool, "s1", 0)
	wantCode(t, err, codes.Unauthenticated, "a claim under a binder's own certificate")
	_, err = binder.Destroy(ctx(t), requestID(t), "s1")
	wantCode(t, err, codes.Unauthenticated, "a destroy under a binder's own certificate")
	// Who issued a certificate says nothing of its key: one of the
	// orchestrators' authority that has ended still shows the key the pool
	// would have to name, and it names another.
	if code := watch(t, h.Client(&h.Ended), sessiondtest.Pool).refused(t); code != codes.PermissionDenied {
		t.Fatalf("a key the pool does not name, under a certificate that has ended: %s", code)
	}
	// The orchestrator still claims, call after call.
	c := h.AsOrchestrator()
	for i := range 3 {
		name := fmt.Sprintf("o%d", i)
		if _, err := c.Claim(ctx(t), requestID(t), sessiondtest.Pool, name, 5*time.Second); err != nil {
			t.Fatalf("the orchestrator's claim: %v", err)
		}
		if _, err := c.Destroy(ctx(t), requestID(t), name); err != nil {
			t.Fatalf("the orchestrator's destroy: %v", err)
		}
	}
}

// The daemon carries a bounded number of streams, and one that ends makes
// room for another.
func TestWatchReadyStreamsAreBounded(t *testing.T) {
	h := newHost(t, 1, nil)
	c := h.AsOrchestrator()
	open := make([]*watched, sessiond.MaxWatchers)
	for i := range open {
		open[i] = watch(t, c, sessiondtest.Pool)
	}
	for _, w := range open {
		eventually(t, "every stream within the bound is served", func() bool { return len(w.seen()) == 1 })
	}
	if code := watch(t, c, sessiondtest.Pool).refused(t); code != codes.ResourceExhausted {
		t.Fatalf("a stream beyond the bound ended with %s", code)
	}
	open[0].stop()
	if code := open[0].refused(t); code != codes.Canceled {
		t.Fatalf("the stream that was stopped ended with %s", code)
	}
	eventually(t, "a stream that ended makes room", func() bool {
		w := watch(t, c, sessiondtest.Pool)
		defer w.stop()
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			if len(w.seen()) == 1 {
				return true
			}
			select {
			case <-w.ended:
				return false
			case <-time.After(5 * time.Millisecond):
			}
		}
		return false
	})
}
