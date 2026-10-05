package sessiond_test

import (
	"context"
	"crypto/sha256"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sessionv1alpha1 "github.com/confidential-dot-ai/c8s/api/session/v1alpha1"
	"github.com/confidential-dot-ai/c8s/internal/sessiond"
	"github.com/confidential-dot-ai/c8s/internal/sessiond/sessiondtest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/daemon"
)

// claiming is a host whose pool lets each binder it names claim a TD with a
// bind under o's authority.
func claiming(t *testing.T, depth int, o *owner) *host {
	t.Helper()
	authority, err := session.InstanceKeyDigest(&o.authority.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return newHost(t, depth, func(c *sessiond.Config) {
		for i := range c.Pools[0].Binders {
			c.Pools[0].Binders[i].Authorities = []string{authority}
		}
	})
}

// bindFor is a bind under o's authority for the ready guest a stream showed.
func (h *host) bindFor(o *owner, name string, shown *session.Relayed) (*session.ReadyTD, *session.SignedBind) {
	h.t.Helper()
	readyPolicy := session.Policy{Image: h.Identity, LaunchKey: h.LaunchKey, Authority: o.authorityPub, AllowReady: true}
	ready, err := session.VerifyReady(ctx(h.t), readyPolicy, h.Engine, shown, time.Now())
	if err != nil {
		h.t.Fatalf("what the stream showed does not verify: %v", err)
	}
	bind, err := session.NewBind(session.BindOptions{
		Authority: o.authority, InstanceKey: ready.InstanceKey, Tenant: "acme", Session: name,
		NotAfter: time.Now().Add(time.Minute),
		Policy: session.BindPolicy{
			Access:      session.Access{Exec: []string{o.accessPub}, Credentials: []string{o.accessPub}},
			Credentials: []session.Credential{{Name: "token", MaxBytes: 64}},
		},
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return ready, bind
}

// claims sends a bind that names no TD: for the ready guest a stream showed,
// which the bind then claims. It returns the session as its binder judged
// it, and the TD the daemon says the bind claimed.
func (h *host) claims(c *daemon.Client, o *owner, id, name string, shown *session.Relayed) (*started, error) {
	h.t.Helper()
	ready, bind := h.bindFor(o, name, shown)
	call, err := c.BindWith(ctx(h.t), id, "", bind, nil)
	if err != nil {
		return nil, err
	}
	defer call.Close()
	if call.TD == "" || call.Host != "host-a" {
		h.t.Fatalf("a bind that claimed its TD was answered with TD %q on host %q", call.TD, call.Host)
	}
	return h.judge(c, call.TD, ready, bind, call.Answer)
}

// events is what a Watch stream has shown so far.
type events struct {
	mu    sync.Mutex
	shown []*sessionv1alpha1.Event
	ended chan error
	stop  context.CancelFunc
}

func watchEvents(t *testing.T, c *daemon.Client) *events {
	t.Helper()
	watching, cancel := context.WithCancel(ctx(t))
	e := &events{ended: make(chan error, 1), stop: cancel}
	go func() {
		e.ended <- c.Watch(watching, func(event *sessionv1alpha1.Event) {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.shown = append(e.shown, event)
		})
	}()
	t.Cleanup(cancel)
	return e
}

// last is the TD as the stream last showed it, or nil.
func (e *events) last(td string) *sessionv1alpha1.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := len(e.shown) - 1; i >= 0; i-- {
		if e.shown[i].GetTd() == td {
			return e.shown[i]
		}
	}
	return nil
}

func (e *events) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.shown)
}

// A binder that watches a pool has judged its ready TDs, and needs no claim:
// a bind that names no TD claims the ready TD of the instance key it names,
// for the bind's session. The orchestrator learns of the session from Watch,
// and is who ends it.
func TestBindClaimsTheReadyTDItNames(t *testing.T) {
	o := newOwner(t)
	h := claiming(t, 2, o)
	orchestrator, binder := h.AsOrchestrator(), h.Client(&h.Binder)
	binderKey, err := daemon.BinderName(h.Binder.Leaf)
	if err != nil {
		t.Fatal(err)
	}
	w := watch(t, binder, sessiondtest.Pool)
	eventually(t, "the binder is shown both ready TDs", func() bool { return len(w.seen()) == 2 })
	seen := watchEvents(t, orchestrator)
	eventually(t, "the orchestrator is shown both TDs as they are", func() bool { return seen.count() >= 2 })
	first, second := w.seen()[0], w.seen()[1]

	s, err := h.claims(binder, o, requestID(t), "s1", first)
	if err != nil {
		t.Fatalf("a bind that claims its TD: %v", err)
	}
	// The session is the owner's: a command reaches its guest through the
	// daemon, under a key the bind grants.
	if result, err := h.drive(o, s).Exec(ctx(t), session.ExecRequest{Argv: []string{"true"}}); err != nil || result.ExitCode != 0 {
		t.Fatalf("a command in the session a bind claimed its TD for: %v", err)
	}
	// The orchestrator sees the TD run the bind's session, and who started
	// it.
	eventually(t, "the orchestrator is shown the session a binder's bind started", func() bool {
		event := seen.last(s.td)
		return event != nil && event.GetState() == sessionv1alpha1.TDState_TD_STATE_RUNNING && event.GetSession() == "s1" &&
			event.GetClaimedBy() == binderKey && event.GetPool() == sessiondtest.Pool && event.GetHost() == "host-a"
	})
	// The stream of ready TDs says the TD left, and of the other nothing.
	eventually(t, "the binder is told the TD it bound left ready", func() bool { return w.gone(first.Certificate) })
	if w.gone(second.Certificate) {
		t.Fatal("the stream says a TD left that nobody took")
	}
	// A bind makes its claim with no grace: the TD does not return to its
	// pool when a claim's would have run out.
	time.Sleep(time.Duration(h.Config.Pools[0].BindGrace) + 200*time.Millisecond)
	if event := seen.last(s.td); event.GetState() != sessionv1alpha1.TDState_TD_STATE_RUNNING {
		t.Fatalf("a TD its bind claimed is %s once a claim's grace has passed", event.GetState())
	}

	// A binder ends no session. The orchestrator does, by its name.
	_, err = binder.Destroy(ctx(t), requestID(t), "s1")
	wantCode(t, err, codes.Unauthenticated, "a destroy under a binder's certificate")
	if _, err := orchestrator.Destroy(ctx(t), requestID(t), "s1"); err != nil {
		t.Fatalf("the orchestrator's destroy of a session a binder started: %v", err)
	}
	eventually(t, "the orchestrator is shown the TD ended", func() bool {
		event := seen.last(s.td)
		return event.GetState() == sessionv1alpha1.TDState_TD_STATE_ENDED && event.GetReason() == "destroyed"
	})

	// An orchestrator's bind claims too, and is shown as nobody's but its own.
	other, err := h.claims(orchestrator, o, requestID(t), "s2", second)
	if err != nil {
		t.Fatalf("an orchestrator's bind that claims its TD: %v", err)
	}
	eventually(t, "the orchestrator is shown its own session", func() bool {
		event := seen.last(other.td)
		return event.GetState() == sessionv1alpha1.TDState_TD_STATE_RUNNING && event.GetSession() == "s2" && event.GetClaimedBy() == ""
	})
}

// What may claim a TD with a bind is an orchestrator, and a binder its pool
// names, under an authority the pool names for that binder. Everybody else
// is refused whatever TDs there are, before anything reaches a guest, and so
// is a bind that says nothing a daemon can read.
func TestBindThatClaimsIsHeldToWhatItsPoolNames(t *testing.T) {
	o, stranger := newOwner(t), newOwner(t)
	h := claiming(t, 1, o)
	orchestrator, binder := h.AsOrchestrator(), h.Client(&h.Binder)
	w := watch(t, binder, sessiondtest.Pool)
	eventually(t, "the binder is shown the ready TD", func() bool { return len(w.seen()) == 1 })
	shown := w.seen()[0]
	eventually(t, "the pool's TD boots", func() bool { return h.Runner.Booted() >= 1 })
	guest := h.Runner.Last()

	_, own := h.bindFor(o, "s1", shown)
	_, foreign := h.bindFor(stranger, "s1", shown)
	forged := *own
	forged.Signature = foreign.Signature
	for name, tc := range map[string]struct {
		client *daemon.Client
		bind   *session.SignedBind
		want   codes.Code
	}{
		"a binder the pool names, under an authority it does not name": {binder, foreign, codes.PermissionDenied},
		"a caller the pool does not name":                              {h.Client(&h.Stranger), own, codes.PermissionDenied},
		"a caller the pool does not name, with what is no bind":        {h.Client(&h.Stranger), &forged, codes.PermissionDenied},
		"a caller with no certificate":                                 {h.Client(nil), own, codes.Unauthenticated},
		"a bind whose signature is another's":                          {binder, &forged, codes.InvalidArgument},
		"an orchestrator's certificate that has ended":                 {h.Client(&h.Ended), own, codes.PermissionDenied},
	} {
		call, err := tc.client.BindWith(ctx(t), requestID(t), "", tc.bind, nil)
		if status.Code(err) != tc.want || call != nil {
			t.Errorf("%s: %v, want %s", name, err, tc.want)
		}
		if daemon.NotReady(err) {
			t.Errorf("%s was told the TD is not ready: a bind is no probe for what is", name)
		}
	}
	if got := guest.Asked(session.PathBind); got != 0 {
		t.Fatalf("%d refused binds reached the guest", got)
	}
	// The TD is as ready as it was: the bind its pool allows claims it.
	id := requestID(t)
	s, err := h.claims(binder, o, id, "s1", shown)
	if err != nil {
		t.Fatalf("after the refusals, the bind the pool allows: %v", err)
	}
	if got := guest.Asked(session.PathBind); got != 1 {
		t.Fatalf("the guest was sent %d binds for one", got)
	}

	// The same request again is answered as the first was, with the TD it
	// claimed, and the guest hears nothing of it.
	again, err := binder.BindWith(ctx(t), id, "", s.bind, nil)
	if err != nil || again.TD != s.td {
		t.Fatalf("the same request again: %v", err)
	}
	again.Close()
	if got := guest.Asked(session.PathBind); got != 1 {
		t.Fatalf("a repeated request reached the guest: %d binds", got)
	}
	// Under the same id from another caller it is nobody's repeat, and a
	// claim under it is another request.
	_, err = orchestrator.BindWith(ctx(t), id, "", s.bind, nil)
	wantCode(t, err, codes.InvalidArgument, "another caller under the first one's request id")
	_, err = orchestrator.Claim(ctx(t), id, sessiondtest.Pool, "s1", 0)
	wantCode(t, err, codes.InvalidArgument, "a claim under the request id of a bind that claimed")

	// The pool refills. A second bind for the session that has a TD claims
	// none, and the TD it named stays ready.
	eventually(t, "the TD that refilled the pool is shown", func() bool { return len(w.seen()) == 2 })
	next, nextGuest := w.seen()[1], h.Runner.Last()
	_, twice := h.bindFor(o, "s1", next)
	_, err = binder.BindWith(ctx(t), requestID(t), "", twice, nil)
	wantCode(t, err, codes.AlreadyExists, "a bind for a session that has a TD")

	// A claim takes that TD first: the bind for it finds it not ready, and
	// says so in a way its sender can tell from any other refusal.
	claimed, err := orchestrator.Claim(ctx(t), requestID(t), sessiondtest.Pool, "s2", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, late := h.bindFor(o, "s3", next)
	_, err = binder.BindWith(ctx(t), requestID(t), "", late, nil)
	if status.Code(err) != codes.FailedPrecondition || !daemon.NotReady(err) {
		t.Fatalf("a bind for a TD a claim took first: %v, want it told the TD is not ready", err)
	}
	if got := nextGuest.Asked(session.PathBind); got != 0 {
		t.Fatalf("a bind for a TD that was taken reached its guest %d times", got)
	}
	// The claimed TD's own bind is its orchestrator's to send: a binder that
	// names it is refused.
	_, err = binder.BindWith(ctx(t), requestID(t), claimed.TD, late, nil)
	wantCode(t, err, codes.Unauthenticated, "a bind for a claimed TD under a binder's certificate")
	// A bind for a guest of another host finds no TD ready here either.
	other := newHost(t, 1, nil)
	elsewhere := watch(t, other.AsOrchestrator(), sessiondtest.Pool)
	eventually(t, "another host shows its ready TD", func() bool { return len(elsewhere.seen()) == 1 })
	_, absent := other.bindFor(o, "s4", elsewhere.seen()[0])
	if _, err := orchestrator.BindWith(ctx(t), requestID(t), "", absent, nil); !daemon.NotReady(err) {
		t.Fatalf("a bind for a guest of another host: %v, want it told no such TD is ready", err)
	}
}

// A pool that names a binder with no authority lets it watch, and claim
// nothing: its bind is an outsider's.
func TestWatcherWithNoAuthorityClaimsNothing(t *testing.T) {
	o := newOwner(t)
	h := newHost(t, 1, nil)
	binder := h.Client(&h.Binder)
	w := watch(t, binder, sessiondtest.Pool)
	eventually(t, "the binder is shown the ready TD", func() bool { return len(w.seen()) == 1 })
	_, bind := h.bindFor(o, "s1", w.seen()[0])
	_, err := binder.BindWith(ctx(t), requestID(t), "", bind, nil)
	wantCode(t, err, codes.PermissionDenied, "a bind from a binder the pool names no authority for")
	// An orchestrator needs no naming.
	if _, err := h.claims(h.AsOrchestrator(), o, requestID(t), "s1", w.seen()[0]); err != nil {
		t.Fatalf("an orchestrator's bind that claims: %v", err)
	}
}

// Watch shows an orchestrator every TD of the host as it is, then each as it
// changes, and shows nobody else anything.
func TestWatchShowsAnOrchestratorTheHostsTDs(t *testing.T) {
	h := newHost(t, 2, nil)
	o := newOwner(t)
	c := h.AsOrchestrator()
	eventually(t, "both TDs boot", func() bool { return h.Runner.Booted() >= 2 })
	ready := watch(t, c, sessiondtest.Pool)
	eventually(t, "both TDs are ready", func() bool { return len(ready.seen()) == 2 })

	seen := watchEvents(t, c)
	eventually(t, "both TDs are shown as ready", func() bool {
		if seen.count() != 2 {
			return false
		}
		seen.mu.Lock()
		defer seen.mu.Unlock()
		return seen.shown[0].GetState() == sessionv1alpha1.TDState_TD_STATE_READY && seen.shown[1].GetState() == sessionv1alpha1.TDState_TD_STATE_READY &&
			seen.shown[0].GetTd() != seen.shown[1].GetTd() && seen.shown[0].GetSession() == ""
	})
	claimed, err := c.Claim(ctx(t), requestID(t), sessiondtest.Pool, "s1", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, "the claim is shown", func() bool {
		event := seen.last(claimed.TD)
		return event.GetState() == sessionv1alpha1.TDState_TD_STATE_CLAIMED && event.GetSession() == "s1" && event.GetClaimedBy() == ""
	})
	if _, err := h.bind(c, o, "s1", claimed); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the session is shown running", func() bool {
		return seen.last(claimed.TD).GetState() == sessionv1alpha1.TDState_TD_STATE_RUNNING
	})
	// The pool refills: the new TD is shown too.
	eventually(t, "the TD that refills the pool is shown", func() bool {
		tds := map[string]bool{}
		seen.mu.Lock()
		defer seen.mu.Unlock()
		for _, event := range seen.shown {
			tds[event.GetTd()] = true
		}
		return len(tds) == 3
	})

	for name, client := range map[string]*daemon.Client{
		"a binder the pool names":      h.Client(&h.Binder),
		"a caller with no certificate": h.Client(nil),
		"a stranger":                   h.Client(&h.Stranger),
	} {
		refused := watchEvents(t, client)
		select {
		case err := <-refused.ended:
			if status.Code(err) != codes.Unauthenticated || refused.count() != 0 {
				t.Errorf("%s watched the host's TDs: %v, shown %d", name, err, refused.count())
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s was neither shown the host's TDs nor refused", name)
		}
	}

	// The daemon carries a bounded number of such streams.
	for range sessiond.MaxEventWatchers - 1 {
		within := watchEvents(t, c)
		eventually(t, "every stream within the bound is served", func() bool { return within.count() > 0 })
	}
	beyond := watchEvents(t, c)
	select {
	case err := <-beyond.ended:
		wantCode(t, err, codes.ResourceExhausted, "a stream beyond the bound")
	case <-time.After(10 * time.Second):
		t.Fatal("a stream beyond the bound was served")
	}
	// A stream that ends makes room for another.
	seen.stop()
	wantCode(t, <-seen.ended, codes.Canceled, "a stream whose caller left")
	eventually(t, "a stream that ended makes room", func() bool {
		next := watchEvents(t, c)
		defer next.stop()
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			if next.count() > 0 {
				return true
			}
			select {
			case <-next.ended:
				return false
			case <-time.After(5 * time.Millisecond):
			}
		}
		return false
	})
}

// A TD that a bind claims is ready no more from that moment: those who watch
// its pool are told while its guest still takes the bind, and sign for it no
// longer, and an orchestrator is shown the session it is bound for.
func TestWatchersLearnOfABindsClaimWhileItsGuestTakesTheBind(t *testing.T) {
	sandbox := newHeld()
	h := &host{Host: sessiondtest.NewHostWithSandbox(t, 2, sandbox), t: t}
	c, o := h.AsOrchestrator(), newOwner(t)
	w := watch(t, c, sessiondtest.Pool)
	eventually(t, "both ready TDs are shown", func() bool { return len(w.seen()) == 2 })
	seen := watchEvents(t, c)
	shown := w.seen()[0]
	held := func(name string) (*session.ReadyTD, *session.SignedBind) {
		t.Helper()
		ready, err := session.VerifyReady(ctx(t), session.Policy{Image: h.Identity, LaunchKey: h.LaunchKey, Authority: o.authorityPub, AllowReady: true}, h.Engine, shown, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		bind, err := session.NewBind(session.BindOptions{
			Authority: o.authority, InstanceKey: ready.InstanceKey, Tenant: "acme", Session: name, NotAfter: time.Now().Add(time.Minute),
			Policy: session.BindPolicy{Access: session.Access{Exec: []string{o.accessPub}}, Sandbox: &session.Sandbox{Image: sealedImage}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return ready, bind
	}
	ready, bind := held("s1")
	id := requestID(t)
	call, err := c.StartBind(ctx(t), id, "", bind, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer call.Close()
	select {
	case <-sandbox.preparing:
	case <-time.After(20 * time.Second):
		t.Fatal("the guest never prepared its sandbox")
	}
	// The guest holds the bind, and has not answered it.
	told := func(what string, ok func() bool) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for !ok() {
			if time.Now().After(deadline) {
				t.Fatalf("while the guest took the bind, never: %s", what)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	told("the pool's watchers are told the TD left ready", func() bool { return w.gone(shown.Certificate) })
	told("the orchestrator is shown the TD bound for its session", func() bool {
		seen.mu.Lock()
		defer seen.mu.Unlock()
		for _, event := range seen.shown {
			if event.GetState() == sessionv1alpha1.TDState_TD_STATE_BOUND && event.GetSession() == "s1" {
				return true
			}
		}
		return false
	})
	// A second bind for that TD meanwhile, from a binder that had not read
	// on, finds it not ready. The same request again is told to wait.
	_, twin := held("s2")
	_, err = c.BindWith(ctx(t), requestID(t), "", twin, nil)
	if !daemon.NotReady(err) {
		t.Fatalf("a second bind for a TD whose guest is taking one: %v", err)
	}
	_, err = c.BindWith(ctx(t), id, "", bind, nil)
	wantCode(t, err, codes.Aborted, "the same request again while the first is in flight")
	close(sandbox.release)
	if err := call.Await(); err != nil {
		t.Fatalf("the bind's answer: %v", err)
	}
	if call.TD == "" || call.Answer.Receipt == nil {
		t.Fatalf("the bind was answered with TD %q and receipt %v", call.TD, call.Answer.Receipt)
	}
	if _, err := h.judge(c, call.TD, ready, bind, call.Answer); err != nil {
		t.Fatalf("the bind's answer: %v", err)
	}
}

// The certificate a binder keeps its verdict by is the one the stream names
// a TD that left by.
func TestStreamNamesATDThatLeftByItsCertificate(t *testing.T) {
	o := newOwner(t)
	h := claiming(t, 2, o)
	binder := h.Client(&h.Binder)
	w := watch(t, binder, sessiondtest.Pool)
	eventually(t, "the binder is shown both ready TDs", func() bool { return len(w.seen()) == 2 })
	policy := session.Policy{Image: h.Identity, LaunchKey: h.LaunchKey, Authority: o.authorityPub, AllowReady: true}
	verdicts, err := session.NewReadyVerdicts(policy, h.Engine)
	if err != nil {
		t.Fatal(err)
	}
	for _, shown := range w.seen() {
		if err := verdicts.Judge(ctx(t), shown); err != nil {
			t.Fatal(err)
		}
	}
	// Another claim takes one of the two: the older, which the stream may
	// have shown second if it was the later to become ready.
	claimed, err := h.AsOrchestrator().Claim(ctx(t), requestID(t), sessiondtest.Pool, "taken", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	still := w.seen()[1]
	switch string(claimed.Evidence.Certificate) {
	case string(w.seen()[0].Certificate):
	case string(still.Certificate):
		still = w.seen()[0]
	default:
		t.Fatal("a claim took a TD the stream did not show")
	}
	eventually(t, "the stream says that TD left", func() bool { return w.gone(claimed.Evidence.Certificate) })
	w.mu.Lock()
	left := slices.Clone(w.left)
	w.mu.Unlock()
	for _, certificate := range left {
		verdicts.Forget(certificate)
	}
	// What the binder signs for next is the other TD, and its bind claims it.
	judged, err := verdicts.Take()
	if err != nil || sha256.Sum256(judged.Certificate) != sha256.Sum256(still.Certificate) {
		t.Fatalf("after one TD left, the binder takes %v", err)
	}
	if _, err := h.claims(binder, o, requestID(t), "s1", still); err != nil {
		t.Fatalf("the bind for the TD that is still ready: %v", err)
	}
	if _, err := verdicts.Take(); err == nil {
		t.Fatal("a binder with no ready TD left to sign for was handed one")
	}
}
