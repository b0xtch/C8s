package sessiond_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/confidential-dot-ai/c8s/internal/sessiond"
	"github.com/confidential-dot-ai/c8s/internal/sessiond/sessiondtest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/daemon"
)

// A host that lets its guests work on one bind at once holds a second bind
// back while the first guest is at work on its own: the second reaches no
// guest and takes no TD from the pool. When the first guest has said all it
// will, the second bind's turn comes, and it claims its TD and is answered.
func TestBindPastTheBoundWaitsItsTurnAndTakesNoTD(t *testing.T) {
	sandbox := newHeld()
	h := &host{Host: sessiondtest.NewHostWith(t, 2, func(c *sessiond.Config) { c.BindsAtOnce = 1 }, sandbox), t: t}
	c, o := h.AsOrchestrator(), newOwner(t)
	w := watch(t, c, sessiondtest.Pool)
	eventually(t, "both ready TDs are shown", func() bool { return len(w.seen()) == 2 })
	shown := w.seen()
	bindFor := func(name string, guest *session.Relayed) (*session.ReadyTD, *session.SignedBind) {
		t.Helper()
		ready, err := session.VerifyReady(ctx(t), session.Policy{Image: h.Identity, LaunchKey: h.LaunchKey, Authority: o.authorityPub, AllowReady: true}, h.Engine, guest, time.Now())
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
	firstReady, firstBind := bindFor("s1", shown[0])
	first, err := c.StartBind(ctx(t), requestID(t), "", firstBind, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	select {
	case <-sandbox.preparing:
	case <-time.After(20 * time.Second):
		t.Fatal("the first guest never prepared its sandbox")
	}
	// The first guest holds its bind. The second bind is sent now.
	secondReady, secondBind := bindFor("s2", shown[1])
	second, err := c.StartBind(ctx(t), requestID(t), "", secondBind, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	select {
	case <-sandbox.preparing:
		t.Fatal("the second bind reached its guest while the first guest was at work")
	case <-time.After(300 * time.Millisecond):
	}
	if w.gone(shown[1].Certificate) {
		t.Fatal("the second bind took its TD from the pool while it waited its turn")
	}
	close(sandbox.release)
	if err := first.Await(); err != nil {
		t.Fatalf("the first bind's answer: %v", err)
	}
	if _, err := h.judge(c, first.TD, firstReady, firstBind, first.Answer); err != nil {
		t.Fatalf("the first bind's answer: %v", err)
	}
	if err := second.Await(); err != nil {
		t.Fatalf("the second bind's answer, once its turn came: %v", err)
	}
	if second.TD == "" || second.TD == first.TD {
		t.Fatalf("the second bind was answered with TD %q, and the first with %q", second.TD, first.TD)
	}
	if _, err := h.judge(c, second.TD, secondReady, secondBind, second.Answer); err != nil {
		t.Fatalf("the second bind's answer: %v", err)
	}
}

// A caller that gives up while its bind waits its turn is told so, and its
// bind has reached no guest.
func TestCallerThatLeavesBeforeItsBindsTurnIsTold(t *testing.T) {
	sandbox := newHeld()
	h := &host{Host: sessiondtest.NewHostWith(t, 2, func(c *sessiond.Config) { c.BindsAtOnce = 1 }, sandbox), t: t}
	c, o := h.AsOrchestrator(), newOwner(t)
	w := watch(t, c, sessiondtest.Pool)
	eventually(t, "both ready TDs are shown", func() bool { return len(w.seen()) == 2 })
	shown := w.seen()
	bindFor := func(name string, guest *session.Relayed) *session.SignedBind {
		t.Helper()
		ready, err := session.VerifyReady(ctx(t), session.Policy{Image: h.Identity, LaunchKey: h.LaunchKey, Authority: o.authorityPub, AllowReady: true}, h.Engine, guest, time.Now())
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
		return bind
	}
	first, err := c.StartBind(ctx(t), requestID(t), "", bindFor("s1", shown[0]), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	select {
	case <-sandbox.preparing:
	case <-time.After(20 * time.Second):
		t.Fatal("the first guest never prepared its sandbox")
	}
	second, err := c.StartBind(ctx(t), requestID(t), "", bindFor("s2", shown[1]), nil)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	second.Close()
	time.Sleep(100 * time.Millisecond)
	select {
	case <-sandbox.preparing:
		t.Fatal("the bind of a caller that left reached a guest")
	default:
	}
	if w.gone(shown[1].Certificate) {
		t.Fatal("the bind of a caller that left took a TD from the pool")
	}
	close(sandbox.release)
	if err := first.Await(); err != nil {
		t.Fatalf("the first bind's answer: %v", err)
	}
}

// A caller may have as many binds waiting as the host runs TDs, and its next
// one is refused at once: it waits for nothing, reaches no guest and takes
// no TD.
func TestBindPastItsCallersLineIsRefusedAtOnce(t *testing.T) {
	sandbox := newHeld()
	h := &host{Host: sessiondtest.NewHostWith(t, 2, func(c *sessiond.Config) { c.BindsAtOnce, c.Capacity = 1, 2 }, sandbox), t: t}
	c, o := h.AsOrchestrator(), newOwner(t)
	w := watch(t, c, sessiondtest.Pool)
	eventually(t, "both ready TDs are shown", func() bool { return len(w.seen()) == 2 })
	shown := w.seen()
	bindFor := func(name string, guest *session.Relayed) *session.SignedBind {
		t.Helper()
		ready, err := session.VerifyReady(ctx(t), session.Policy{Image: h.Identity, LaunchKey: h.LaunchKey, Authority: o.authorityPub, AllowReady: true}, h.Engine, guest, time.Now())
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
		return bind
	}
	first, err := c.StartBind(ctx(t), requestID(t), "", bindFor("s1", shown[0]), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	select {
	case <-sandbox.preparing:
	case <-time.After(20 * time.Second):
		t.Fatal("the first guest never prepared its sandbox")
	}
	// Two more wait in line, which is then as long as the host has TDs.
	for _, name := range []string{"s2", "s3"} {
		waiting, err := c.StartBind(ctx(t), requestID(t), "", bindFor(name, shown[1]), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer waiting.Close()
	}
	time.Sleep(200 * time.Millisecond)
	began := time.Now()
	past, err := c.StartBind(ctx(t), requestID(t), "", bindFor("s4", shown[1]), nil)
	if err == nil {
		defer past.Close()
		err = past.Await()
	}
	if status.Code(err) != codes.ResourceExhausted || time.Since(began) > 5*time.Second {
		t.Fatalf("a bind past its caller's line: %v, after %v", err, time.Since(began))
	}
	select {
	case <-sandbox.preparing:
		t.Fatal("a bind reached a guest while the first guest was at work")
	default:
	}
	if w.gone(shown[1].Certificate) {
		t.Fatal("a bind that waited or was refused took a TD from the pool")
	}
	close(sandbox.release)
	if err := first.Await(); err != nil {
		t.Fatalf("the first bind's answer: %v", err)
	}
}

// A turn ends when the guest has sent its receipt and its quote, and does
// not wait for the command that came sealed with the bind: the next bind
// goes through while the first session's command still runs.
func TestBindsTurnDoesNotWaitOnItsCommand(t *testing.T) {
	h := newHost(t, 2, func(c *sessiond.Config) { c.BindsAtOnce = 1 })
	c, o := h.AsOrchestrator(), newOwner(t)
	first := h.seals(c, o, "s1", false)
	gate := filepath.Join(t.TempDir(), "go")
	long, err := session.SealWithBind(first.ready, first.bind, first.signer, session.SealedParts{
		Command: &session.ExecRequest{
			Argv: []string{"/bin/sh", "-c", `while [ ! -e "$GATE" ]; do sleep 0.02; done; echo done`},
			Env:  map[string]string{"GATE": gate},
		},
		Credentials: map[string][]byte{"api-token": credential},
	})
	if err != nil {
		t.Fatal(err)
	}
	one, err := c.BindWith(ctx(t), requestID(t), first.td, first.bind, long.Sealed)
	if err != nil {
		t.Fatalf("the first bind: %v", err)
	}
	defer one.Close()
	if _, err := one.Quote(ctx(t)); err != nil {
		t.Fatalf("the first bind's quote: %v", err)
	}
	// The first guest has said all of its bind, and its command runs on.
	second := h.seals(c, o, "s2", false)
	message := second.seal(t)
	answered := make(chan error, 1)
	var two *daemon.BindCall
	go func() {
		var err error
		two, err = c.BindWith(ctx(t), requestID(t), second.td, second.bind, message.Sealed)
		answered <- err
	}()
	select {
	case err := <-answered:
		if err != nil {
			t.Fatalf("the second bind, while the first session's command ran: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the second bind waited on the first session's command")
	}
	defer two.Close()
	if _, opened := result(t, two, message); opened.ExitCode != 0 {
		t.Fatalf("the second session's command: %+v", opened)
	}
	if err := os.WriteFile(gate, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	sealed, status, err := one.SealedAnswer()
	if err != nil || status != session.SealedTaken {
		t.Fatalf("the first session's sealed answer: %q, %v", status, err)
	}
	if opened, err := long.Open(sealed); err != nil || opened.Command == nil || string(opened.Command.Stdout) != "done\n" {
		t.Fatalf("the first session's command: %+v, %v", opened, err)
	}
}

// A TD that was claimed before its bind stays claimed while the bind waits
// its turn, past the claim's grace. A bind whose own time runs out as it
// waits is dropped: it reaches no guest, and its TD's claim lapses.
func TestClaimOutlastsItsGraceWhileItsBindWaits(t *testing.T) {
	sandbox := newHeld()
	h := &host{Host: sessiondtest.NewHostWith(t, 3, func(c *sessiond.Config) { c.BindsAtOnce = 1 }, sandbox), t: t}
	c, o := h.AsOrchestrator(), newOwner(t)
	claim := func(name string, grace time.Duration, life time.Duration) (string, *session.ReadyTD, *session.SignedBind) {
		t.Helper()
		claimed, err := c.Claim(ctx(t), requestID(t), sessiondtest.Pool, name, grace)
		if err != nil {
			t.Fatal(err)
		}
		ready, err := session.VerifyReady(ctx(t), session.Policy{Image: h.Identity, LaunchKey: h.LaunchKey, Authority: o.authorityPub, AllowReady: true}, h.Engine, claimed.Evidence, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		bind, err := session.NewBind(session.BindOptions{
			Authority: o.authority, InstanceKey: ready.InstanceKey, Tenant: "acme", Session: name, NotAfter: time.Now().Add(life),
			Policy: session.BindPolicy{Access: session.Access{Exec: []string{o.accessPub}}, Sandbox: &session.Sandbox{Image: sealedImage}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return claimed.TD, ready, bind
	}
	firstTD, _, firstBind := claim("s1", 10*time.Second, time.Minute)
	first, err := c.StartBind(ctx(t), requestID(t), firstTD, firstBind, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	select {
	case <-sandbox.preparing:
	case <-time.After(20 * time.Second):
		t.Fatal("the first guest never prepared its sandbox")
	}
	// Two more binds wait behind it: one whose TD's claim has a second of
	// grace, and one whose own time is a second.
	keptTD, keptReady, keptBind := claim("s2", time.Second, time.Minute)
	kept, err := c.StartBind(ctx(t), requestID(t), keptTD, keptBind, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer kept.Close()
	staleTD, _, staleBind := claim("s3", time.Second, time.Second)
	stale, err := c.StartBind(ctx(t), requestID(t), staleTD, staleBind, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stale.Close()
	time.Sleep(2500 * time.Millisecond)
	for _, td := range []string{keptTD, staleTD} {
		if state := h.Daemon.StateOf(td); state != sessiond.StateClaimed {
			t.Fatalf("while its bind waited past the claim's grace, the TD %s was %s", td, state)
		}
	}
	close(sandbox.release)
	if err := first.Await(); err != nil {
		t.Fatalf("the first bind's answer: %v", err)
	}
	if err := kept.Await(); err != nil {
		t.Fatalf("the bind whose TD's grace ran out as it waited: %v", err)
	}
	if _, err := h.judge(c, kept.TD, keptReady, keptBind, kept.Answer); kept.TD != "" && err != nil {
		t.Fatalf("its answer: %v", err)
	}
	wantCode(t, stale.Await(), codes.DeadlineExceeded, "a bind whose own time ran out as it waited")
	// The dropped bind reached no guest, and its TD went back to the pool.
	eventually(t, "the TD of the dropped bind is ready again", func() bool { return h.Daemon.StateOf(staleTD) == sessiond.StateReady })
}
