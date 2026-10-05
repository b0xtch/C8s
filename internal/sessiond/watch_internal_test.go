package sessiond

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	sessionv1alpha1 "github.com/confidential-dot-ai/c8s/api/session/v1alpha1"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

type (
	evidenceOf = sessionv1alpha1.Evidence
	changeOf   = sessionv1alpha1.ReadyChange
)

func firstOf(due []*changeOf, _ <-chan struct{}) []*changeOf { return due }

// readyOf is the TDs a stream was shown as ready, and leftOf the
// certificates of those it was told left.
func readyOf(due []*changeOf) (out []*evidenceOf) {
	for _, change := range due {
		if change.GetReady() != nil {
			out = append(out, change.GetReady())
		}
	}
	return out
}

func leftOf(due []*changeOf) (out [][sha256.Size]byte) {
	for _, change := range due {
		if len(change.GetLeft()) == sha256.Size {
			out = append(out, [sha256.Size]byte(change.GetLeft()))
		}
	}
	return out
}

// A stream that watches a pool is shown each ready TD once under each
// certificate it serves: again when the guest comes to serve another, and
// again when a TD that was claimed is ready once more. It is told when a TD
// it was shown is ready no more, by the certificate it was shown under. A TD
// of another pool, one that is not ready, one the daemon has kept nothing of
// and one whose certificate is about to run out are not shown: a claim of
// the last two asks the guest itself.
func TestWatcherIsShownEachReadyTDOnceUnderEachCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	serial := int64(0)
	issue := func(notAfter time.Time) []byte {
		serial++
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "guest"}, NotBefore: now.Add(-time.Hour), NotAfter: notAfter}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	lasting := func() []byte { return issue(now.Add(24 * time.Hour)) }
	said := func(launch string) *session.StateResponse {
		return &session.StateResponse{Phase: session.PhaseReady, Launch: []byte(launch), Signature: "signature of " + launch, Events: []string{"sha256:" + launch}}
	}
	guest := func(id, pool string, state State, age time.Duration, offered *session.StateResponse, leaf []byte) *td {
		return &td{rec: record{ID: id, Pool: pool, State: state, Created: now.Add(-age)}, offered: offered, leaf: leaf, collateral: []byte("documents of " + id)}
	}
	d := &Daemon{now: func() time.Time { return now }, changed: make(chan struct{}), tds: map[string]*td{}}
	pool := &poolState{cfg: &Pool{name: "agents"}}
	young, old := guest("young", "agents", StateReady, time.Minute, said("young"), lasting()), guest("old", "agents", StateReady, time.Hour, said("old"), lasting())
	for _, t := range []*td{
		young, old,
		guest("elsewhere", "another", StateReady, 2*time.Hour, said("elsewhere"), lasting()),
		guest("booting", "agents", StateBooting, 2*time.Hour, nil, nil),
		guest("claimed", "agents", StateClaimed, 2*time.Hour, said("claimed"), lasting()),
		guest("adopted", "agents", StateReady, 2*time.Hour, nil, nil),
		guest("expiring", "agents", StateReady, 2*time.Hour, said("expiring"), issue(now.Add(time.Minute))),
	} {
		d.tds[t.rec.ID] = t
	}
	names := func(due []*changeOf) []string {
		var out []string
		for _, e := range readyOf(due) {
			out = append(out, string(e.GetLaunchDocument()))
		}
		return out
	}
	shown := map[string][sha256.Size]byte{}
	due, changed := d.readyUnshown(pool, shown)
	if got := names(due); len(got) != 2 || got[0] != "old" || got[1] != "young" || len(leftOf(due)) != 0 {
		t.Fatalf("the watcher was shown %v, want the pool's two ready TDs, oldest first", got)
	}
	// Each as a claim of it is answered.
	first := due[0].GetReady()
	if string(first.GetCertificate()) != string(old.leaf) || string(first.GetLaunchSignature()) != "signature of old" ||
		first.GetPhase() != string(session.PhaseReady) || len(first.GetEvents()) != 1 || string(first.GetCollateral()) != "documents of old" {
		t.Fatalf("a ready TD was shown as %v", first)
	}
	if changed != (<-chan struct{})(d.changed) {
		t.Fatal("the watcher waits for another change than the daemon's next")
	}
	if again, _ := d.readyUnshown(pool, shown); len(again) != 0 {
		t.Fatalf("TDs that were shown were shown again: %v", names(again))
	}
	// The guest comes to serve another certificate: a claim is answered
	// with that one, so the watcher is shown it.
	before := sha256.Sum256(young.leaf)
	young.leaf = lasting()
	got, _ := d.readyUnshown(pool, shown)
	if ready := readyOf(got); len(ready) != 1 || string(ready[0].GetCertificate()) != string(young.leaf) {
		t.Fatalf("after a guest's certificate changed the watcher was shown %v", names(got))
	}
	// The certificate it served before is one no binder signs for any more,
	// and the watcher is told so before it is shown the next.
	if left := leftOf(got); len(left) != 1 || left[0] != before || got[0].GetReady() != nil {
		t.Fatalf("after a guest's certificate changed the watcher was told %d certificates left, the old one first: %t", len(left), got[0].GetReady() == nil)
	}
	// A claim takes the TD: the watcher is told it left, by the certificate
	// it was shown under. The claim gives it back: it is shown once more,
	// since a binder's verdict on it went when it left.
	old.rec.State = StateClaimed
	got, _ = d.readyUnshown(pool, shown)
	if left := leftOf(got); len(readyOf(got)) != 0 || len(left) != 1 || left[0] != sha256.Sum256(old.leaf) || len(shown) != 1 {
		t.Fatalf("after a claim the watcher was shown %v, told %d left, and remembers %d TDs", names(got), len(left), len(shown))
	}
	if again, _ := d.readyUnshown(pool, shown); len(again) != 0 {
		t.Fatalf("a TD that left was said to have left twice: %d changes", len(again))
	}
	old.rec.State = StateReady
	if got := names(firstOf(d.readyUnshown(pool, shown))); len(got) != 1 || got[0] != "old" {
		t.Fatalf("a TD that is ready again was shown as %v", got)
	}
	// The daemon comes to hold what an adopted TD says, and it is shown.
	d.tds["adopted"].offered, d.tds["adopted"].leaf = said("adopted"), lasting()
	if got := names(firstOf(d.readyUnshown(pool, shown))); len(got) != 1 || got[0] != "adopted" {
		t.Fatalf("a TD the daemon came to hold evidence of was shown as %v", got)
	}
	// A TD that ended is forgotten, so the watcher's memory is the pool's
	// ready TDs and no more.
	for _, id := range []string{"young", "old", "adopted", "expiring"} {
		d.tds[id].rec.State = StateEnded
	}
	got, _ = d.readyUnshown(pool, shown)
	if len(readyOf(got)) != 0 || len(leftOf(got)) != 3 || len(shown) != 0 {
		t.Fatalf("after every TD ended the watcher was shown %v, told %d left, and remembers %d", names(got), len(leftOf(got)), len(shown))
	}
}

// A stream that watches a host is shown each TD as it is, oldest first, and
// again only once its state or its session is another: with the binder that
// claimed it by a bind, with why it ended and when. A TD whose record the
// daemon keeps no more is shown as ended to a stream that was never shown its
// end.
func TestWatcherIsShownEachTDAsItIs(t *testing.T) {
	now := time.Now()
	d := &Daemon{cfg: &Config{Host: "host-a"}, now: func() time.Time { return now }, changed: make(chan struct{}), tds: map[string]*td{}}
	guest := func(id, pool string, state State, age time.Duration) *td {
		t := &td{rec: record{ID: id, Pool: pool, State: state, Created: now.Add(-age)}}
		d.tds[id] = t
		return t
	}
	old, young := guest("old", "agents", StateReady, time.Hour), guest("young", "agents", StateBooting, time.Minute)
	other := guest("other", "another", StateRunning, 2*time.Hour)
	other.rec.Claim = &claim{RequestID: "r0", Session: "s0"}
	type line struct {
		td, pool string
		state    sessionv1alpha1.TDState
		session  string
		by       string
		reason   string
	}
	shown := map[string]shownTD{}
	next := func() []line {
		t.Helper()
		due, changed := d.eventsUnshown(shown)
		if changed != d.changed {
			t.Fatal("a stream is not told when a TD next changes")
		}
		var out []line
		for _, e := range due {
			if e.GetHost() != "host-a" || e.GetAt() == nil {
				t.Fatalf("an event names host %q at %v", e.GetHost(), e.GetAt())
			}
			out = append(out, line{e.GetTd(), e.GetPool(), e.GetState(), e.GetSession(), e.GetClaimedBy(), e.GetReason()})
		}
		return out
	}
	want := func(what string, got []line, lines ...line) {
		t.Helper()
		if len(got) != len(lines) {
			t.Fatalf("%s: shown %+v, want %+v", what, got, lines)
		}
		for i := range lines {
			if got[i] != lines[i] {
				t.Fatalf("%s: event %d is %+v, want %+v", what, i, got[i], lines[i])
			}
		}
	}
	const ready, running, over = sessionv1alpha1.TDState_TD_STATE_READY, sessionv1alpha1.TDState_TD_STATE_RUNNING, sessionv1alpha1.TDState_TD_STATE_ENDED
	want("a new stream", next(),
		line{"other", "another", running, "s0", "", ""},
		line{"old", "agents", ready, "", "", ""},
		line{"young", "agents", sessionv1alpha1.TDState_TD_STATE_BOOTING, "", "", ""})
	want("nothing changed", next())

	// A binder's bind claims a TD and binds it, and a claim takes another.
	old.rec.State, old.rec.Claim = StateBound, &claim{RequestID: "r1", Session: "s1", ByBind: true, Binder: "sha256:binder"}
	young.rec.State = StateReady
	want("a bind that claimed, and a boot that ended", next(),
		line{"old", "agents", sessionv1alpha1.TDState_TD_STATE_BOUND, "s1", "sha256:binder", ""},
		line{"young", "agents", ready, "", "", ""})
	young.rec.State, young.rec.Claim = StateClaimed, &claim{RequestID: "r2", Session: "s2"}
	old.rec.State = StateRunning
	want("a claim, and a session that runs", next(),
		line{"old", "agents", running, "s1", "sha256:binder", ""},
		line{"young", "agents", sessionv1alpha1.TDState_TD_STATE_CLAIMED, "s2", "", ""})
	// The claim is given back: the TD is ready again, and nobody's.
	young.rec.State, young.rec.Claim = StateReady, nil
	want("a claim given back", next(), line{"young", "agents", ready, "", "", ""})

	// An end is shown with its reason, and at the time it came.
	at := now.Add(-time.Minute)
	old.rec.State, old.rec.Ended = StateEnded, &ended{At: at, Reason: "destroyed"}
	due, _ := d.eventsUnshown(shown)
	if len(due) != 1 || due[0].GetState() != over || due[0].GetReason() != "destroyed" || !due[0].GetAt().AsTime().Equal(at) || due[0].GetSession() != "s1" {
		t.Fatalf("an ended TD was shown as %v", due)
	}
	// Its record is kept no more: the stream was shown its end, and is shown
	// nothing further. One that was never shown the end of a TD is.
	delete(d.tds, "old")
	delete(d.tds, "other")
	delete(d.tds, "young")
	want("records kept no more", next(),
		line{"other", "another", over, "s0", "", forgotten},
		line{"young", "agents", over, "", "", forgotten})
	if len(shown) != 0 {
		t.Fatalf("a stream keeps %d TDs the daemon has forgotten", len(shown))
	}
	want("nothing is left", next())
}
