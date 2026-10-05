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

type evidenceOf = sessionv1alpha1.Evidence

func firstOf(due []*evidenceOf, _ <-chan struct{}) []*evidenceOf { return due }

// A stream that watches a pool is shown each ready TD once under each
// certificate it serves: again when the guest comes to serve another, and
// again when a TD that was claimed is ready once more. A TD of another pool,
// one that is not ready, one the daemon has kept nothing of and one whose
// certificate is about to run out are not shown: a claim of the last two
// asks the guest itself.
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
	names := func(due []*evidenceOf) []string {
		out := make([]string, len(due))
		for i, e := range due {
			out[i] = string(e.GetLaunchDocument())
		}
		return out
	}
	shown := map[string][sha256.Size]byte{}
	due, changed := d.readyUnshown(pool, shown)
	if got := names(due); len(got) != 2 || got[0] != "old" || got[1] != "young" {
		t.Fatalf("the watcher was shown %v, want the pool's two ready TDs, oldest first", got)
	}
	// Each as a claim of it is answered.
	first := due[0]
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
	young.leaf = lasting()
	if got, _ := d.readyUnshown(pool, shown); len(got) != 1 || string(got[0].GetCertificate()) != string(young.leaf) {
		t.Fatalf("after a guest's certificate changed the watcher was shown %v", names(got))
	}
	// A claim takes the TD, and gives it back: it is shown once more, since
	// a binder's verdict on it went with the claim.
	old.rec.State = StateClaimed
	if got, _ := d.readyUnshown(pool, shown); len(got) != 0 || len(shown) != 1 {
		t.Fatalf("after a claim the watcher was shown %v and remembers %d TDs", names(got), len(shown))
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
	if got, _ := d.readyUnshown(pool, shown); len(got) != 0 || len(shown) != 0 {
		t.Fatalf("after every TD ended the watcher was shown %v and remembers %d", names(got), len(shown))
	}
}
