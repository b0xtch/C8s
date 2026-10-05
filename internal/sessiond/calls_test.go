package sessiond

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A claim relays the certificate its kept connection was made under only
// while that certificate is good for a while yet. One about to run out, or
// bytes that are no certificate, have the claim fetch the guest's again.
func TestClaimRelaysOnlyACertificateThatLasts(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	issue := func(notAfter time.Time) []byte {
		template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "guest"}, NotBefore: now.Add(-time.Hour), NotAfter: notAfter}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	for name, tc := range map[string]struct {
		leaf []byte
		want bool
	}{
		"good for a day":           {issue(now.Add(24 * time.Hour)), true},
		"good for the margin only": {issue(now.Add(certMargin)), false},
		"about to run out":         {issue(now.Add(time.Minute)), false},
		"run out":                  {issue(now.Add(-time.Minute)), false},
		"no certificate":           {[]byte("not a certificate"), false},
		"none":                     {nil, false},
	} {
		if got := lasts(tc.leaf, now); got != tc.want {
			t.Errorf("%s: lasts = %v, want %v", name, got, tc.want)
		}
	}
}

// A bind that names no TD finds its own: the ready TD of the instance key it
// names, which no other call holds, in a pool that lets its sender claim with
// a bind under that authority. Every other TD is none to it, and it is told
// so in one way. A repeat of the request finds the TD it claimed, whatever
// became of it, and a session that has a TD gets no second.
func TestBindFindsTheTDItClaims(t *testing.T) {
	const binder, authority = "sha256:binder", "sha256:authority"
	cfg := &Config{Pools: []Pool{
		{name: "named", Binders: []Binder{{Key: binder, Authorities: []string{authority}}, {Key: "sha256:watcher"}}},
		{name: "closed"},
	}}
	d := &Daemon{cfg: cfg, tds: map[string]*td{}, pools: map[string]*poolState{}}
	for i := range cfg.Pools {
		d.pools[cfg.Pools[i].name] = &poolState{cfg: &cfg.Pools[i]}
	}
	guest := func(id, pool, key string, state State) *td {
		t := &td{rec: record{ID: id, Pool: pool, State: state}, instanceKey: key}
		d.tds[id] = t
		return t
	}
	open, closed := guest("open", "named", "key-open", StateReady), guest("closed", "closed", "key-closed", StateReady)
	guest("busy", "named", "key-busy", StateReady).busy = true
	guest("bare", "named", "", StateReady)
	guest("booting", "named", "key-booting", StateBooting)
	guest("ended", "named", "key-ended", StateEnded).rec.Ended = &ended{Reason: "destroyed"}
	claimed := guest("claimed", "named", "key-claimed", StateClaimed)
	claimed.rec.Claim = &claim{RequestID: "r-claim", Session: "claimed-session"}

	as := func(key string, by claimant) *claimant {
		by.instanceKey, by.session = key, "s1"
		return &by
	}
	named, orchestrator := claimant{binder: binder, authority: authority}, claimant{orchestrator: true, authority: "sha256:any"}
	notReady := func(what string, c *claimant) {
		t.Helper()
		found, err := d.claimable(c, "r1")
		if found != nil || status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("%s: found %v, %v", what, found, err)
		}
		details := status.Convert(err).Details()
		if info, ok := details[0].(*errdetails.ErrorInfo); len(details) != 1 || !ok || info.GetReason() != "TD_NOT_READY" || info.GetDomain() != "sessions.c8s" {
			t.Fatalf("%s: refused without the reason a binder signs again on: %v", what, details)
		}
	}
	finds := func(what string, c *claimant, id string, want *td) {
		t.Helper()
		if found, err := d.claimable(c, id); err != nil || found != want {
			t.Fatalf("%s: found %v, %v", what, found, err)
		}
	}
	finds("a binder the pool names, under an authority it names", as("key-open", named), "r1", open)
	finds("an orchestrator, in a pool that names nobody", as("key-closed", orchestrator), "r1", closed)
	finds("an orchestrator, in any pool", as("key-open", orchestrator), "r1", open)
	notReady("a TD of a pool that does not name the binder", as("key-closed", named))
	notReady("a binder under an authority its pool does not name for it", as("key-open", claimant{binder: binder, authority: "sha256:another"}))
	notReady("a binder its pool lets watch and no more", as("key-open", claimant{binder: "sha256:watcher", authority: authority}))
	notReady("a TD another call holds", as("key-busy", orchestrator))
	notReady("a TD that boots", as("key-booting", orchestrator))
	notReady("a TD a claim holds", as("key-claimed", orchestrator))
	notReady("a TD that ended", as("key-ended", orchestrator))
	notReady("a key no TD holds", as("key-absent", orchestrator))
	// A TD the daemon knows no key of is nobody's by a bind that names none.
	notReady("a bind that names no key", as("", orchestrator))

	// The bind claimed its TD, and the session runs. The request again finds
	// that TD, and from nobody but its sender.
	open.rec.State, open.rec.Claim = StateRunning, &claim{RequestID: "r1", Session: "s1", ByBind: true, Binder: binder}
	finds("the same request again", as("key-open", named), "r1", open)
	for name, by := range map[string]claimant{"another binder": {binder: "sha256:other", authority: authority}, "an orchestrator": orchestrator} {
		if found, err := d.claimable(as("key-open", by), "r1"); found != nil || status.Code(err) != codes.InvalidArgument {
			t.Fatalf("%s under a binder's request id: found %v, %v", name, found, err)
		}
	}
	// The session has its TD: a bind for another claims none.
	if found, err := d.claimable(as("key-closed", orchestrator), "r2"); found != nil || status.Code(err) != codes.AlreadyExists {
		t.Fatalf("a second TD for a session that has one: found %v, %v", found, err)
	}
	// A claim's request id is no bind's: a bind under it claims as any other.
	other := as("key-closed", orchestrator)
	other.session = "s2"
	finds("a bind under a claim's request id", other, "r-claim", closed)
	// Once the session's TD has ended, the session may have another.
	open.rec.State = StateEnded
	finds("a bind for a session whose TD ended", as("key-closed", orchestrator), "r2", closed)
	finds("the first request again, after its TD ended", as("key-open", named), "r1", open)
}
