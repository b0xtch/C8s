package keyservice_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/keyservice/keyservicetest"
	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	api "github.com/confidential-dot-ai/c8s/pkg/session/keyservice"
	"github.com/confidential-dot-ai/c8s/pkg/session/sessionsim"
)

// stapling is an engine whose verdicts rest on a document somebody other
// than the vendor handed over, until own is set.
type stapling struct {
	sessiontest.Engine
	own atomic.Bool
}

func (e *stapling) VerifyEvidence(ctx context.Context, env teetypes.AttestationEvidence, reportData []byte) (*teetypes.VerificationResult, error) {
	res, err := e.Engine.VerifyEvidence(ctx, env, reportData)
	if err != nil {
		return nil, err
	}
	if res.Claims.PlatformData == nil {
		res.Claims.PlatformData = map[string]any{}
	}
	now := time.Now()
	res.Claims.PlatformData[session.CollateralClaim] = &session.CollateralFinding{Stapled: !e.own.Load(), Fetched: now, Expires: now.Add(24 * time.Hour)}
	return res, nil
}

// pinned is what a binder pins of a guest's pool: its image and launch key.
func pinned(t *testing.T, g *sessionsim.Guest) (runtimemeasure.ImageIdentity, []byte) {
	t.Helper()
	identity, err := runtimemeasure.LoadImageManifest(g.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	launchKey, err := os.ReadFile(g.LaunchKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	return identity, launchKey
}

// led is a road whose far end a test chooses: the replica a new connection
// reaches, whatever address was asked for, or none. It counts the
// connections made over it, and those its user has closed.
type led struct {
	to             atomic.Pointer[keyservicetest.Sim]
	dialed, closed atomic.Int64
}

func (l *led) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	replica := l.to.Load()
	if replica == nil {
		return nil, errors.New("no road to the key service")
	}
	conn, err := replica.Dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	l.dialed.Add(1)
	return &ledConn{Conn: conn, road: l}, nil
}

type ledConn struct {
	net.Conn
	road *led
	once sync.Once
}

func (c *ledConn) Close() error {
	c.once.Do(func() { c.road.closed.Add(1) })
	return c.Conn.Close()
}

// A binder judges the replica of the key service it pins ahead of its binds,
// as it judges a guest it sends a secret: on the vendor's documents as its
// engine fetched them within the hour, and anew once a newer document came.
// A bind then names that replica at no cost. A replica the binder refuses
// leaves it nothing to name, and one it cannot reach leaves it the verdict it
// has, for what is left of that verdict's hour.
func TestBinderJudgesItsKeyServicesReplicaAheadOfItsBinds(t *testing.T) {
	w := newWorld(t)
	twin := w.ks.Twin(t)
	now := time.Now()
	clock := now
	engine := &vendor{now: func() time.Time { return clock }, fetched: now}
	way := &led{}
	way.to.Store(w.ks)
	members, err := api.NewMembers(api.Options{Pin: w.ks.Pin, Engine: engine, Dial: way.dial, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	defer members.Close()
	names := func(what string, want []string, judgments int) {
		t.Helper()
		before := engine.judged()
		named, err := members.Named(within(t))
		if err != nil || !slices.Equal(named, want) {
			t.Fatalf("%s: the binder names %v, %v", what, named, err)
		}
		if got := engine.judged() - before; got != judgments {
			t.Fatalf("%s: %d judgments were made on the path, want %d", what, got, judgments)
		}
	}
	names("a binder that has judged nothing yet", w.ks.Members, 1)
	names("a verdict that stands", w.ks.Members, 0)

	// A newer document: the verdict rests on what the engine no longer holds
	// as its newest, and is made again where it is needed.
	engine.set(func(v *vendor) { v.documents++ })
	names("after a newer document", w.ks.Members, 1)
	// A judgment made while the engine still took a document in rests on one
	// or the other, so it is made once more.
	engine.set(func(v *vendor) { v.taking = 1 })
	before := engine.judged()
	if _, err := members.Judge(within(t)); err != nil || engine.judged()-before != 2 {
		t.Fatalf("a judgment while a document came in: %v, %d judgments", err, engine.judged()-before)
	}
	names("after it settled", w.ks.Members, 0)

	// The verdict ends an hour after the documents under it were fetched. A
	// binder that cannot have newer ones then names nobody.
	clock = now.Add(time.Hour - time.Second)
	names("a verdict in its last second", w.ks.Members, 0)
	clock = now.Add(time.Hour)
	if named, err := members.Named(within(t)); !errors.Is(err, session.ErrStaleDocuments) {
		t.Fatalf("on documents an hour old the binder names %v, %v", named, err)
	}
	engine.set(func(v *vendor) { v.fetched = clock; v.documents++ })
	names("once the vendor answered again", w.ks.Members, 1)

	// A key service out of reach: the verdict the binder has still stands,
	// and a judgment that could not be made takes nothing from it.
	way.to.Store(nil)
	if _, err := members.Judge(within(t)); err == nil {
		t.Fatal("a replica nobody reached was judged")
	}
	names("while the key service is out of reach", w.ks.Members, 0)
	clock = clock.Add(time.Hour)
	if named, err := members.Named(within(t)); err == nil {
		t.Fatalf("out of reach, past the verdict's hour, the binder names %v", named)
	}

	// The replica came back under another key: the next judgment learns of
	// it, and the one before is named no more.
	way.to.Store(twin)
	engine.set(func(v *vendor) { v.fetched = clock })
	if member, err := members.Judge(within(t)); err != nil || member.Key != twin.Members[0] || !member.Until.Equal(clock.Add(time.Hour)) {
		t.Fatalf("the replica that answers now was judged as %+v, %v", member, err)
	}
	names("after the replica was replaced", twin.Members, 0)

	// A replica whose platform the vendor refuses is named by nobody, and
	// neither is the verdict from before.
	engine.set(func(v *vendor) { v.revoked = true })
	var refused *session.VerificationError
	if _, err := members.Judge(within(t)); !errors.As(err, &refused) {
		t.Fatalf("a replica on a revoked platform: %v", err)
	}
	if named, err := members.Named(within(t)); !errors.As(err, &refused) {
		t.Fatalf("after its replica was refused the binder names %v, %v", named, err)
	}

	// A binder judges as itself, and on the vendor's own word.
	for name, opts := range map[string]api.Options{
		"documents somebody handed over": {Pin: w.ks.Pin, Engine: engine, Judging: session.AllowHandedDocuments},
		"a certificate":                  {Pin: w.ks.Pin, Engine: engine, Certificate: func() (*tls.Certificate, error) { return nil, nil }},
	} {
		if _, err := api.NewMembers(opts); err == nil {
			t.Errorf("a keeper of verdicts on replicas was made with %s", name)
		}
	}
}

// A verdict that lets others rely on a replica rests on nothing somebody
// other than the vendor handed over, whatever its client takes for its other
// calls.
func TestReplicaIsNamedOnTheVendorsOwnWordAlone(t *testing.T) {
	w := newWorld(t)
	handed := &stapling{}
	members, err := api.NewMembers(api.Options{Pin: w.ks.Pin, Engine: handed})
	if err != nil {
		t.Fatal(err)
	}
	defer members.Close()
	if named, err := members.Named(within(t)); err == nil {
		t.Fatalf("on a document somebody handed over the binder names %v", named)
	}
	// A client that takes handed-over documents for its own calls, as a
	// guest's does, judges a replica for a bind no other way.
	lenient, err := api.NewClient(api.Options{Pin: w.ks.Pin, Engine: handed, Judging: session.AllowHandedDocuments})
	if err != nil {
		t.Fatal(err)
	}
	defer lenient.Close()
	if err := lenient.Verify(within(t)); err != nil {
		t.Fatalf("a client that takes handed-over documents, on one: %v", err)
	}
	if member, err := lenient.Member(within(t)); err == nil {
		t.Fatalf("that client judged a replica for a bind on a handed-over document: %+v", member)
	}
	// The same evidence, on the engine's own documents, is named.
	handed.own.Store(true)
	if named, err := members.Named(within(t)); err != nil || !slices.Equal(named, w.ks.Members) {
		t.Fatalf("on the vendor's own documents the binder names %v, %v", named, err)
	}
}

// A guest that waited long enough to open its session again, under its next
// certificate, knows which replica that session is with: a bind that names
// that replica finds nothing to do, and one that names the replica of its
// first session has it open a third.
func TestGuestKnowsTheReplicaItOpenedAgainWith(t *testing.T) {
	w := newWorld(t)
	twin := w.ks.Twin(t)
	c, err := api.NewClient(api.Options{Pin: w.ks.Pin, Engine: sessionsim.Engine(), Dial: twin.Dial})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.RegisterAuthority(within(t), "acme", w.owner.pub, w.owner.signer); err != nil {
		t.Fatal(err)
	}
	if err := c.PutCredential(within(t), "acme", "token", []byte("the twin's"), w.owner.signer); err != nil {
		t.Fatal(err)
	}
	way := &led{}
	way.to.Store(w.ks)
	w.pool.KeyServiceDial = way.dial
	w.pool.CertTTL = 4 * time.Second
	g := w.pool.Boot(t, nil, w.ks.Pin)
	for deadline := time.Now().Add(10 * time.Second); !offered(t, g); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the guest never opened its session with the key service")
		}
	}
	// From here on its host leads it to the twin, where its next certificate
	// takes it.
	way.to.Store(twin)
	for deadline := time.Now().Add(15 * time.Second); g.Logged("opened the session with the key service again, under a new certificate") == 0; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the guest did not open its session again under its next certificate")
		}
	}
	dialed := way.dialed.Load()
	binder, key, err := w.startNaming(t, g, twin.Members)
	if err != nil {
		t.Fatalf("a bind that names the replica the guest opened again with: %v", err)
	}
	if got := g.Logged("the session with the key service is with a replica the bind does not name"); got != 0 {
		t.Fatal("the guest took the replica it opened again with for the one before")
	}
	// A guest opens again as often as its certificates end, bind or no bind,
	// until it is bound: what the bind added is no connection of its own.
	if again := int64(g.Logged("opened the session with the key service again, with a replica the bind names")); again != 0 || way.dialed.Load()-dialed > 1 {
		t.Fatalf("the bind had the guest open %d sessions and make %d connections", again, way.dialed.Load()-dialed)
	}
	result, err := binder.Exec(within(t), session.ExecRequest{Argv: []string{"sh", "-c", `cat "$C8S_CREDENTIALS_DIR/token"`}})
	if err != nil || string(result.Stdout) != "the twin's" {
		t.Fatalf("the sandbox read %q, %v", result.Stdout, err)
	}
	if _, _, bound, _ := w.ks.Service.Verdict(key); bound {
		t.Fatal("the replica of the guest's first session was shown its bind")
	}
}

// A client that is held to replicas deals with no other: a connection that
// ends elsewhere is dropped once the far end's evidence has shown which
// replica it is, before the client says anything of its own. One held to
// nobody deals with nobody.
func TestClientHeldToReplicasDealsWithNoOther(t *testing.T) {
	w := newWorld(t)
	twin := w.ks.Twin(t)
	g := newGuest(t, w.pool, w.ks)
	var other *api.NotMemberError

	// Held to the twin, and led to the first replica.
	g.client.Hold(twin.Members)
	if err := g.open(); !errors.As(err, &other) || other.Replica != w.ks.Members[0] {
		t.Fatalf("an open that ended at a replica the client is held away from: %v", err)
	}
	if _, _, _, ok := w.ks.Service.Verdict(g.keyDigest); ok {
		t.Fatal("a replica the guest is held away from was sent its launch document")
	}
	// Held to the first, or to both, it opens its session there.
	for _, members := range [][]string{w.ks.Members, {twin.Members[0], w.ks.Members[0]}} {
		g.client.Hold(members)
		if err := g.open(); err != nil {
			t.Fatalf("an open with a replica the client is held to: %v", err)
		}
	}
	if _, _, _, ok := w.ks.Service.Verdict(g.keyDigest); !ok {
		t.Fatal("the replica the client is held to did not take the guest's session")
	}
	bind := g.bind(w.owner, w.ks, nil)
	// Held away from the replica its connection ends at, the client drops
	// that connection: the next call finds none it may use.
	g.client.Hold(twin.Members)
	if _, err := g.acquire(bind, "token"); !errors.As(err, &other) {
		t.Fatalf("an acquire from a replica the client was since held away from: %v", err)
	}
	if _, _, bound, _ := w.ks.Service.Verdict(g.keyDigest); bound {
		t.Fatal("a replica the guest is held away from was shown its bind")
	}
	// Held to nobody, it deals with nobody.
	g.client.Hold(nil)
	if err := g.open(); !errors.As(err, &other) {
		t.Fatalf("an open from a client held to nobody: %v", err)
	}
	// Held to the first again, it takes its credential there.
	g.client.Hold(w.ks.Members)
	if answer, err := g.acquire(bind, "token"); err != nil || len(answer.Credentials) != 1 {
		t.Fatalf("an acquire from the replica the client is held to: %v", err)
	}
}

// A guest judges its key service before its bind on what its host hands it,
// so from its bind on it deals with none but the replicas the bind names,
// which the binder judged on the vendor's own documents. A guest whose
// session is with another replica opens one with a replica the bind names,
// and one that reaches none refuses its bind and ends: it takes nothing from
// a replica nobody vouched for, and shows it no bind.
func TestGuestHoldsItsKeyServiceToTheReplicasItsBindNames(t *testing.T) {
	w := newWorld(t)
	twin := w.ks.Twin(t)
	// The twin holds the same tenant, and another secret under the same name.
	c, err := api.NewClient(api.Options{Pin: w.ks.Pin, Engine: sessionsim.Engine(), Dial: twin.Dial})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.RegisterAuthority(within(t), "acme", w.owner.pub, w.owner.signer); err != nil {
		t.Fatal(err)
	}
	if err := c.PutCredential(within(t), "acme", "token", []byte("the twin's"), w.owner.signer); err != nil {
		t.Fatal(err)
	}
	way := &led{}
	w.pool.KeyServiceDial = way.dial
	// boot is a guest of the pool whose session is with the first replica.
	boot := func(t *testing.T) *sessionsim.Guest {
		t.Helper()
		way.to.Store(w.ks)
		g := w.pool.Boot(t, nil, w.ks.Pin)
		for deadline := time.Now().Add(10 * time.Second); !offered(t, g); time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("the guest never opened its session with the key service")
			}
		}
		return g
	}
	read := func(t *testing.T, binder *session.Client) string {
		t.Helper()
		result, err := binder.Exec(within(t), session.ExecRequest{Argv: []string{"sh", "-c", `cat "$C8S_CREDENTIALS_DIR/token"`}})
		if err != nil {
			t.Fatal(err)
		}
		return string(result.Stdout)
	}
	released := func(replica *keyservicetest.Sim, guest string) (known, bound bool) {
		_, _, bound, known = replica.Service.Verdict(guest)
		return known, bound
	}

	t.Run("its session is with a replica the bind names", func(t *testing.T) {
		g := boot(t)
		// Led elsewhere from here on: the guest has no cause to go there.
		way.to.Store(twin)
		binder, key, err := w.startNaming(t, g, []string{twin.Members[0], w.ks.Members[0]})
		if err != nil {
			t.Fatalf("bind: %v", err)
		}
		if got := read(t, binder); got != "s3cret" {
			t.Fatalf("the sandbox read %q", got)
		}
		if known, _ := released(twin, key); known {
			t.Fatal("a guest whose session was with a named replica opened one with another")
		}
		if g.Logged("the session with the key service is with a replica the bind does not name") != 0 {
			t.Fatal("the guest says its session was with a replica the bind does not name")
		}
	})

	t.Run("it opens a session with a replica the bind names", func(t *testing.T) {
		g := boot(t)
		way.to.Store(twin)
		binder, key, err := w.startNaming(t, g, twin.Members)
		if err != nil {
			t.Fatalf("bind: %v", err)
		}
		// What the sandbox holds came from the replica the bind names.
		if got := read(t, binder); got != "the twin's" {
			t.Fatalf("the sandbox read %q", got)
		}
		if known, bound := released(w.ks, key); !known || bound {
			t.Fatalf("the replica the bind does not name: session %t, bind shown %t", known, bound)
		}
		if _, bound := released(twin, key); !bound {
			t.Fatal("the replica the bind names released nothing")
		}
	})

	// open is how many connections made over the road are not closed.
	open := func() int64 { return way.dialed.Load() - way.closed.Load() }

	t.Run("it reaches none the bind names", func(t *testing.T) {
		others := open()
		g := boot(t)
		// Its host leads it to the replica it has, whatever the bind names.
		before := way.dialed.Load()
		_, key, err := w.startNaming(t, g, twin.Members)
		if err == nil || !strings.Contains(err.Error(), "no replica of its key service that the bind names") {
			t.Fatalf("a bind that names a replica the guest cannot reach: %v", err)
		}
		// It tried three times, and left each connection at the handshake.
		if tried := way.dialed.Load() - before; tried != 3 {
			t.Fatalf("the guest opened %d connections to find a replica the bind names", tried)
		}
		if kept := open() - others; kept != 0 {
			t.Fatalf("the guest keeps %d connections to a replica the bind does not name", kept)
		}
		if known, bound := released(w.ks, key); !known || bound {
			t.Fatalf("the replica the bind does not name: session %t, bind shown %t", known, bound)
		}
		if known, _ := released(twin, key); known {
			t.Fatal("the replica the bind names heard of a guest that never reached it")
		}
		if got := g.Logged("the session with the key service is with a replica the bind does not name"); got != 1 {
			t.Fatalf("the guest said %d times that its session was with another replica", got)
		}
		// It read a bind it did not take, so it takes no other: one that names
		// the replica it has comes too late.
		if _, _, err := w.startNaming(t, g, w.ks.Members); err == nil || !strings.Contains(err.Error(), "takes no bind any more") {
			t.Fatalf("a second bind for a guest that refused its first: %v", err)
		}
		if _, bound := released(w.ks, key); bound {
			t.Fatal("a guest that refused its bind showed its key service another")
		}
	})

	t.Run("a bind that names no key service ends its dealings with one", func(t *testing.T) {
		others := open()
		g := boot(t)
		if kept := open() - others; kept != 1 {
			t.Fatalf("a guest with a session open keeps %d connections to its key service", kept)
		}
		identity, launchKey := pinned(t, g)
		access := newOwner(t)
		binder, err := session.NewClient(g.URL, session.Policy{Image: identity, LaunchKey: launchKey, Authority: w.owner.pub, AllowReady: true}, sessionsim.Engine(), access.signer)
		if err != nil {
			t.Fatal(err)
		}
		defer binder.Close()
		ready, err := binder.Ready(within(t))
		if err != nil {
			t.Fatal(err)
		}
		bind, err := session.NewBind(session.BindOptions{
			Authority: w.owner.key, InstanceKey: ready.InstanceKey, Tenant: "acme", Session: "s1", NotAfter: time.Now().Add(time.Minute),
			Policy: session.BindPolicy{Access: session.Access{Exec: []string{string(access.pub)}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		binding := session.Binding{LaunchKey: launchKey, Launch: ready.Launch, Bind: bind}
		if _, _, err := binder.BindAttested(within(t), bind, binding.Policy(identity)); err != nil {
			t.Fatalf("bind: %v", err)
		}
		if got := g.Logged("the bind names no key service, and the guest deals with its pool's no more"); got != 1 {
			t.Fatalf("the guest said %d times that it deals with no key service any more", got)
		}
		// The session it had is closed: no connection of the guest's to its
		// key service is left.
		if kept := open() - others; kept != 0 {
			t.Fatalf("the guest keeps %d connections to a key service its bind does not name", kept)
		}
		if _, bound := released(w.ks, bind.Doc.InstanceKey); bound {
			t.Fatal("the key service was shown a bind that does not name it")
		}
	})
}
