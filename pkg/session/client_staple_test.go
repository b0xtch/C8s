package session_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// judgment is what one judgment's context gave an engine that was short of
// Intel's documents.
type judgment struct {
	// named: the context names somebody to ask.
	named bool
	// docs is how many documents that somebody handed over.
	docs int
	// root: the verdict may rest on a root CA CRL from them.
	root bool
}

// asking is the test engine as one with none of Intel's documents: at every
// judgment it asks whoever the context names, and notes what it was allowed.
type asking struct {
	sessiontest.Engine
	mu   sync.Mutex
	seen []judgment
}

func (e *asking) VerifyEvidence(ctx context.Context, env teetypes.AttestationEvidence, reportData []byte) (*teetypes.VerificationResult, error) {
	docs, named := session.Stapled(ctx)
	e.mu.Lock()
	e.seen = append(e.seen, judgment{named: named, docs: len(docs), root: session.MayStapleRoot(ctx)})
	e.mu.Unlock()
	return e.Engine.VerifyEvidence(ctx, env, reportData)
}

func (e *asking) judgments() []judgment {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.seen)
}

// handedIn is what a host hands a guest: n documents, of which nothing but
// the count matters here.
func handedIn(t *testing.T, n int) []byte {
	t.Helper()
	var answer session.CollateralResponse
	for i := range n {
		answer.Documents = append(answer.Documents, session.CollateralDocument{
			URL: "https://pcs.example/" + string(rune('a'+i)), Body: []byte("body"),
		})
	}
	blob, err := json.Marshal(answer)
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

// A client asks its guest for Intel's documents once, on a connection of its
// own, when a judgment is short of one. A verdict from before the pin may
// rest on the root CA CRL among them. The judgment that pins the guest, and
// every verdict after, may not.
func TestClientTakesIntelsDocumentsFromItsGuest(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	s.agent.KeepCollateral(handedIn(t, 4))
	hop := sessiontest.NewHop(t, s.addr)
	engine := &asking{}
	var mu sync.Mutex
	var steps []string
	client, err := session.NewClient(hop.URL, s.policy, engine, s.signer, session.Timed(func(step string, _ time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		steps = append(steps, step)
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	now := &clock{now: time.Now()}
	client.SetNow(now.Now)

	if _, err := client.Attest(within(t)); err != nil {
		t.Fatal(err)
	}
	want := []judgment{{named: true, docs: 4, root: true}, {named: true, docs: 4, root: false}}
	if got := engine.judgments(); !slices.Equal(got, want) {
		t.Fatalf("the handshake gate and the judgment that pins saw %+v, want %+v", got, want)
	}
	// The connection it asked on, and the one it verified.
	if n := hop.Accepted(); n != 2 {
		t.Fatalf("%d connections, want one to ask on and one verified", n)
	}
	mu.Lock()
	got := strings.Join(steps, ", ")
	mu.Unlock()
	if want := "dial, staple, serving_verdict, handshake, request /v1/attest, judgment"; got != want {
		t.Fatalf("steps: %s\n want: %s", got, want)
	}

	// The gate's verdict runs out. The guest is pinned by then, and what the
	// gate decides now is what commands rest on.
	now.advance(session.ServingVerdictTTL)
	client.Close()
	run(t, client)
	seen := engine.judgments()
	if last := seen[len(seen)-1]; len(seen) != 3 || !last.named || last.root {
		t.Fatalf("after the pin the gate saw %+v", seen)
	}
	// It asked the guest once, whatever came after.
	if n := hop.Accepted(); n != 3 {
		t.Fatalf("%d connections, want the two from before and one for the command", n)
	}
}

// The check that a guest is unbound leads to a bind, which is not secret: it
// may rest on a root CA CRL the guest handed over. The judgment of the bound
// guest may not.
func TestReadyCheckMayRestOnAStapledRootCRL(t *testing.T) {
	s := serveReady(t, sessiontest.NewTD())
	s.agent.KeepCollateral(handedIn(t, 4))
	engine := &asking{}
	client, err := session.NewClient("https://"+s.addr, s.policy, engine, s.signer)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ready, err := client.Ready(within(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []judgment{{named: true, docs: 4, root: true}, {named: true, docs: 4, root: true}}
	if got := engine.judgments(); !slices.Equal(got, want) {
		t.Fatalf("the handshake gate and the ready check saw %+v, want %+v", got, want)
	}
	bind, err := session.NewBind(session.BindOptions{
		Authority: s.authority, InstanceKey: ready.InstanceKey,
		Tenant: "acme", Session: "sbx-1", NotAfter: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	bound := s.policy
	bound.Launch, bound.Bind, bound.AllowReady = ready.Launch, bind.Raw, false
	if _, _, err := client.BindAttested(within(t), bind, bound); err != nil {
		t.Fatal(err)
	}
	seen := engine.judgments()
	if last := seen[len(seen)-1]; len(seen) != 3 || !last.named || last.root {
		t.Fatalf("the judgment of the bound guest saw %+v", seen)
	}
}

// stapling is a guest's address as a client reaches it: the client's second
// connection, the one it asks for Intel's documents on, lands at a server of
// the test's that notes what arrives. Every other one reaches the guest.
type stapling struct {
	guest string
	srv   *httptest.Server

	mu       sync.Mutex
	dials    int
	requests []*http.Request
	bodies   [][]byte
	// closed is told when the server's side of a connection ends, and hung
	// up when the client closes its own.
	closed, hungUp chan struct{}
}

// hangingUp tells when its owner closes it.
type hangingUp struct {
	net.Conn
	told chan<- struct{}
}

func (c hangingUp) Close() error {
	select {
	case c.told <- struct{}{}:
	default:
	}
	return c.Conn.Close()
}

func newStapling(t *testing.T, guest string, answer http.HandlerFunc) *stapling {
	t.Helper()
	s := &stapling{guest: guest, closed: make(chan struct{}, 16), hungUp: make(chan struct{}, 1)}
	s.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.requests, s.bodies = append(s.requests, r), append(s.bodies, body)
		s.mu.Unlock()
		answer(w, r)
	}))
	s.srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			s.closed <- struct{}{}
		}
	}
	s.srv.StartTLS()
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stapling) dial(ctx context.Context, network, _ string) (net.Conn, error) {
	s.mu.Lock()
	s.dials++
	second := s.dials == 2
	s.mu.Unlock()
	if !second {
		return (&net.Dialer{}).DialContext(ctx, network, s.guest)
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, network, s.srv.Listener.Addr().String())
	if err != nil {
		return nil, err
	}
	return hangingUp{Conn: conn, told: s.hungUp}, nil
}

// The connection a client asks for Intel's documents on is verified by
// nothing, so it carries nothing: one request with no token and no body, and
// then it is closed.
func TestStapleConnectionCarriesNothing(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	blob := handedIn(t, 4)
	road := newStapling(t, s.addr, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(blob) })
	engine := &asking{}
	client, _ := clientFor(t, "https://"+s.addr, s, engine)
	client.SetDial(road.dial)

	if _, err := client.Attest(within(t)); err != nil {
		t.Fatal(err)
	}
	run(t, client)
	if got := engine.judgments(); len(got) != 2 || got[0].docs != 4 {
		t.Fatalf("judgments %+v", got)
	}
	// The client hangs up itself, whatever the other end does.
	select {
	case <-road.hungUp:
	default:
		t.Fatal("the client left the connection open")
	}
	select {
	case <-road.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the connection was left open")
	}
	road.mu.Lock()
	defer road.mu.Unlock()
	if len(road.requests) != 1 {
		t.Fatalf("%d requests on the connection nothing verified", len(road.requests))
	}
	r := road.requests[0]
	if r.Method != http.MethodGet || r.URL.Path != session.PathCollateral || r.URL.RawQuery != "" || len(road.bodies[0]) != 0 {
		t.Fatalf("the request: %s %s with %d bytes", r.Method, r.URL, len(road.bodies[0]))
	}
	for name := range r.Header {
		if !slices.Contains([]string{"Connection", "User-Agent"}, name) {
			t.Errorf("the request carries header %s: %v", name, r.Header[name])
		}
	}
	if !r.Close {
		t.Error("the request leaves the connection open for another")
	}
}

// What comes back on that connection is a stranger's word. Whatever is not
// an answer of the expected shape and size is no answer, and costs the
// client nothing but a fetch from Intel.
func TestStapleAnswerThatIsNone(t *testing.T) {
	session.SetStapleTimeout(t, 200*time.Millisecond)
	for name, tc := range map[string]struct {
		answer http.HandlerFunc
		docs   int
	}{
		"control":   {func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(handedIn(t, 4)) }, 4},
		"the most":  {func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(handedIn(t, 8)) }, 8},
		"too many":  {func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(handedIn(t, 9)) }, 0},
		"not found": {func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) }, 0},
		"an error with documents": {func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write(handedIn(t, 4))
		}, 0},
		"not JSON": {func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }, 0},
		"too large": {func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(append(bytes.TrimSuffix(handedIn(t, 4), []byte("}")), []byte(`,"pad":"`+strings.Repeat("a", session.MaxCollateralBytes)+`"}`)...))
		}, 0},
		// Until the client gives up and closes.
		"no answer in time": {func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }, 0},
	} {
		t.Run(name, func(t *testing.T) {
			s := serve(t, sessiontest.NewTD(), nil)
			road := newStapling(t, s.addr, tc.answer)
			engine := &asking{}
			client, _ := clientFor(t, "https://"+s.addr, s, engine)
			client.SetDial(road.dial)
			if _, err := client.Attest(within(t)); err != nil {
				t.Fatalf("the client did not go on: %v", err)
			}
			if got := engine.judgments(); len(got) != 2 || got[0].docs != tc.docs || got[1].docs != tc.docs {
				t.Fatalf("judgments %+v, want %d documents", got, tc.docs)
			}
		})
	}
}

// A guest with nothing to hand over, and one that cannot be reached a second
// time, cost the client nothing but the question.
func TestGuestWithNoDocumentsToHandOver(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	hop := sessiontest.NewHop(t, s.addr)
	engine := &asking{}
	client, _ := clientFor(t, hop.URL, s, engine)
	for range 2 {
		if _, err := client.Attest(within(t)); err != nil {
			t.Fatal(err)
		}
	}
	// The gate, and the judgment of each attestation. Each asked, and the
	// client asked its guest once for all of them.
	want := []judgment{{named: true, root: true}, {named: true}, {named: true}}
	if got := engine.judgments(); !slices.Equal(got, want) {
		t.Fatalf("judgments %+v, want %+v", got, want)
	}
	if n := hop.Accepted(); n != 2 {
		t.Fatalf("%d connections, want one to ask on and one verified", n)
	}

	refusing := &stapling{guest: s.addr}
	client, _ = clientFor(t, "https://"+s.addr, s, &asking{})
	client.SetDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
		refusing.mu.Lock()
		refusing.dials++
		second := refusing.dials == 2
		refusing.mu.Unlock()
		if second {
			return nil, context.DeadlineExceeded
		}
		return (&net.Dialer{}).DialContext(ctx, network, s.addr)
	})
	if _, err := client.Attest(within(t)); err != nil {
		t.Fatalf("a guest that could not be asked: %v", err)
	}
}

// A verdict the gate reached before the pin releases nothing, and may rest
// on less than a command needs. The pin ends it: from then on the gate goes
// by the judgment that pinned the guest, also when a clock that moved makes
// the earlier verdict the longer one.
func TestGateVerdictFromBeforeThePinEndsWithIt(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	engine := &asking{}
	client, now := clientFor(t, "https://"+s.addr, s, engine)

	// The gate judges the certificate at t0, and nothing pins the guest yet.
	if _, err := client.FetchEvidence(within(t)); err != nil {
		t.Fatal(err)
	}
	// The clock moves back, and the judgment that pins stands for an hour
	// from there: less long than the gate's.
	now.advance(-30 * time.Minute)
	if _, err := client.Attest(within(t)); err != nil {
		t.Fatal(err)
	}
	if got := engine.judgments(); len(got) != 2 {
		t.Fatalf("judgments %+v", got)
	}
	// Past the pinning judgment's hour and inside the gate's.
	now.advance(session.ServingVerdictTTL + 15*time.Minute)
	client.Close()
	run(t, client)
	seen := engine.judgments()
	if last := seen[len(seen)-1]; len(seen) != 3 || last.root {
		t.Fatalf("the command went out on a verdict from before the pin: %+v", seen)
	}
}

// prefetching is an engine that notes when it is told to fetch ahead.
type prefetching struct {
	sessiontest.Engine
	mu    sync.Mutex
	calls int
}

func (e *prefetching) Prefetch() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
}

func (e *prefetching) told() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls
}

// The one document of Intel's a guest cannot hand over for the judgment that
// pins it is fetched while the client is on its way to the guest: the engine
// is told before the first dial.
func TestClientHasItsEnginePrefetchBeforeItDials(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	engine := &prefetching{}
	client, _ := clientFor(t, "https://"+s.addr, s, engine)
	var atDial []int
	client.SetDial(func(ctx context.Context, network, _ string) (net.Conn, error) {
		atDial = append(atDial, engine.told())
		return (&net.Dialer{}).DialContext(ctx, network, s.addr)
	})
	if engine.told() != 0 {
		t.Fatal("a client that was only made told its engine to fetch")
	}
	if _, err := client.Attest(within(t)); err != nil {
		t.Fatal(err)
	}
	if len(atDial) != 1 || atDial[0] != 1 {
		t.Fatalf("at each dial the engine had been told %v times, want once before the first", atDial)
	}
	// With its guest pinned it may have nothing left to judge, and a command
	// that judges nothing asks Intel for nothing: later connections of this
	// client, and a process that starts from the verdict this one kept.
	client.Close()
	run(t, client)
	verdict, ok := client.Verdict()
	if !ok {
		t.Fatal("the client keeps no verdict")
	}
	next, err := session.NewClient("https://"+s.addr, s.policy, engine, s.signer, session.Kept(verdict))
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	run(t, next)
	if engine.told() != 1 {
		t.Fatalf("the engine was told to fetch %d times, want once", engine.told())
	}
}
