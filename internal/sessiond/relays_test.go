package sessiond

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	sessionv1alpha1 "github.com/confidential-dot-ai/c8s/api/session/v1alpha1"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// A caller has its own bound on the evidence requests the daemon has in
// flight for it: one caller that asks without end is refused, and takes no
// place of another's. A place given back is a place again, and giving one
// back twice gives back one.
func TestEvidenceRelaysAreBoundedByCaller(t *testing.T) {
	var r relays
	var held []func()
	for i := range maxCallerRelays {
		leave := r.enter("key a")
		if leave == nil {
			t.Fatalf("request %d of a caller within its bound was refused", i+1)
		}
		held = append(held, leave)
	}
	if r.enter("key a") != nil {
		t.Fatal("a caller beyond its bound was let in")
	}
	// Another caller is served while the first is at its bound.
	leave := r.enter("key b")
	if leave == nil {
		t.Fatal("another caller was refused while the first is at its bound")
	}
	leave()
	// The first caller's place given back is one again, once.
	held[0]()
	held[0]()
	if leave = r.enter("key a"); leave == nil {
		t.Fatal("a caller that gave a place back was refused")
	}
	if r.enter("key a") != nil {
		t.Fatal("a place given back twice counted for two")
	}
	leave()
	for _, leave := range held[1:] {
		leave()
	}
	// Nothing is kept of requests that are over.
	if len(r.byCaller) != 0 {
		t.Fatalf("with nothing in flight the daemon keeps %d callers", len(r.byCaller))
	}
}

// slowGuest serves a state that says which request for it this was, each
// when a test lets it.
type slowGuest struct {
	// arrived is sent each request's number as it comes, and let is read
	// once before each is answered.
	arrived chan int
	let     chan struct{}
	asked   atomic.Int32
}

func (g *slowGuest) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != session.PathState {
		http.NotFound(w, r)
		return
	}
	n := int(g.asked.Add(1))
	g.arrived <- n
	select {
	case <-g.let:
	case <-r.Context().Done():
		return
	}
	_ = json.NewEncoder(w).Encode(session.StateResponse{Phase: session.PhaseRunning, Launch: []byte("launch"), Events: []string{fmt.Sprintf("sha256:%d", n)}})
}

// A guest serves the same evidence to anyone, so the daemon has it answer
// one request at a time. Everyone who asks while one is in flight shares the
// next, which is sent when that one is done: each gets an answer of a
// request sent after it asked, nobody is refused for the others, and a
// caller that leaves takes nobody's answer with it. Nothing is kept once a
// request is done, and a TD's end ends the request in flight.
func TestEvidenceOfATDIsAskedForOnceForAllWhoWait(t *testing.T) {
	guest := &slowGuest{arrived: make(chan int, 16), let: make(chan struct{})}
	server := httptest.NewTLSServer(guest)
	defer server.Close()
	d := &Daemon{cfg: &Config{}, tds: map[string]*td{}, pools: map[string]*poolState{}}
	live, end := context.WithCancel(context.Background())
	defer end()
	one := &td{
		rec: record{ID: "td-1", State: StateRunning, Address: strings.TrimPrefix(server.URL, "https://")},
		ctx: live, cancel: end, guests: newGuestClient((&net.Dialer{}).DialContext),
	}
	defer one.guests.reconnect()
	d.tds["td-1"] = one

	type answer struct {
		request string
		err     error
	}
	// asks sends one caller's request, and waits until the daemon has it.
	asks := func(ctx context.Context, caller string) <-chan answer {
		t.Helper()
		d.relays.mu.Lock()
		before := d.relays.byCaller["address "+caller]
		d.relays.mu.Unlock()
		out := make(chan answer, 1)
		from := peer.NewContext(ctx, &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP(caller), Port: 4000}})
		go func() {
			evidence, err := d.GetEvidence(from, &sessionv1alpha1.EvidenceRequest{Td: "td-1"})
			out <- answer{strings.Join(evidence.GetEvents(), ","), err}
		}()
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
			d.relays.mu.Lock()
			now := d.relays.byCaller["address "+caller]
			d.relays.mu.Unlock()
			if now > before {
				return out
			}
			if time.Now().After(deadline) {
				t.Fatalf("the daemon never took the request of %s", caller)
			}
		}
	}
	said := func(what string, from <-chan answer, want string) {
		t.Helper()
		select {
		case got := <-from:
			if got.err != nil || got.request != want {
				t.Fatalf("%s: answered with request %q, %v, want %q", what, got.request, got.err, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: no answer", what)
		}
	}
	arrives := func(want int) {
		t.Helper()
		select {
		case n := <-guest.arrived:
			if n != want {
				t.Fatalf("the guest was sent request %d, want %d", n, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("request %d never reached the guest", want)
		}
	}
	ctx := context.Background()

	first := asks(ctx, "192.0.2.1")
	arrives(1)
	// Three ask while the first is in flight, and one of them leaves.
	second, third := asks(ctx, "192.0.2.2"), asks(ctx, "192.0.2.3")
	leaving, leave := context.WithCancel(ctx)
	left := asks(leaving, "192.0.2.4")
	leave()
	if got := <-left; status.Code(got.err) != codes.Canceled {
		t.Fatalf("a caller that left was answered %q, %v", got.request, got.err)
	}
	select {
	case n := <-guest.arrived:
		t.Fatalf("the guest was sent request %d while it had one to answer", n)
	case <-time.After(50 * time.Millisecond):
	}
	guest.let <- struct{}{}
	said("the first caller", first, "sha256:1")
	// The others share one request, sent now.
	arrives(2)
	guest.let <- struct{}{}
	said("a caller that asked meanwhile", second, "sha256:2")
	said("another that asked meanwhile", third, "sha256:2")
	// A caller that asks later is answered by a request of its own.
	fourth := asks(ctx, "192.0.2.5")
	arrives(3)
	guest.let <- struct{}{}
	said("a caller that asked later", fourth, "sha256:3")
	d.mu.Lock()
	kept := one.asking != nil || one.asksNext != nil
	d.mu.Unlock()
	d.relays.mu.Lock()
	callers := len(d.relays.byCaller)
	d.relays.mu.Unlock()
	if kept || callers != 0 {
		t.Fatalf("with nothing in flight the daemon keeps a request (%v) and %d callers", kept, callers)
	}

	// The TD's end ends the request in flight, and whoever waits behind it.
	fifth := asks(ctx, "192.0.2.6")
	arrives(4)
	sixth := asks(ctx, "192.0.2.7")
	end()
	for _, from := range []<-chan answer{fifth, sixth} {
		select {
		case got := <-from:
			if status.Code(got.err) != codes.Unavailable {
				t.Fatalf("a caller of a TD that ended was answered %q, %v", got.request, got.err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a caller of a TD that ended was left waiting")
		}
	}
}

// A caller is the key of the certificate it presents, and without one the
// address it calls from, whatever port: two connections of one host are one
// caller, and two keys from one address are two.
func TestCallerIsItsKeyOrItsAddress(t *testing.T) {
	certified := func(addr string) context.Context {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		info := credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{{PublicKey: &key.PublicKey}}}}
		return peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP(addr), Port: 4000}, AuthInfo: info})
	}
	from := func(addr string, port int) context.Context {
		return peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP(addr), Port: port}})
	}
	a, b := callerOf(certified("192.0.2.1")), callerOf(certified("192.0.2.1"))
	if a == b || !strings.HasPrefix(a, "key sha256:") {
		t.Fatalf("two keys from one address are callers %q and %q", a, b)
	}
	if one, other := callerOf(from("192.0.2.1", 4000)), callerOf(from("192.0.2.1", 4001)); one != other || one != "address 192.0.2.1" {
		t.Fatalf("two connections of one host are callers %q and %q", one, other)
	}
	if one, other := callerOf(from("192.0.2.1", 4000)), callerOf(from("192.0.2.2", 4000)); one == other {
		t.Fatalf("two hosts are one caller, %q", one)
	}
	if got := callerOf(context.Background()); got != "" {
		t.Fatalf("a caller the daemon can tell nothing of is %q", got)
	}
}
