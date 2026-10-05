package sessiond

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// saidGuest is a guest that answers the daemon with whatever a test has it
// say: the daemon reads none of it.
type saidGuest struct {
	mu    sync.Mutex
	bind  session.BindResponse
	state session.StateResponse
	asked []string
}

func (g *saidGuest) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.asked = append(g.asked, r.Method+" "+r.URL.Path)
	var answer any
	switch r.URL.Path {
	case session.PathBind:
		answer = g.bind
	case session.PathState:
		answer = g.state
	default:
		http.NotFound(w, r)
		return
	}
	_ = json.NewEncoder(w).Encode(answer)
}

func (g *saidGuest) say(change func(*saidGuest)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	change(g)
}

func (g *saidGuest) requests(path string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, asked := range g.asked {
		if strings.HasSuffix(asked, " "+path) {
			n++
		}
	}
	return n
}

// A guest answers its bind with a receipt, and with the quote over the
// bind's nonce only if it has it by then. The daemon relays both as they
// are. With no quote in the answer it relays the certificate and the phase
// and asks the guest nothing more: the quote comes with the guest's state
// once it is taken, and whoever asks for the guest's evidence gets it then.
func TestGuestsReceiptAndQuoteAreRelayedAsTheyAre(t *testing.T) {
	guest := &saidGuest{}
	server := httptest.NewTLSServer(guest)
	defer server.Close()
	addr := strings.TrimPrefix(server.URL, "https://")
	client := newGuestClient((&net.Dialer{}).DialContext)
	defer client.reconnect()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	leaf := server.Certificate().Raw

	receipt := &session.SignedReceipt{Receipt: []byte(`{"schemaVersion":"c8s-bind-receipt/v1"}`), Signature: "c2lnbmF0dXJl"}
	quote := &session.AttestResponse{
		Evidence: teetypes.AttestationEvidence{Platform: "tdx", Evidence: json.RawMessage(`{"quote":"cXVvdGU="}`)},
		Launch:   []byte("launch"), Signature: "launch signature", Events: []string{"sha256:1", "sha256:2", "sha256:3"},
		Phase: session.PhaseRunning, Bind: []byte("bind"), BindSignature: "bind signature",
	}
	wantQuote, err := json.Marshal(quote.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	wantReceipt, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}

	// The receipt alone.
	guest.say(func(g *saidGuest) { g.bind = session.BindResponse{Phase: session.PhaseRunning, Receipt: receipt} })
	answer, err := client.bind(ctx, addr, []byte("bind"), []byte("bind signature"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	evidence, relayed := answer.evidence, answer.receipt
	if answer.command != "" || answer.wait != nil {
		t.Fatalf("a bind that came with no command was answered as one that did: %+v", answer)
	}
	if !bytes.Equal(relayed, wantReceipt) {
		t.Fatalf("the receipt was relayed as %s", relayed)
	}
	if !bytes.Equal(evidence.GetCertificate(), leaf) || evidence.GetPhase() != string(session.PhaseRunning) || len(evidence.GetQuote()) != 0 ||
		len(evidence.GetEvents()) != 0 || len(evidence.GetBind()) != 0 {
		t.Fatalf("the evidence relayed with a receipt alone: %+v", evidence)
	}
	if n := guest.requests(session.PathState) + guest.requests(session.PathCollateral); n != 0 {
		t.Fatalf("the daemon asked the guest %d more times after its answer to the bind", n)
	}

	// The guest's state, before and after it has the quote.
	guest.say(func(g *saidGuest) {
		g.state = session.StateResponse{
			Phase: session.PhaseRunning, Launch: []byte("launch"), Signature: "launch signature", Events: []string{"sha256:1", "sha256:2", "sha256:3"},
			Bind: []byte("bind"), BindSignature: "bind signature",
		}
	})
	if evidence, err = client.evidence(ctx, addr); err != nil {
		t.Fatal(err)
	}
	if len(evidence.GetQuote()) != 0 || evidence.GetPhase() != string(session.PhaseRunning) || len(evidence.GetEvents()) != 3 || !bytes.Equal(evidence.GetBind(), []byte("bind")) {
		t.Fatalf("the evidence of a bound guest that has no quote yet: %+v", evidence)
	}
	// Where the guest says its quote stands is relayed as the guest says it.
	for _, said := range []string{session.BindQuoteTrying, session.BindQuoteGivenUp, ""} {
		guest.say(func(g *saidGuest) { g.state.BindQuote = said })
		if evidence, err = client.evidence(ctx, addr); err != nil || evidence.GetBindQuote() != said || len(evidence.GetQuote()) != 0 {
			t.Fatalf("a guest that says its quote is %q was relayed as %q (%v)", said, evidence.GetBindQuote(), err)
		}
	}
	guest.say(func(g *saidGuest) {
		g.state.Attestation, g.state.BindQuote, g.state.ReadyCertificate = quote, session.BindQuoteTaken, []byte("the certificate from before the bind")
	})
	if evidence, err = client.evidence(ctx, addr); err != nil {
		t.Fatal(err)
	}
	if evidence.GetBindQuote() != session.BindQuoteTaken {
		t.Fatalf("a guest that has its quote was relayed as %q", evidence.GetBindQuote())
	}
	// The certificate a bound guest keeps from before its bind, whose quote
	// binds the key its receipt is signed under, is relayed with the rest.
	if string(evidence.GetReadyCertificate()) != "the certificate from before the bind" {
		t.Fatalf("the certificate from before the bind was relayed as %q", evidence.GetReadyCertificate())
	}
	if !bytes.Equal(evidence.GetQuote(), wantQuote) || !bytes.Equal(evidence.GetCertificate(), leaf) ||
		!bytes.Equal(evidence.GetLaunchDocument(), []byte("launch")) || string(evidence.GetLaunchSignature()) != "launch signature" ||
		len(evidence.GetEvents()) != 3 || !bytes.Equal(evidence.GetBind(), []byte("bind")) || string(evidence.GetBindSignature()) != "bind signature" ||
		evidence.GetPhase() != string(session.PhaseRunning) {
		t.Fatalf("the evidence of a bound guest that has its quote: %+v", evidence)
	}

	// The receipt and the quote in one answer.
	guest.say(func(g *saidGuest) { g.bind.Attestation = quote })
	if answer, err = client.bind(ctx, addr, []byte("bind"), []byte("bind signature"), nil, nil); err != nil {
		t.Fatal(err)
	}
	evidence, relayed = answer.evidence, answer.receipt
	if !bytes.Equal(relayed, wantReceipt) || !bytes.Equal(evidence.GetQuote(), wantQuote) || len(evidence.GetEvents()) != 3 ||
		!bytes.Equal(evidence.GetCertificate(), leaf) || !bytes.Equal(evidence.GetBind(), []byte("bind")) {
		t.Fatalf("the answer relayed with a receipt and a quote: receipt %s, evidence %+v", relayed, evidence)
	}

	// A guest of an image from before receipts answers with neither.
	guest.say(func(g *saidGuest) { g.bind = session.BindResponse{Phase: session.PhaseRunning} })
	if answer, err = client.bind(ctx, addr, []byte("bind"), []byte("bind signature"), nil, nil); err != nil {
		t.Fatal(err)
	}
	evidence, relayed = answer.evidence, answer.receipt
	if relayed != nil || len(evidence.GetQuote()) != 0 || evidence.GetPhase() != string(session.PhaseRunning) {
		t.Fatalf("an answer with neither was relayed as receipt %s, evidence %+v", relayed, evidence)
	}
}

// A booting guest is asked whether it serves over a connection that must
// open at once. One that does not is given up on, and the next ask opens
// another: a guest that came up just after the first packet to it is found
// by the next, and nobody waits for the kernel to send the first again.
func TestBootProbeGivesUpOnAConnectionThatDoesNotOpen(t *testing.T) {
	guest := &saidGuest{state: session.StateResponse{Phase: session.PhaseReady, Prepared: true}}
	server := httptest.NewTLSServer(guest)
	defer server.Close()
	addr := strings.TrimPrefix(server.URL, "https://")
	var dials atomic.Int32
	// The first connection is to a guest that is not up yet: nothing answers.
	client := newGuestClient(func(ctx context.Context, network, to string) (net.Conn, error) {
		if dials.Add(1) == 1 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return (&net.Dialer{}).DialContext(ctx, network, to)
	})
	defer client.reconnect()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	began := time.Now()
	if state, _ := client.ready(withDialLimit(ctx, 20*time.Millisecond), addr); state != nil {
		t.Fatalf("a guest nothing reached answered: %+v", state)
	}
	if waited := time.Since(began); waited > 5*time.Second {
		t.Fatalf("the ask waited %s for a connection that did not open", waited)
	}
	// The answer comes with the certificate the guest gave it under, which a
	// claim relays.
	if state, leaf := client.ready(withDialLimit(ctx, 5*time.Second), addr); state == nil || !state.Prepared || !bytes.Equal(leaf, server.Certificate().Raw) {
		t.Fatalf("the next ask did not find the guest, or its certificate: %+v", state)
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("%d connections were opened, want one that was given up on and one that served", got)
	}

	// Without such a limit an ask waits for its connection as long as it may.
	client.reconnect()
	dials.Store(0)
	short, stop := context.WithTimeout(ctx, 200*time.Millisecond)
	defer stop()
	began = time.Now()
	if state, _ := client.ready(short, addr); state != nil {
		t.Fatalf("a guest nothing reached answered: %+v", state)
	}
	if waited := time.Since(began); waited < 150*time.Millisecond {
		t.Fatalf("an ask with no limit on its connection gave up after %s", waited)
	}
}

// A TD's connections to its guest are its own and end with it. The next TD in
// its slot has its address: a connection kept from the guest that is gone
// would carry the daemon's first question to the new one into nothing, and
// the daemon would wait on it instead of on the guest.
func TestEndedTDKeepsNoConnectionForTheNextAtItsAddress(t *testing.T) {
	guest := &saidGuest{state: session.StateResponse{Phase: session.PhaseReady, Prepared: true}}
	server := httptest.NewUnstartedServer(guest)
	states := make(chan http.ConnState, 16)
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew || state == http.StateClosed {
			states <- state
		}
	}
	server.StartTLS()
	defer server.Close()
	addr := strings.TrimPrefix(server.URL, "https://")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	d := &Daemon{
		cfg: &Config{StateDir: t.TempDir()}, log: slog.New(slog.DiscardHandler), now: time.Now,
		tds: map[string]*td{}, changed: make(chan struct{}),
	}
	dial := (&net.Dialer{}).DialContext
	first := &td{rec: record{ID: "td-first", State: StateReady, Address: addr}, guests: newGuestClient(dial)}
	first.ctx, first.cancel = context.WithCancel(context.Background())
	if err := os.MkdirAll(d.dir(first.rec.ID), 0o700); err != nil {
		t.Fatal(err)
	}
	if state, _ := first.guests.ready(ctx, addr); state == nil {
		t.Fatal("the first TD's guest did not answer")
	}
	if got := <-states; got != http.StateNew {
		t.Fatalf("the guest saw %v, want the daemon's connection", got)
	}
	d.mu.Lock()
	d.endLocked(first, "destroyed", "")
	d.mu.Unlock()
	select {
	case got := <-states:
		if got != http.StateClosed {
			t.Fatalf("after its TD ended the guest saw %v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the connection to an ended TD's guest was kept")
	}
	// The next TD at the address is asked over a connection of its own.
	next := &td{rec: record{ID: "td-next", State: StateBooting, Address: addr}, guests: newGuestClient(dial)}
	if state, _ := next.guests.ready(ctx, addr); state == nil {
		t.Fatal("the next TD's guest did not answer")
	}
	if got := <-states; got != http.StateNew {
		t.Fatalf("the next TD's guest was asked over a connection that was not new: %v", got)
	}
	next.guests.reconnect()
}

// commandGuest is a guest that took a first command with its bind: it
// answers the bind, and the command's sealed answer when the test lets it.
type commandGuest struct {
	answer chan []byte
	// cut is how many requests for a command after its bind it breaks the
	// connection of, and fence how many more it refuses as fenced.
	cut, fence atomic.Int32
	commands   atomic.Int32
}

func (g *commandGuest) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case session.PathBind:
		_ = json.NewEncoder(w).Encode(session.BindResponse{Phase: session.PhaseRunning, Command: session.CommandTaken})
		w.(http.Flusher).Flush()
		select {
		case sealed := <-g.answer:
			_ = json.NewEncoder(w).Encode(session.CommandAnswer{Command: session.CommandTaken, Answer: sealed})
		case <-r.Context().Done():
		}
	case session.PathBindCommand:
		g.commands.Add(1)
		switch {
		case g.cut.Add(-1) >= 0:
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
		case g.fence.Add(-1) >= 0:
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"fenced"}`))
		default:
			_ = json.NewEncoder(w).Encode(session.CommandAnswer{Command: session.CommandTaken, Answer: []byte("sealed answer")})
		}
	default:
		http.NotFound(w, r)
	}
}

// A guest that takes a first command with its bind answers twice: the bind
// at once, and the command once it has run. The daemon hands on the first
// answer when it has it, and waits for the second apart from it.
func TestBindAnswerComesBeforeItsCommands(t *testing.T) {
	guest := &commandGuest{answer: make(chan []byte, 1)}
	server := httptest.NewTLSServer(guest)
	defer server.Close()
	addr := strings.TrimPrefix(server.URL, "https://")
	client := newGuestClient((&net.Dialer{}).DialContext)
	defer client.reconnect()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wrote atomic.Int32
	answer, err := client.bind(ctx, addr, []byte("bind"), []byte("bind signature"), []byte("sealed command"), func() { wrote.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	// The guest has not answered the command, and the bind's answer is here.
	if answer.command != session.CommandTaken || answer.wait == nil || answer.evidence.GetPhase() != string(session.PhaseRunning) {
		t.Fatalf("the bind's answer: %+v", answer)
	}
	if wrote.Load() != 1 {
		t.Fatalf("the daemon was told %d times that the bind was written", wrote.Load())
	}
	guest.answer <- []byte("sealed answer")
	result, err := answer.wait()
	if err != nil || result.Command != session.CommandTaken || string(result.Answer) != "sealed answer" {
		t.Fatalf("the command's answer: %+v, %v", result, err)
	}
	// Asked again, it is the same answer, and the guest is not.
	if again, err := answer.wait(); err != nil || string(again.Answer) != "sealed answer" {
		t.Fatalf("the command's answer, asked for again: %+v, %v", again, err)
	}

	// A guest that ends before it answers the command: the wait says so.
	answer, err = client.bind(ctx, addr, []byte("bind"), []byte("bind signature"), []byte("sealed command"), nil)
	if err != nil {
		t.Fatal(err)
	}
	server.CloseClientConnections()
	if result, err := answer.wait(); err == nil {
		t.Fatalf("a guest that went away answered its command: %+v", result)
	}
}

// A command that follows its bind goes on a connection of its own, made as
// the bind is written. If the guest's fence took that connection, the daemon
// sends the command once more on one made after it.
func TestCommandAfterItsBindIsSentAgainPastTheFence(t *testing.T) {
	for name, set := range map[string]func(*commandGuest){
		"the connection broke":     func(g *commandGuest) { g.cut.Store(1) },
		"the guest refused unread": func(g *commandGuest) { g.fence.Store(1) },
	} {
		guest := &commandGuest{}
		set(guest)
		server := httptest.NewTLSServer(guest)
		addr := strings.TrimPrefix(server.URL, "https://")
		client := newGuestClient((&net.Dialer{}).DialContext)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		answer, err := client.command(ctx, addr, []byte("sealed command"))
		if err != nil || answer.Command != session.CommandTaken || string(answer.Answer) != "sealed answer" {
			t.Errorf("%s: the command's answer: %+v, %v", name, answer, err)
		}
		if n := guest.commands.Load(); n != 2 {
			t.Errorf("%s: the guest was sent the command %d times", name, n)
		}
		// It is sent once more, and no more than that. The connection the
		// client kept is dropped first: a request that breaks a kept one is
		// sent again by the transport itself.
		client.reconnect()
		guest.cut.Store(2)
		guest.commands.Store(0)
		if answer, err := client.command(ctx, addr, []byte("sealed command")); err == nil {
			t.Errorf("%s: a guest that broke two connections answered: %+v", name, answer)
		}
		if n := guest.commands.Load(); n != 2 {
			t.Errorf("%s: the guest was sent the command %d times after two broken connections", name, n)
		}
		cancel()
		client.reconnect()
		server.Close()
	}
}
