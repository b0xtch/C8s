package sessiond

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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
	evidence, relayed, err := client.bind(ctx, addr, []byte("bind"), []byte("bind signature"))
	if err != nil {
		t.Fatal(err)
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
	guest.say(func(g *saidGuest) { g.state.Attestation, g.state.BindQuote = quote, session.BindQuoteTaken })
	if evidence, err = client.evidence(ctx, addr); err != nil {
		t.Fatal(err)
	}
	if evidence.GetBindQuote() != session.BindQuoteTaken {
		t.Fatalf("a guest that has its quote was relayed as %q", evidence.GetBindQuote())
	}
	if !bytes.Equal(evidence.GetQuote(), wantQuote) || !bytes.Equal(evidence.GetCertificate(), leaf) ||
		!bytes.Equal(evidence.GetLaunchDocument(), []byte("launch")) || string(evidence.GetLaunchSignature()) != "launch signature" ||
		len(evidence.GetEvents()) != 3 || !bytes.Equal(evidence.GetBind(), []byte("bind")) || string(evidence.GetBindSignature()) != "bind signature" ||
		evidence.GetPhase() != string(session.PhaseRunning) {
		t.Fatalf("the evidence of a bound guest that has its quote: %+v", evidence)
	}

	// The receipt and the quote in one answer.
	guest.say(func(g *saidGuest) { g.bind.Attestation = quote })
	if evidence, relayed, err = client.bind(ctx, addr, []byte("bind"), []byte("bind signature")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(relayed, wantReceipt) || !bytes.Equal(evidence.GetQuote(), wantQuote) || len(evidence.GetEvents()) != 3 ||
		!bytes.Equal(evidence.GetCertificate(), leaf) || !bytes.Equal(evidence.GetBind(), []byte("bind")) {
		t.Fatalf("the answer relayed with a receipt and a quote: receipt %s, evidence %+v", relayed, evidence)
	}

	// A guest of an image from before receipts answers with neither.
	guest.say(func(g *saidGuest) { g.bind = session.BindResponse{Phase: session.PhaseRunning} })
	if evidence, relayed, err = client.bind(ctx, addr, []byte("bind"), []byte("bind signature")); err != nil {
		t.Fatal(err)
	}
	if relayed != nil || len(evidence.GetQuote()) != 0 || evidence.GetPhase() != string(session.PhaseRunning) {
		t.Fatalf("an answer with neither was relayed as receipt %s, evidence %+v", relayed, evidence)
	}
}
