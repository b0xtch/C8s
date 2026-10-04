package sessionagent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// askedHost is the guest's host as an ask reaches it: each connection is one
// end of a pipe, and the host answers what its test scripted.
type askedHost struct {
	mu sync.Mutex
	// answers are what the host writes on its first connection, its second,
	// and so on; the last holds for every later one. Nil answers nothing.
	answers [][]byte
	// down refuses every connection, and silent takes one and says nothing.
	down, silent bool
	// said is the line each connection was told.
	said [][]byte
	done sync.WaitGroup
}

func (h *askedHost) dial(context.Context) (net.Conn, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.down {
		return nil, errors.New("connection refused")
	}
	n := len(h.said)
	h.said = append(h.said, nil)
	var answer []byte
	if len(h.answers) > 0 {
		answer = h.answers[min(n, len(h.answers)-1)]
	}
	silent := h.silent
	guest, host := net.Pipe()
	h.done.Add(1)
	go func() {
		defer h.done.Done()
		defer host.Close()
		line, err := bufio.NewReader(host).ReadBytes('\n')
		if err != nil {
			return
		}
		h.mu.Lock()
		h.said[n] = line
		h.mu.Unlock()
		if silent {
			// Until the guest hangs up.
			_, _ = io.Copy(io.Discard, host)
			return
		}
		_, _ = host.Write(answer)
	}()
	return guest, nil
}

func (h *askedHost) lines() [][]byte {
	h.done.Wait()
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.said)
}

func (h *askedHost) set(change func(*askedHost)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	change(h)
}

var testAskPace = askPace{every: 10 * time.Minute, first: 250 * time.Millisecond, retry: 2 * time.Second, answer: 5 * time.Second}

func askingAgent(platform *session.CollateralPlatform, out io.Writer) *Agent {
	a := &Agent{log: slog.New(slog.NewJSONHandler(out, nil)), kept: make(chan struct{})}
	a.platform.Store(platform)
	return a
}

// asks runs the agent's asking for as many rounds as waits lists changes
// for, and returns how long it waited after each.
func asks(a *Agent, host *askedHost, rounds int, before map[int]func()) []time.Duration {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var waits []time.Duration
	a.askHost(ctx, host.dial, testAskPace, func(_ context.Context, d time.Duration) bool {
		waits = append(waits, d)
		if change := before[len(waits)]; change != nil {
			change()
		}
		if len(waits) == rounds {
			cancel()
			return false
		}
		return true
	})
	return waits
}

// collateralAnswer is the agent's answer to a request for PathCollateral.
func collateralAnswer(t *testing.T, a *Agent, method string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, httptest.NewRequest(method, session.PathCollateral, nil))
	return rec
}

// A guest tells its host which platform its quotes come from and is answered
// with Intel's documents for it. It serves what it was answered with byte
// for byte, to anyone, and reads none of it.
func TestGuestAsksItsHostForIntelsDocuments(t *testing.T) {
	platform := &session.CollateralPlatform{FMSPC: "b0c06f000000", CA: "platform"}
	a := askingAgent(platform, io.Discard)
	if rec := collateralAnswer(t, a, http.MethodGet); rec.Code != http.StatusNotFound {
		t.Fatalf("before any ask: %d %s", rec.Code, rec.Body)
	}
	// Not JSON, on purpose: the guest keeps bytes.
	blob := []byte("\x00not for the guest to read\xff")
	largest := bytes.Repeat([]byte{'a'}, session.MaxCollateralBytes)
	host := &askedHost{answers: [][]byte{blob, nil, make([]byte, session.MaxCollateralBytes+1), largest}}
	served := func(when string, want []byte) func() {
		return func() {
			t.Helper()
			rec := collateralAnswer(t, a, http.MethodGet)
			if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), want) || rec.Header().Get("Content-Type") != "application/json" {
				t.Errorf("%s: %d, %d bytes, %v", when, rec.Code, rec.Body.Len(), rec.Header())
			}
		}
	}
	waits := asks(a, host, 4, map[int]func(){
		1: served("after an answer", blob),
		// A host that answers with nothing leaves what the guest holds.
		2: served("after an answer of no bytes", blob),
		// More than a guest takes is not taken, in part or whole.
		3: served("after an answer that was too large", blob),
		4: served("after the largest answer", largest),
	})
	want := []time.Duration{testAskPace.every, testAskPace.first, 2 * testAskPace.first, testAskPace.every}
	if !slices.Equal(waits, want) {
		t.Fatalf("the guest waited %v between its asks, want %v", waits, want)
	}
	select {
	case <-a.kept:
	default:
		t.Fatal("nobody was told that the guest holds an answer")
	}
	// The one thing the guest says: its platform, as one line.
	for i, line := range host.lines() {
		var said session.CollateralPlatform
		if err := json.Unmarshal(line, &said); err != nil || said != *platform || !bytes.HasSuffix(line, []byte("\n")) {
			t.Errorf("ask %d said %q, %v", i, line, err)
		}
	}

	// Nothing reaches what the guest holds through its API.
	for _, method := range []string{http.MethodPut, http.MethodPost, http.MethodDelete} {
		if rec := collateralAnswer(t, a, method); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: %d", method, session.PathCollateral, rec.Code)
		}
	}
	served("after requests through the API", largest)()
}

// records collects what the agent logs.
type records struct {
	mu    sync.Mutex
	lines []string
}

func (r *records) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var record struct {
		Level string `json:"level"`
		Msg   string `json:"msg"`
	}
	if json.Unmarshal(p, &record) == nil {
		r.lines = append(r.lines, record.Level+" "+record.Msg)
	}
	return len(p), nil
}

// A guest asks again soon after an ask that was not answered, twice as late
// each time up to a limit, every ten minutes once it is, and says each
// change once.
func TestGuestAsksAgainAtItsPace(t *testing.T) {
	out := &records{}
	a := askingAgent(&session.CollateralPlatform{FMSPC: "b0c06f000000", CA: "platform"}, out)
	host := &askedHost{answers: [][]byte{[]byte("documents")}, down: true}
	waits := asks(a, host, 11, map[int]func(){
		5: func() { host.set(func(h *askedHost) { h.down = false }) },
		7: func() { host.set(func(h *askedHost) { h.answers = [][]byte{nil} }) },
		9: func() { host.set(func(h *askedHost) { h.answers = [][]byte{[]byte("newer documents")} }) },
	})
	ms := time.Millisecond
	want := []time.Duration{
		// A host that takes no connection.
		250 * ms, 500 * ms, 1000 * ms, 2000 * ms, 2000 * ms,
		// It answers.
		testAskPace.every, testAskPace.every,
		// It has nothing for two asks, and then something again.
		250 * ms, 500 * ms, testAskPace.every, testAskPace.every,
	}
	if !slices.Equal(waits, want) {
		t.Fatalf("waits %v\n want %v", waits, want)
	}
	if rec := collateralAnswer(t, a, http.MethodGet); rec.Body.String() != "newer documents" {
		t.Fatalf("the guest serves %q", rec.Body)
	}
	out.mu.Lock()
	defer out.mu.Unlock()
	wantLines := []string{
		"WARN the host answered with none of Intel's documents, and this guest's verifiers ask Intel",
		"INFO took Intel's documents for this platform from the host",
		"WARN the host answered with none of Intel's documents, and this guest's verifiers ask Intel",
		"INFO took Intel's documents for this platform from the host",
	}
	if !slices.Equal(out.lines, wantLines) {
		t.Fatalf("the agent said %q\nwant %q", out.lines, wantLines)
	}
}

// A guest whose evidence names no Intel platform has nothing to ask its host
// for, and asks nobody.
func TestGuestWithNoPlatformAsksNobody(t *testing.T) {
	a := askingAgent(nil, io.Discard)
	host := &askedHost{answers: [][]byte{[]byte("documents")}}
	a.askHost(t.Context(), host.dial, testAskPace, func(context.Context, time.Duration) bool {
		t.Fatal("the guest waited to ask again")
		return false
	})
	if n := len(host.lines()); n != 0 {
		t.Fatalf("the guest opened %d connections", n)
	}
	if rec := collateralAnswer(t, a, http.MethodGet); rec.Code != http.StatusNotFound {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

// A host that takes the guest's line and says nothing holds one ask for the
// ask's own limit and no longer, and one that the guest's end ends.
func TestGuestWaitsForAnAnswerNoLongerThanItsLimit(t *testing.T) {
	a := askingAgent(&session.CollateralPlatform{FMSPC: "b0c06f000000", CA: "platform"}, io.Discard)
	host := &askedHost{silent: true}
	began := time.Now()
	if _, err := a.ask(t.Context(), host.dial, []byte("{}\n"), 50*time.Millisecond); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ask = %v, want its deadline", err)
	}
	if waited := time.Since(began); waited > 2*time.Second {
		t.Fatalf("the ask waited %s", waited)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := a.ask(ctx, host.dial, []byte("{}\n"), time.Minute)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("an ask the guest ended returned an answer")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the ask went on after the guest ended it")
	}
	if rec := collateralAnswer(t, a, http.MethodGet); rec.Code != http.StatusNotFound {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

// The platform is read from the guest's own quote, once.
func TestAgentNotesItsPlatformFromItsQuote(t *testing.T) {
	data, err := os.ReadFile("../../../pkg/session/testdata/tdx-evidence.json")
	if err != nil {
		t.Fatal(err)
	}
	var env teetypes.AttestationEvidence
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	a := &Agent{log: slog.New(slog.DiscardHandler)}
	// Evidence that names no platform leaves the question open.
	a.notePlatform(teetypes.AttestationEvidence{Platform: teetypes.PlatformTDX, Evidence: []byte(`{"quote":"AAAA"}`)})
	if got := a.platform.Load(); got != nil {
		t.Fatalf("evidence with no quote in it named %+v", got)
	}
	a.notePlatform(env)
	first := a.platform.Load()
	if first == nil || *first != (session.CollateralPlatform{FMSPC: "b0c06f000000", CA: "platform"}) {
		t.Fatalf("the platform is %+v", first)
	}
	a.notePlatform(env)
	if a.platform.Load() != first {
		t.Fatal("the platform was read again")
	}

	// Every serving certificate is issued over a quote, and the agent is
	// shown each: the first names its platform.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fresh := &Agent{log: slog.New(slog.DiscardHandler)}
	provider := &instanceProvider{key: key, tee: showing{env}, ttl: time.Hour, seen: fresh.notePlatform}
	if _, _, err := provider.Provision(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := fresh.platform.Load(); got == nil || *got != *first {
		t.Fatalf("after its first certificate the agent's platform is %+v", got)
	}
}

// showing is a TEE whose evidence is always the same.
type showing struct{ env teetypes.AttestationEvidence }

func (showing) Family() teetypes.Family { return teetypes.FamilyTDX }
func (showing) Measurements(context.Context) (*teetypes.VerificationResult, error) {
	return nil, errors.New("not asked for here")
}
func (showing) Register() (runtimemeasure.Register, error) { return nil, runtimemeasure.ErrNoRegister }
func (s showing) Evidence(context.Context, []byte) (teetypes.AttestationEvidence, error) {
	return s.env, nil
}
