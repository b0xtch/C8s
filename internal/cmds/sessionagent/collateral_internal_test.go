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
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// hostSide is a hostListener that hands out one end of a pipe for every
// connection its test opens.
type hostSide struct {
	conns chan net.Conn
}

func newHostSide() *hostSide { return &hostSide{conns: make(chan net.Conn)} }

func (h *hostSide) Accept() (io.ReadWriteCloser, error) {
	conn, ok := <-h.conns
	if !ok {
		return nil, errors.New("the listener ended")
	}
	return conn, nil
}

func (h *hostSide) Close() error { close(h.conns); return nil }

// connect is a connection from the host: its end of the pipe.
func (h *hostSide) connect() net.Conn {
	host, guest := net.Pipe()
	h.conns <- guest
	return host
}

func fedAgent(platform *session.CollateralPlatform) *Agent {
	a := &Agent{log: slog.New(slog.DiscardHandler)}
	a.platform.Store(platform)
	return a
}

// asked is the agent's answer to GET PathCollateral.
func asked(t *testing.T, a *Agent, method string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, httptest.NewRequest(method, session.PathCollateral, nil))
	return rec
}

// A host is told which platform the guest's quotes come from and hands in
// Intel's documents for it. The guest serves what it was handed byte for
// byte, to anyone, and reads none of it.
func TestHostHandsInIntelsDocuments(t *testing.T) {
	platform := &session.CollateralPlatform{FMSPC: "b0c06f000000", CA: "platform"}
	a := fedAgent(platform)
	ln := newHostSide()
	served := make(chan error, 1)
	go func() { served <- a.TakeHandIns(ln) }()

	if rec := asked(t, a, http.MethodGet); rec.Code != http.StatusNotFound {
		t.Fatalf("before any hand-in: %d %s", rec.Code, rec.Body)
	}
	// handIn is one connection: what the guest said, then what the host sent.
	handIn := func(blob []byte) {
		t.Helper()
		conn := ln.connect()
		line, err := bufio.NewReader(conn).ReadBytes('\n')
		if err != nil {
			t.Fatalf("the guest's line: %v", err)
		}
		var said session.CollateralPlatform
		if err := json.Unmarshal(line, &said); err != nil || said != *platform {
			t.Fatalf("the guest said %q, %v", line, err)
		}
		if _, err := conn.Write(blob); err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		// The next connection is taken once this one is done with.
		_ = ln.connect().Close()
	}

	// Not JSON, on purpose: the guest keeps bytes.
	blob := []byte("\x00not for the guest to read\xff")
	handIn(blob)
	rec := asked(t, a, http.MethodGet)
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), blob) || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("after a hand-in: %d %q %v", rec.Code, rec.Body.Bytes(), rec.Header())
	}
	// A host that only asks which platform this is leaves what the guest holds.
	handIn(nil)
	if rec := asked(t, a, http.MethodGet); !bytes.Equal(rec.Body.Bytes(), blob) {
		t.Fatalf("after a connection that sent nothing: %q", rec.Body.Bytes())
	}
	// More than a guest takes is not taken, in part or whole.
	handIn(make([]byte, session.MaxCollateralBytes+1))
	if rec := asked(t, a, http.MethodGet); !bytes.Equal(rec.Body.Bytes(), blob) {
		t.Fatalf("after a hand-in that was too large: %d bytes", rec.Body.Len())
	}
	largest := bytes.Repeat([]byte{'a'}, session.MaxCollateralBytes)
	handIn(largest)
	if rec := asked(t, a, http.MethodGet); !bytes.Equal(rec.Body.Bytes(), largest) {
		t.Fatalf("after the largest hand-in: %d bytes", rec.Body.Len())
	}

	// Nothing is handed in through the guest's API: only its host reaches
	// the port that takes a hand-in.
	for _, method := range []string{http.MethodPut, http.MethodPost, http.MethodDelete} {
		if rec := asked(t, a, method); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: %d", method, session.PathCollateral, rec.Code)
		}
	}
	if rec := asked(t, a, http.MethodGet); !bytes.Equal(rec.Body.Bytes(), largest) {
		t.Fatal("a request through the API changed what the guest holds")
	}

	_ = ln.Close()
	if err := <-served; err == nil {
		t.Fatal("the agent went on taking hand-ins from a listener that ended")
	}
}

// A guest whose evidence names no Intel platform has nothing to ask its host
// for, and takes nothing.
func TestGuestWithNoPlatformTakesNoHandIn(t *testing.T) {
	a := fedAgent(nil)
	ln := newHostSide()
	go func() { _ = a.TakeHandIns(ln) }()
	defer ln.Close()
	conn := ln.connect()
	// The guest hangs up without a word, whatever the host has to say.
	if line, err := io.ReadAll(conn); err != nil || len(line) != 0 {
		t.Fatalf("the guest said %q, %v", line, err)
	}
	_ = conn.Close()
	if rec := asked(t, a, http.MethodGet); rec.Code != http.StatusNotFound {
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
