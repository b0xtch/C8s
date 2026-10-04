package sessionagent_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// realQuote is a guest's TEE whose every quote is one a real TD took: what
// the agent reads its platform from.
type realQuote struct {
	sessiontest.TEE
	env teetypes.AttestationEvidence
}

func (r realQuote) Evidence(context.Context, []byte) (teetypes.AttestationEvidence, error) {
	return r.env, nil
}

// fromHost is the guest's hand-in port as a test reaches it: each connection
// is one end of a pipe.
type fromHost struct{ conns chan net.Conn }

func (f *fromHost) Accept() (io.ReadWriteCloser, error) {
	conn, ok := <-f.conns
	if !ok {
		return nil, errors.New("the listener ended")
	}
	return conn, nil
}

func (f *fromHost) Close() error { close(f.conns); return nil }

func (f *fromHost) connect() net.Conn {
	host, guest := net.Pipe()
	f.conns <- guest
	return host
}

// A guest tells its host which platform its quotes come from as soon as it
// serves, takes Intel's documents for it, and answers anyone who asks with
// what it was handed: also a caller with no key, on a guest that is nobody's
// yet, over a connection nothing has verified.
func TestGuestPassesOnWhatItsHostHandsIn(t *testing.T) {
	data, err := os.ReadFile("../../../pkg/session/testdata/tdx-evidence.json")
	if err != nil {
		t.Fatal(err)
	}
	var env teetypes.AttestationEvidence
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	p := newPool(t)
	p.cfg.TEE = realQuote{TEE: sessiontest.TEE{TD: p.td}, env: env}
	p.start(t)
	ln := &fromHost{conns: make(chan net.Conn)}
	go func() { _ = p.agent.TakeHandIns(ln) }()
	defer ln.Close()

	ask := func() (int, []byte) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, p.url+session.PathCollateral, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}).Do(req) //nolint:gosec // as a client asks: nothing about this connection is trusted
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, body
	}
	if status, body := ask(); status != http.StatusNotFound {
		t.Fatalf("before any hand-in: %d %s", status, body)
	}

	conn := ln.connect()
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatalf("the guest's line: %v", err)
	}
	var platform session.CollateralPlatform
	if err := json.Unmarshal(line, &platform); err != nil || platform != (session.CollateralPlatform{FMSPC: "b0c06f000000", CA: "platform"}) {
		t.Fatalf("the guest said %q, %v", line, err)
	}
	blob := []byte(`{"documents":[{"url":"https://pcs.example/tcb","body":"Ym9keQ=="}]}`)
	if _, err := conn.Write(blob); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	// The next connection is taken once that one is done with.
	_ = ln.connect().Close()

	if status, body := ask(); status != http.StatusOK || !bytes.Equal(body, blob) {
		t.Fatalf("after the hand-in: %d %q", status, body)
	}
}
