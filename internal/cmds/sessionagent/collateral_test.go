package sessionagent_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

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

// A guest tells its host which platform its quotes come from as soon as it
// serves, takes Intel's documents for it, and answers anyone who asks with
// what its host answered: also a caller with no key, on a guest that is
// nobody's yet, over a connection nothing has verified.
func TestGuestPassesOnWhatItsHostAnswersWith(t *testing.T) {
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
		t.Fatalf("before the guest asked its host: %d %s", status, body)
	}

	blob := []byte(`{"documents":[{"url":"https://pcs.example/tcb","body":"Ym9keQ=="}]}`)
	said := make(chan []byte, 1)
	// The host's end of the guest's connection.
	dial := func(context.Context) (net.Conn, error) {
		guest, host := net.Pipe()
		go func() {
			defer host.Close()
			line, err := bufio.NewReader(host).ReadBytes('\n')
			if err != nil {
				return
			}
			select {
			case said <- line:
			default:
			}
			_, _ = host.Write(blob)
		}()
		return guest, nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go p.agent.AskHost(ctx, dial)
	p.agent.AwaitCollateral(ctx, 10*time.Second)

	var platform session.CollateralPlatform
	select {
	case line := <-said:
		if err := json.Unmarshal(line, &platform); err != nil || platform != (session.CollateralPlatform{FMSPC: "b0c06f000000", CA: "platform"}) {
			t.Fatalf("the guest said %q, %v", line, err)
		}
	default:
		t.Fatal("the guest said nothing to its host")
	}
	if status, body := ask(); status != http.StatusOK || !bytes.Equal(body, blob) {
		t.Fatalf("after the host's answer: %d %q", status, body)
	}
}
