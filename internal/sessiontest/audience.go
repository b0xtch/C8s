package sessiontest

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// Audience is the name the guest at url takes tokens under, read from its
// public state the way any peer can read it. A test that mints a token by
// hand, past the client that would have named the guest itself, needs it.
func Audience(t testing.TB, url string) string {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // a probe: nothing about this peer is trusted
	defer client.CloseIdleConnections()
	resp, err := client.Get(url + session.PathState)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var state session.StateResponse
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil || resp.StatusCode != http.StatusOK || len(state.InstanceKey) == 0 {
		t.Fatalf("read the guest's instance key from its state: HTTP %d, %v", resp.StatusCode, err)
	}
	sum := sha256.Sum256(state.InstanceKey)
	return "sha256:" + hex.EncodeToString(sum[:])
}
