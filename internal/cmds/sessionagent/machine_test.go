package sessionagent_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// serveStaged serves an agent a test staged itself, as start does after it.
func (h *harness) serveStaged(t *testing.T, agent *sessionagent.Agent) {
	t.Helper()
	if err := agent.WarmUp(context.Background()); err != nil {
		t.Fatalf("WarmUp: %v", err)
	}
	if err := agent.Admit(context.Background()); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.srv = agent.Server()
	go func(srv *http.Server) { _ = agent.Serve(srv, ln) }(h.srv)
	t.Cleanup(h.stop)
	h.agent, h.url = agent, "https://"+ln.Addr().String()
}

// A guest serves nothing on a machine its launch document does not list: the
// host built it another shape than the document's signer recorded.
func TestGuestStagesOnlyOnAMachineItsDocumentLists(t *testing.T) {
	listed := bytes.Repeat([]byte{0xab}, 48)
	h := newUnbound(t, func(o *session.BundleOptions) {
		o.Machines = []string{hex.EncodeToString(listed), strings.Repeat("c", 96)}
	})
	// The harness's TD came up with a register of its own.
	if _, err := sessionagent.Stage(context.Background(), h.cfg); err == nil || !strings.Contains(err.Error(), "is none of the 2 its launch document lists") {
		t.Fatalf("a guest staged on a machine its document does not list: %v", err)
	}
	copy(h.td.RTMR[0][:], listed)
	agent, err := sessionagent.Stage(context.Background(), h.cfg)
	if err != nil {
		t.Fatalf("a guest on a listed machine: %v", err)
	}
	h.serveStaged(t, agent)
	ready, err := h.client(t, h.owner).Ready(ctxT(t))
	if err != nil || ready.Document.Machine == nil {
		t.Fatalf("the check of the guest: %v", err)
	}
}

// The agent's own check is not what a verifier relies on. Evidence of a
// machine the document does not list is refused in the handshake, before
// anything is sent, when the policy pins the document.
func TestHandshakeRefusesAMachineTheDocumentDoesNotList(t *testing.T) {
	listed := bytes.Repeat([]byte{0xab}, 48)
	h := newUnbound(t, func(o *session.BundleOptions) { o.Machines = []string{hex.EncodeToString(listed)} })
	h.policy.Launch = h.bundle.Launch
	copy(h.td.RTMR[0][:], listed)
	agent, err := sessionagent.Stage(context.Background(), h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	// From here the guest's evidence, its serving certificate's included,
	// shows another machine.
	h.td.RTMR[0][0] ^= 1
	h.serveStaged(t, agent)
	_, err = h.client(t, h.owner).Ready(ctxT(t))
	var verdict *session.VerificationError
	if !errors.As(err, &verdict) || !strings.Contains(err.Error(), "is none of the 1 its launch document lists") {
		t.Fatalf("the check of the guest: %v", err)
	}
	// It is the connection that failed: no request was written.
	if sent := new(url.Error); !errors.As(err, &sent) {
		t.Fatalf("the guest was refused after the handshake: %v", err)
	}
}

// A binder that is about to bind a guest has the guest's document from the
// guest itself, and holds the guest to the machines it lists before it sends
// a bind.
func TestReadyCheckRefusesAMachineTheLaunchDocumentDoesNotList(t *testing.T) {
	listed := bytes.Repeat([]byte{0xab}, 48)
	p := newPoolWith(t, func(o *session.BundleOptions) { o.Machines = []string{hex.EncodeToString(listed)} })
	copy(p.td.RTMR[0][:], listed)
	agent, err := sessionagent.Stage(context.Background(), p.cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.td.RTMR[0][0] ^= 1
	p.serveStaged(t, agent)
	_, err = p.client(t, p.access).Ready(ctxT(t))
	var verdict *session.VerificationError
	if !errors.As(err, &verdict) || !strings.Contains(err.Error(), "is none of the 1 its launch document lists") {
		t.Fatalf("the unbound check: %v", err)
	}
	// This binder pins no launch document, so its handshake could not know
	// the machines: the check that refused came after the guest's answer.
	if sent := new(url.Error); errors.As(err, &sent) {
		t.Fatalf("refused in the handshake, with no document to go by: %v", err)
	}
	// A binder that pins the pool's launch document refuses in the handshake.
	p.policy.Launch = p.bundle.Launch
	_, err = p.client(t, p.access).Ready(ctxT(t))
	if sent := new(url.Error); !errors.As(err, &verdict) || !errors.As(err, &sent) || !strings.Contains(err.Error(), "is none of the 1 its launch document lists") {
		t.Fatalf("the unbound check under a pinned pool document: %v", err)
	}

	// On the machine it lists, the guest is taken, and a policy that wants a
	// pinned machine is content with it.
	good := newPoolWith(t, func(o *session.BundleOptions) { o.Machines = []string{hex.EncodeToString(listed)} })
	copy(good.td.RTMR[0][:], listed)
	good.policy.RequireMachine = true
	good.start(t)
	if ready, err := good.client(t, good.access).Ready(ctxT(t)); err != nil || ready.Document.Machine == nil {
		t.Fatalf("the unbound check of a guest on its listed machine: %v", err)
	}
	// And one whose document pins none is refused by that policy.
	plain := newPool(t)
	plain.policy.RequireMachine = true
	plain.start(t)
	if _, err := plain.client(t, plain.access).Ready(ctxT(t)); !errors.As(err, &verdict) || !strings.Contains(err.Error(), "pins no machine") {
		t.Fatalf("the unbound check of a guest whose document pins no machine: %v", err)
	}
}
