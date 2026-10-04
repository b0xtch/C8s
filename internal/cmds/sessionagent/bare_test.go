package sessionagent_test

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

const noSandboxRefusal = "inside a sandbox image only"

// A guest image for sessions leaves bare mode off. Its agent takes no bind
// that would run commands beside its own services: it refuses it as it
// refuses any bind it will not take, measures nothing, and ends.
func TestOnlyABareGuestTakesABindWithoutAnImage(t *testing.T) {
	noImage := func(o *session.BindOptions) { o.Policy.Sandbox = nil }

	t.Run("refused, and the guest ends", func(t *testing.T) {
		p := newPool(t)
		p.cfg.Bare = false
		p.start(t)
		ready, err := p.client(t, p.access).Ready(ctxT(t))
		if err != nil {
			t.Fatal(err)
		}
		before := register(t, p.td)
		bind := p.bindFor(t, ready, noImage)
		if status := p.postBind(t, bind.Raw, bind.Signature); status != http.StatusBadRequest {
			t.Fatalf("HTTP %d, want 400", status)
		}
		select {
		case err := <-p.agent.Fatal():
			if err == nil || !strings.Contains(err.Error(), "refused a bind while unbound") || !strings.Contains(err.Error(), noSandboxRefusal) {
				t.Fatalf("the agent ends for another reason: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the agent carries on after refusing a bind")
		}
		if state := p.state(t); state.Phase != session.PhaseReady || len(state.Bind) != 0 {
			t.Fatalf("the guest left the unbound phase: %s", state.Phase)
		}
		if !bytes.Equal(before, register(t, p.td)) {
			t.Fatal("a refused bind was measured")
		}
		if steps := p.runner.recorded(); steps != "" {
			t.Fatalf("a refused bind reached the runner: %s", steps)
		}
	})

	t.Run("with an image the same guest is bound", func(t *testing.T) {
		p := newPool(t)
		p.cfg.Bare = false
		p.start(t)
		client := p.client(t, p.access)
		ready, err := client.Ready(ctxT(t))
		if err != nil {
			t.Fatal(err)
		}
		if resp, err := client.Bind(ctxT(t), p.bindFor(t, ready, nil)); err != nil || resp.Phase != session.PhaseRunning {
			t.Fatalf("Bind = %+v, %v", resp, err)
		}
		if p.runner.recorded() != "prepare "+sandboxImage+",start" {
			t.Fatalf("runner steps = %s", p.runner.recorded())
		}
	})

	t.Run("a bare guest takes it, and runs commands on its own file system", func(t *testing.T) {
		p := newPool(t)
		p.start(t)
		client := p.client(t, p.access)
		ready, err := client.Ready(ctxT(t))
		if err != nil {
			t.Fatal(err)
		}
		bind := p.bindFor(t, ready, noImage)
		if resp, err := client.Bind(ctxT(t), bind); err != nil || resp.Phase != session.PhaseRunning || len(resp.Admission) != 0 {
			t.Fatalf("Bind = %+v, %v", resp, err)
		}
		if steps := p.runner.recorded(); steps != "" {
			t.Fatalf("a bind with no image drove the runner: %s", steps)
		}
		out, err := p.boundClient(t, ready, bind).Exec(ctxT(t), session.ExecRequest{Argv: []string{"sh", "-c", "echo on the guest"}})
		if err != nil || string(out.Stdout) != "on the guest\n" {
			t.Fatalf("exec = %+v, %v", out, err)
		}
	})
}
