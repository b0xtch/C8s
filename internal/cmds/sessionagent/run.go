package sessionagent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/netutil"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// maxConnections caps accepted sockets: each costs a TLS handshake before any
// token is checked, and the listener is reachable by whoever can route to the
// guest. Streams to the sandbox hold up to maxForwards of them for as long as
// they last; the rest are the other routes'.
const maxConnections = 128

// sandboxEndMargin is what a guest whose sandbox has ended allows, beyond
// the pauses between its attempts at its bind's quote, for those attempts
// and for its answers to leave.
var sandboxEndMargin = 1250 * time.Millisecond

// sandboxEndGrace is how long such a guest gives the answers it still owes
// before it stops: its bind's quote is settled within it.
func sandboxEndGrace() time.Duration {
	grace := sandboxEndMargin
	for _, pause := range bindQuotePauses {
		grace += pause
	}
	return grace
}

// Run stages the launch document, serves the agent API, and admits the
// sandbox. It returns when ctx ends, when the sandbox ends, or when anything
// on that path fails; the unit that runs it then powers the guest off, because
// a guest whose agent is gone can be neither verified nor controlled.
func Run(ctx context.Context, cfg Config, listen string) error {
	if cfg.Guard != nil {
		if err := cfg.Guard(ctx); err != nil {
			return fmt.Errorf("before serving: %w", err)
		}
	}
	agent, err := Stage(ctx, cfg)
	if err != nil {
		return fmt.Errorf("stage launch document: %w", err)
	}
	warm, cancel := context.WithTimeout(ctx, 60*time.Second)
	err = agent.WarmUp(warm)
	cancel()
	if err != nil {
		return fmt.Errorf("attest instance key: %w", err)
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listen, err)
	}
	srv := agent.Server()
	served := make(chan error, 1)
	go func() { served <- agent.Serve(srv, netutil.LimitListener(ln, maxConnections)) }()
	cfg.Logger.Info("agent serving", "listen", listen)
	// The guest asks its host for Intel's documents for its platform, which
	// it passes on unread. A guest with nobody to ask serves none, and its
	// verifiers ask Intel.
	if cfg.CollateralDial != nil {
		go agent.AskHost(ctx, cfg.CollateralDial)
	}

	// The key service judges this guest's evidence now, while the guest is
	// nobody's, so that a bind costs it no quote. A TD judges the key service
	// by the vendor's documents its host answers with, and has nothing to
	// judge by until the first answer.
	go func() {
		// A guest that takes no bind has nothing to open a session for.
		if agent.Unpinned() {
			return
		}
		if cfg.CollateralDial != nil && cfg.Platform == "tdx" {
			agent.AwaitCollateral(ctx, CollateralWait)
		}
		agent.KeepKeyServiceOpen(ctx)
	}()

	// The API is up while the image is fetched, so a verifier can already see
	// a staged guest; exec and credentials stay refused until admission.
	if err := agent.Admit(ctx); err != nil {
		_ = srv.Close()
		return err
	}
	// A guest nobody binds in time ends by itself, so the host holds no guest
	// longer than the launch document says.
	if left, bounded := agent.UnboundFor(); bounded {
		// Past the deadline by a moment, so the check inside finds it passed.
		timer := time.AfterFunc(max(left, 0)+time.Second, agent.ExpireUnbound)
		defer timer.Stop()
	}
	sandbox := make(chan error, 1)
	go func() { sandbox <- cfg.Runner.Wait(ctx) }()
	select {
	case <-ctx.Done():
	case err := <-served:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case err := <-agent.Fatal():
		// The request that ran into it still gets its answer.
		shut, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = srv.Shutdown(shut)
		cancel()
		return err
	case err := <-sandbox:
		// A session's guest is its sandbox. When that ends the agent takes
		// no more connections, gives the answers it still owes, its bind's
		// quote among them, and stops; the unit then powers the guest off.
		if ctx.Err() == nil {
			owed, cancel := context.WithTimeout(context.Background(), sandboxEndGrace())
			_ = srv.Shutdown(owed)
			cancel()
			_ = srv.Close()
			if err != nil {
				return fmt.Errorf("sandbox ended: %w", err)
			}
			cfg.Logger.Info("sandbox exited with status 0, stopping")
			return nil
		}
	}
	shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shut)
}

// Serve runs srv, which Server made, on ln. The agent keeps track of the
// connections it accepts there, which is what lets an unbound guest end them
// all when it is claimed.
func (a *Agent) Serve(srv *http.Server, ln net.Listener) error {
	return srv.ServeTLS(fenceListener{Listener: ln, fence: &a.fence}, "", "")
}

// Server is the agent's HTTPS server, bounded so an unauthenticated peer can
// hold neither memory nor a connection for long. Run it with Serve.
func (a *Agent) Server() *http.Server {
	// HTTP/1 only: HTTP/2 would put hundreds of concurrent streams on each of
	// the capped connections, every one allowed a body before its token is read.
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	return &http.Server{
		Handler:           a.Handler(),
		Protocols:         protocols,
		TLSConfig:         a.tlsCfg,
		ConnContext:       withConn,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// A command may run for MaxExecTimeout before its response is written.
		WriteTimeout:   (session.MaxExecTimeout + 60) * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
}
