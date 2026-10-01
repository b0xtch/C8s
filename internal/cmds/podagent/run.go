package podagent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/netutil"

	"github.com/confidential-dot-ai/c8s/pkg/podcvm"
)

// maxConnections caps accepted sockets: each costs a TLS handshake before any
// token is checked, and the listener is reachable by whoever can route to the pod.
const maxConnections = 64

// Run stages the launch document, serves the agent API, and admits the
// workload. It returns when ctx ends or anything on that path fails; the unit
// that runs it powers the guest off on failure, because a guest whose agent is
// gone can be neither verified nor controlled.
func Run(ctx context.Context, cfg Config, listen string) error {
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
	go func() { served <- srv.ServeTLS(netutil.LimitListener(ln, maxConnections), "", "") }()
	cfg.Logger.Info("agent serving", "listen", listen)

	// The API is up while the image is fetched, so a verifier can already see
	// a staged guest; exec and credentials stay refused until admission.
	if err := agent.Admit(ctx); err != nil {
		_ = srv.Close()
		return err
	}
	select {
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shut)
	case err := <-served:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// Server is the agent's HTTPS server, bounded so an unauthenticated peer can
// hold neither memory nor a connection for long.
func (a *Agent) Server() *http.Server {
	return &http.Server{
		Handler:           a.Handler(),
		TLSConfig:         a.tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// A command may run for MaxExecTimeout before its response is written.
		WriteTimeout:   (podcvm.MaxExecTimeout + 60) * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
}
