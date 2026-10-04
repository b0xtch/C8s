package sessiond

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	sessionv1alpha1 "github.com/confidential-dot-ai/c8s/api/session/v1alpha1"
)

// maxMessageBytes bounds one message of a caller: a bind and its signature
// fit many times over.
const maxMessageBytes = 1 << 20

// open are the calls that need no certificate. Evidence is public, and a
// connection to a bound TD carries the caller's own TLS session, which the
// guest authenticates. Every other call is an orchestrator's.
var open = map[string]bool{
	sessionv1alpha1.Sessions_GetEvidence_FullMethodName: true,
	sessionv1alpha1.Sessions_Connect_FullMethodName:     true,
}

// Serve serves the session API on ln until ctx ends.
func (d *Daemon) Serve(ctx context.Context, ln net.Listener) error {
	config, err := d.tlsConfig()
	if err != nil {
		return err
	}
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(config)),
		grpc.MaxRecvMsgSize(maxMessageBytes),
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
			if err := authorize(ctx, info.FullMethod); err != nil {
				return nil, err
			}
			return next(ctx, req)
		}),
		grpc.StreamInterceptor(func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, next grpc.StreamHandler) error {
			if err := authorize(stream.Context(), info.FullMethod); err != nil {
				return err
			}
			return next(srv, stream)
		}),
		// A caller that went away without a word frees its streams.
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 30 * time.Second, Timeout: 10 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}),
	)
	sessionv1alpha1.RegisterSessionsServer(srv, d)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		graceful := make(chan struct{})
		go func() {
			srv.GracefulStop()
			close(graceful)
		}()
		select {
		case <-graceful:
		case <-time.After(5 * time.Second):
			srv.Stop()
		}
	}()
	err = srv.Serve(ln)
	if ctx.Err() != nil {
		<-stopped
		return nil
	}
	return err
}

// authorize admits a call that is open to anyone, or one whose caller
// presented a certificate of the orchestrators' authority.
func authorize(ctx context.Context, method string) error {
	if open[method] {
		return nil
	}
	if p, ok := peer.FromContext(ctx); ok {
		if info, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(info.State.VerifiedChains) > 0 {
			return nil
		}
	}
	return status.Error(codes.Unauthenticated, "this call needs an orchestrator's certificate")
}

func (d *Daemon) tlsConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(d.cfg.TLS.Cert, d.cfg.TLS.Key)
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	pem, err := os.ReadFile(d.cfg.TLS.ClientCA)
	if err != nil {
		return nil, fmt.Errorf("tls.clientCA: %w", err)
	}
	clients := x509.NewCertPool()
	if !clients.AppendCertsFromPEM(pem) {
		return nil, errors.New("tls.clientCA holds no certificate")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		// A certificate that is presented must verify. None is needed for the
		// open calls.
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  clients,
	}, nil
}
