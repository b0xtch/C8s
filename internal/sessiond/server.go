package sessiond

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
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
// guest authenticates.
var open = map[string]bool{
	sessionv1alpha1.Sessions_GetEvidence_FullMethodName: true,
	sessionv1alpha1.Sessions_Connect_FullMethodName:     true,
}

// byKey are the calls a pool opens to the keys its configuration names. The
// handshake proved the caller holds its certificate's key, and the call
// holds that key to its pool's list: a binder needs no certificate of the
// orchestrators' authority, and its key opens no orchestrator call. Every
// call in neither list is an orchestrator's.
var byKey = map[string]bool{
	sessionv1alpha1.Sessions_WatchReady_FullMethodName: true,
	// A bind for a claimed TD is an orchestrator's. One that claims its TD
	// is also a binder's, under an authority its pool names for it.
	sessionv1alpha1.Sessions_Bind_FullMethodName: true,
}

// maxChains bounds the certificates whose chain the daemon remembers.
const maxChains = 256

// chains remembers which certificates chain to the orchestrators' authority,
// so that a call costs no signature check after its caller's first.
type chains struct {
	mu sync.Mutex
	// until is when the outcome for a certificate ends, by its digest: the
	// earliest end among the certificates of its chain.
	until map[[sha256.Size]byte]time.Time
}

// Serve serves the session API on ln until ctx ends.
func (d *Daemon) Serve(ctx context.Context, ln net.Listener) error {
	config, err := d.tlsConfig()
	if err != nil {
		return err
	}
	if d.orchestrators, err = d.clientCA(); err != nil {
		return err
	}
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(config)),
		grpc.MaxRecvMsgSize(maxMessageBytes),
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
			if err := d.authorize(ctx, info.FullMethod); err != nil {
				return nil, err
			}
			return next(ctx, req)
		}),
		grpc.StreamInterceptor(func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, next grpc.StreamHandler) error {
			if err := d.authorize(stream.Context(), info.FullMethod); err != nil {
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

// presented returns the certificates the caller of ctx presented in its
// handshake, which proved it holds the first one's key and nothing else.
func presented(ctx context.Context) []*x509.Certificate {
	if p, ok := peer.FromContext(ctx); ok {
		if info, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			return info.State.PeerCertificates
		}
	}
	return nil
}

// authorize admits a call that is open to anyone, one that its pool opens to
// the caller's key, which the call itself checks, or one whose caller
// presented a certificate of the orchestrators' authority.
func (d *Daemon) authorize(ctx context.Context, method string) error {
	if open[method] {
		return nil
	}
	certs := presented(ctx)
	switch {
	case len(certs) == 0:
		return status.Error(codes.Unauthenticated, "this call needs a certificate")
	case byKey[method], d.chained(certs):
		return nil
	}
	return status.Error(codes.Unauthenticated, "this call needs an orchestrator's certificate")
}

// chained reports whether the certificate a caller presented chains to the
// orchestrators' authority now, as a client's. The handshake checks no
// chain, so that a binder may present a certificate of its own making.
func (d *Daemon) chained(certs []*x509.Certificate) bool {
	leaf, now := certs[0], d.now()
	digest := sha256.Sum256(leaf.Raw)
	d.chains.mu.Lock()
	until, known := d.chains.until[digest]
	d.chains.mu.Unlock()
	if known && now.Before(until) {
		return true
	}
	opts := x509.VerifyOptions{
		Roots: d.orchestrators, Intermediates: x509.NewCertPool(), CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	verified, err := leaf.Verify(opts)
	if err != nil {
		return false
	}
	// It stands for as long as one chain's every certificate does.
	until = time.Time{}
	for _, chain := range verified {
		end := chain[0].NotAfter
		for _, cert := range chain[1:] {
			if cert.NotAfter.Before(end) {
				end = cert.NotAfter
			}
		}
		if end.After(until) {
			until = end
		}
	}
	d.chains.mu.Lock()
	defer d.chains.mu.Unlock()
	if d.chains.until == nil || len(d.chains.until) >= maxChains {
		d.chains.until = map[[sha256.Size]byte]time.Time{}
	}
	d.chains.until[digest] = until
	return true
}

// clientCA is the orchestrators' authority: what an orchestrator's
// certificate chains to.
func (d *Daemon) clientCA() (*x509.CertPool, error) {
	pem, err := os.ReadFile(d.cfg.TLS.ClientCA)
	if err != nil {
		return nil, fmt.Errorf("tls.clientCA: %w", err)
	}
	clients := x509.NewCertPool()
	if !clients.AppendCertsFromPEM(pem) {
		return nil, errors.New("tls.clientCA holds no certificate")
	}
	return clients, nil
}

func (d *Daemon) tlsConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(d.cfg.TLS.Cert, d.cfg.TLS.Key)
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		// A caller is asked for a certificate, and the handshake proves it
		// holds the key of the one it presents. Whose certificate it is, each
		// call decides: see authorize. No authority is named to the caller,
		// since a client with a certificate of another presents none at all
		// when one is, and a pool's binder may have made its own.
		ClientAuth: tls.RequestClientCert,
	}, nil
}
