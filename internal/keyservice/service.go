// Package keyservice is one replica of the session key service
// (docs/session-key-service.md), as far as milestone 1 needs it: it holds
// tenants' authority keys and stored credentials in memory, verifies the
// guests of the pools its launch document lists, judges their evidence again
// as the vendor replaces its documents, and releases a stored credential to
// a bound guest by the release rule, sealed to that guest.
//
// It grows out of CDS: the store is CDS's, and the evidence checks are the
// ones every session verifier runs. Leases, generations, replication, the
// ledger and recovery are not here yet.
package keyservice

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	agratls "github.com/confidential-dot-ai/attestation-go/ratls"
	"github.com/confidential-dot-ai/c8s/internal/httputil"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	api "github.com/confidential-dot-ai/c8s/pkg/session/keyservice"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	// DefaultMaxTenants and DefaultMaxGuests bound what one replica keeps.
	DefaultMaxTenants = 10000
	DefaultMaxGuests  = 100000
	// maxCredentials bounds the stored credentials of every tenant together.
	maxCredentials = DefaultMaxTenants * 4
	// tokenClockSkew is how far an owner's clock may be from the replica's.
	tokenClockSkew = 2 * time.Minute
	// verifyTimeout bounds one judgment of a guest's evidence, a fetch of
	// the vendor's documents included.
	verifyTimeout = 45 * time.Second
)

// Evidencer produces evidence of the replica's own guest, binding report data.
type Evidencer interface {
	Evidence(ctx context.Context, reportData []byte) (teetypes.AttestationEvidence, error)
}

// Config is one replica.
type Config struct {
	// Launch, Signature and LaunchKey are the replica's launch document, as
	// its guest authenticated and measured it at boot.
	Launch    []byte
	Signature string
	LaunchKey []byte
	// TEE attests the replica's instance key.
	TEE Evidencer
	// Engine verifies the evidence of guests.
	Engine session.Engine
	// Store keeps the credentials. Nil is a store in this process's memory.
	Store      secrets.Store
	MaxTenants int
	MaxGuests  int
	CertTTL    time.Duration
	Logger     *slog.Logger
	Now        func() time.Time
}

// Service is a running replica.
type Service struct {
	cfg  Config
	log  *slog.Logger
	doc  *api.Document
	pins []pool
	key  *ecdsa.PrivateKey
	// audience is the digest of the replica's instance key: what an owner's
	// token must be for.
	audience string
	tls      *tls.Config
	// unpinned: a TD whose launch document lists no machine it may be. It
	// serves its state, which says which machine it is, and nothing else.
	unpinned bool

	mu      sync.Mutex
	tenants map[string]*tenant
	guests  map[string]*guest
}

// pool is a pool the launch document lists, as a policy for its guests.
type pool struct {
	policy session.Policy
}

// tenant is what the replica holds of a tenant.
type tenant struct {
	authority    *ecdsa.PublicKey
	authorityPEM string
	// credentials are the names the tenant has stored.
	credentials map[string]bool
}

// guest is the verdict on a guest's evidence, by its instance key: the
// evidence, kept to be judged again as the vendor replaces its documents,
// until when the verdict stands, the one-time keys the evidence bound, and
// the one bind the replica has accepted for the guest.
type guest struct {
	evidence *session.Relayed
	// pool is the served pool whose policy the evidence passed under.
	pool int
	// until is when the verdict ends, an hour at most after the replica
	// fetched the oldest document under it: nothing is released past it.
	// documents is the engine's count of the vendor's documents when the
	// verdict was made, by which a newer document shows.
	until     time.Time
	documents uint64
	oneTime   *session.OneTimeKeys
	bind      string
}

// verdict is one judgment of a guest's evidence.
type verdict struct {
	ready     *session.ReadyTD
	pool      int
	documents uint64
}

// New prepares a replica: its instance key, and a serving certificate that
// carries evidence of it.
func New(ctx context.Context, cfg Config) (*Service, error) {
	if cfg.TEE == nil || cfg.Engine == nil {
		return nil, errors.New("a key service needs a TEE and an engine")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxTenants <= 0 {
		cfg.MaxTenants = DefaultMaxTenants
	}
	if cfg.MaxGuests <= 0 {
		cfg.MaxGuests = DefaultMaxGuests
	}
	if cfg.CertTTL <= 0 {
		cfg.CertTTL = ratls.DefaultCertTTL
	}
	if cfg.Store == nil {
		cfg.Store = secrets.NewMemoryStore(maxCredentials, api.MaxCredentialsPerTenant, session.MaxCredentialBytes)
	}
	doc, err := api.VerifySigned(cfg.LaunchKey, cfg.Launch, cfg.Signature)
	if err != nil {
		return nil, err
	}
	s := &Service{cfg: cfg, log: cfg.Logger, doc: doc, tenants: map[string]*tenant{}, guests: map[string]*guest{}}
	// A TD has a register for what its host declared, and a document that
	// lists no value for it leaves the host free to declare anything.
	s.unpinned = doc.Machine == nil && doc.Image.HasMachineRegister()
	for _, p := range doc.Pools {
		identity, err := p.Image.Identity()
		if err != nil {
			return nil, err
		}
		s.pins = append(s.pins, pool{policy: session.Policy{
			Image: identity, LaunchKey: []byte(p.LaunchKey), AllowReady: true, AcceptTCBStatus: p.AcceptTCBStatus,
		}})
	}
	if s.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return nil, fmt.Errorf("generate instance key: %w", err)
	}
	if s.audience, err = session.InstanceKeyDigest(&s.key.PublicKey); err != nil {
		return nil, err
	}
	var certs *ratls.CertManager
	s.tls, certs, err = ratls.NewServerTLSConfig(&ratls.ServerConfig{
		CertProvider: &provider{key: s.key, tee: cfg.TEE, ttl: cfg.CertTTL},
		CertTTL:      cfg.CertTTL,
		Logger:       cfg.Logger,
	})
	if err != nil {
		return nil, err
	}
	// A guest presents its own attested certificate. It is self-signed, so no
	// chain is checked here: the handshake proves the key, and the handlers
	// judge the evidence.
	s.tls.ClientAuth = tls.RequestClientCert
	if err := certs.WarmUp(ctx); err != nil {
		return nil, fmt.Errorf("attest the instance key: %w", err)
	}
	if s.unpinned {
		s.log.Warn("the launch document lists no machine this key service may be: it serves only what says which machine it is")
	}
	s.log.Info("key service ready", "pools", len(s.pins), "launch_digest", session.DocumentDigest(cfg.Launch), "instance_key", s.audience)
	return s, nil
}

// provider issues the replica's serving certificates over one key held in
// memory, each carrying evidence that binds it.
type provider struct {
	key *ecdsa.PrivateKey
	tee Evidencer
	ttl time.Duration
}

func (p *provider) Provision(ctx context.Context) (*tls.Certificate, time.Duration, error) {
	rd, err := ratls.ReportDataForKey(&p.key.PublicKey, nil)
	if err != nil {
		return nil, 0, err
	}
	env, err := p.tee.Evidence(ctx, rd[:48])
	if err != nil {
		return nil, 0, fmt.Errorf("attest instance key: %w", err)
	}
	att, err := agratls.NewAttestation(env)
	if err != nil {
		return nil, 0, err
	}
	der, err := ratls.CreateAttestedCert(p.key, att, &ratls.CertOptions{
		Subject: pkix.Name{CommonName: "c8s key service", Organization: []string{"Confidential"}},
		TTL:     p.ttl,
	})
	if err != nil {
		return nil, 0, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, 0, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: p.key, Leaf: leaf}, p.ttl, nil
}

// Verdict says what the replica holds of the guest with this instance key
// digest: the digest of the certificate that carried the evidence it judged,
// until when its verdict on that stands, and whether a bind has been
// accepted for the guest. ok is false for a guest with no open session.
func (s *Service) Verdict(instanceKey string) (certificate [sha256.Size]byte, until time.Time, bound, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.guests[instanceKey]
	if !ok {
		return certificate, time.Time{}, false, false
	}
	return sha256.Sum256(g.evidence.Certificate), g.until, g.bind != "", true
}

// documents is the engine's count of the vendor's documents it came to
// hold. An engine that counts none judges by none.
func (s *Service) documents() uint64 {
	if counter, ok := s.cfg.Engine.(session.DocumentCounter); ok {
		return counter.Documents()
	}
	return 0
}

// judge judges a guest's evidence against the pools at, as a verifier whose
// verdict lets a secret go: on the vendor's documents as this replica
// fetched them within the hour. A verdict made while the engine was still
// taking documents in is made once more. The error is the last pool's, or
// that of one that could not judge for want of a document.
func (s *Service) judge(ctx context.Context, evidence *session.Relayed, pools ...int) (*verdict, error) {
	var last, unjudged error
	for _, at := range pools {
		for range 2 {
			before := s.documents()
			ready, err := session.VerifyReadyToRelease(ctx, s.pins[at].policy, s.cfg.Engine, evidence, s.cfg.Now())
			if err == nil && s.documents() != before {
				continue
			}
			if err == nil {
				return &verdict{ready: ready, pool: at, documents: before}, nil
			}
			var refused *session.VerificationError
			if last = err; !errors.As(err, &refused) {
				unjudged = err
			}
			break
		}
	}
	if unjudged != nil {
		return nil, unjudged
	}
	if last == nil {
		last = errors.New("the vendor's documents kept changing under the judgment")
	}
	return nil, last
}

// currentLocked reports whether the verdict on g stands: within its time,
// and on the newest documents the engine holds. The caller holds the lock.
func (s *Service) currentLocked(g *guest) bool {
	return s.cfg.Now().Before(g.until) && g.documents == s.documents()
}

// Rejudge keeps the verdicts on pooled guests current, off the path of any
// start. It has the engine ask the vendor again for the documents that are
// due, and judges again, on the evidence each guest opened with and with no
// new quote, every guest no bind has been accepted for whose verdict no
// longer rests on the newest documents the replica holds or ends within
// five minutes. A guest whose evidence is refused now is forgotten. judged
// is how many verdicts were made anew, and the error a document the vendor
// could not be asked for.
func (s *Service) Rejudge(ctx context.Context) (judged int, err error) {
	if renewer, ok := s.cfg.Engine.(session.Renewer); ok {
		err = renewer.Renew(ctx)
	}
	type stale struct {
		key string
		g   *guest
	}
	now := s.cfg.Now()
	s.mu.Lock()
	var due []stale
	for key, g := range s.guests {
		if g.bind == "" && (!s.currentLocked(g) || g.until.Sub(now) <= session.RenewAhead) {
			due = append(due, stale{key, g})
		}
	}
	s.mu.Unlock()
	dropped := 0
	for _, d := range due {
		if ctx.Err() != nil {
			return judged, ctx.Err()
		}
		check, cancel := context.WithTimeout(ctx, verifyTimeout)
		v, failed := s.judge(check, d.g.evidence, d.g.pool)
		cancel()
		var refused *session.VerificationError
		s.mu.Lock()
		// The guest may have opened again meanwhile, or been bound.
		if g := s.guests[d.key]; g == d.g && g.bind == "" {
			switch {
			case failed == nil:
				g.until, g.documents, g.oneTime = v.ready.Until, v.documents, v.ready.OneTime
				judged++
			case errors.As(failed, &refused):
				delete(s.guests, d.key)
				dropped++
				s.log.Warn("a pooled guest's evidence no longer passes", "instance_key", d.key, "error", failed)
			}
		}
		s.mu.Unlock()
	}
	if judged > 0 || dropped > 0 || err != nil {
		s.log.Info("judged pooled guests again", "judged", judged, "dropped", dropped, "due", len(due), "vendor", err)
	}
	return judged, err
}

// keepJudged calls Rejudge every minute until ctx ends.
func (s *Service) keepJudged(ctx context.Context) {
	tick := time.NewTicker(session.RefreshEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			_, _ = s.Rejudge(ctx)
		}
	}
}

// Serve serves the replica's API on ln until ctx ends, and keeps its
// verdicts on pooled guests current meanwhile.
func (s *Service) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		TLSConfig:         s.tls,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}
	keeping, stop := context.WithCancel(ctx)
	defer stop()
	stopped, kept := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(kept)
		s.keepJudged(keeping)
	}()
	go func() {
		defer close(stopped)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	err := srv.Serve(tls.NewListener(ln, s.tls))
	stop()
	<-kept
	if ctx.Err() != nil {
		<-stopped
		return nil
	}
	return err
}

// Handler serves the replica's API.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+api.PathHealth, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	mux.HandleFunc("GET "+api.PathState, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, api.StateResponse{Launch: s.cfg.Launch, Signature: s.cfg.Signature})
	})
	mux.HandleFunc("POST "+api.PathOpen, s.pinned(s.guestRoute(s.open)))
	mux.HandleFunc("POST "+api.PathAcquire, s.pinned(s.guestRoute(s.acquire)))
	mux.HandleFunc("PUT "+api.PathTenants+"{tenant}/authority", s.pinned(s.registerAuthority))
	mux.HandleFunc("PUT "+api.PathTenants+"{tenant}/credentials/{name}", s.pinned(s.putCredential))
	return mux
}

// Unpinned reports whether this replica is a TD whose launch document lists
// no machine it may be. Such a replica keeps nothing and releases nothing:
// its host could have built it any machine. It still serves its state, so
// that whoever writes the document can read the machine from the replica's
// evidence and list it.
func (s *Service) Unpinned() bool { return s.unpinned }

// pinned admits a request only to a replica whose document lists its machine.
func (s *Service) pinned(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.unpinned {
			refuse(w, http.StatusConflict, "this key service's launch document lists no machine it may be: it serves its state and nothing else")
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

// refuse answers a request that the replica will not serve. reason goes to
// the caller: it names a rule, and nothing of another tenant.
func refuse(w http.ResponseWriter, status int, reason string, args ...any) {
	httputil.WriteError(w, status, types.ErrorCodeInvalidRequest, fmt.Sprintf(reason, args...))
}

// guestRoute admits a request only from a caller that presented a
// certificate in its handshake, which proved it holds the certificate's key.
func (s *Service) guestRoute(next func(w http.ResponseWriter, r *http.Request, leaf *x509.Certificate, key string, body []byte)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			refuse(w, http.StatusUnauthorized, "a guest presents its attested certificate")
			return
		}
		leaf := r.TLS.PeerCertificates[0]
		key, err := session.InstanceKeyDigest(leaf.PublicKey)
		if err != nil {
			refuse(w, http.StatusUnauthorized, "the certificate carries no usable key")
			return
		}
		body, ok := httputil.ReadCappedBody(w, r, api.MaxRequestBytes)
		if !ok {
			return
		}
		next(w, r, leaf, key, body)
	}
}

// open judges a guest's evidence against the pools the replica serves and
// keeps the verdict, and the evidence, by the guest's instance key. Rule 1
// and rule 2 of the release rule are settled here, off the path of a start,
// and are kept settled by Rejudge.
//
// A guest that no bind has been accepted for may open again under another
// certificate, as it does when the one it opened with nears its end: a
// verdict never outlives the certificate that carried its evidence.
func (s *Service) open(w http.ResponseWriter, r *http.Request, leaf *x509.Certificate, key string, body []byte) {
	var req api.OpenRequest
	if err := json.Unmarshal(body, &req); err != nil || len(req.Launch) == 0 {
		refuse(w, http.StatusBadRequest, "malformed open request")
		return
	}
	s.mu.Lock()
	g, known := s.guests[key]
	same := known && (g.bind != "" || bytes.Equal(g.evidence.Certificate, leaf.Raw))
	full := !known && len(s.guests) >= s.cfg.MaxGuests
	s.mu.Unlock()
	if same {
		writeJSON(w, struct{}{})
		return
	}
	if full {
		refuse(w, http.StatusServiceUnavailable, "the key service tracks as many guests as it can")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), verifyTimeout)
	defer cancel()
	evidence := &session.Relayed{
		Certificate: leaf.Raw, Phase: session.PhaseReady, Launch: req.Launch, Signature: req.Signature,
		Events: []string{session.DocumentDigest(req.Launch)},
	}
	pools := make([]int, len(s.pins))
	for i := range pools {
		pools[i] = i
	}
	v, err := s.judge(ctx, evidence, pools...)
	var refused *session.VerificationError
	switch {
	case errors.As(err, &refused):
		s.log.Warn("a guest of no served pool was refused", "instance_key", key, "error", err)
		refuse(w, http.StatusForbidden, "the guest is of no pool this key service serves")
		return
	case err != nil:
		// Nothing was said of the guest: it asks again.
		s.log.Warn("a guest's evidence could not be judged", "instance_key", key, "error", err)
		refuse(w, http.StatusServiceUnavailable, "the key service could not judge the guest's evidence: the vendor's documents are not at hand")
		return
	}
	s.mu.Lock()
	if g, known := s.guests[key]; !known || g.bind == "" {
		// The one-time keys are the ones the quote just judged binds: a
		// release is made only against a receipt signed under the first.
		s.guests[key] = &guest{evidence: evidence, pool: v.pool, until: v.ready.Until, documents: v.documents, oneTime: v.ready.OneTime}
	}
	s.mu.Unlock()
	s.log.Info("opened a guest's session", "instance_key", key, "again", known)
	writeJSON(w, struct{}{})
}

// standing settles rules 1 and 2 for a release to the guest of key: the
// verdict on the evidence it opened with stands now, on the vendor's
// documents as this replica fetched them within the hour, the newest it
// holds. A verdict that ran out, or that a newer document came after, is
// made again here, on the kept evidence. It returns the status and reason to
// refuse with, or zero.
func (s *Service) standing(ctx context.Context, key string) (int, string) {
	s.mu.Lock()
	g, known := s.guests[key]
	current := known && s.currentLocked(g)
	s.mu.Unlock()
	switch {
	case !known:
		return http.StatusConflict, "the guest has no open session with this key service"
	case current:
		return 0, ""
	}
	ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()
	v, err := s.judge(ctx, g.evidence, g.pool)
	var refused *session.VerificationError
	switch {
	case errors.As(err, &refused):
		s.log.Warn("a guest's evidence no longer passes", "instance_key", key, "error", err)
		return http.StatusForbidden, "the evidence the guest opened its session with no longer passes"
	case err != nil:
		s.log.Warn("a guest's evidence could not be judged again", "instance_key", key, "error", err)
		return http.StatusServiceUnavailable, "the key service's verdict on the guest has run out, and the vendor's documents for another are not at hand"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if now, ok := s.guests[key]; ok && now == g {
		g.until, g.documents = v.ready.Until, v.documents
	}
	return 0, ""
}

// acquire releases what a guest's bind allows, by the release rule.
func (s *Service) acquire(w http.ResponseWriter, r *http.Request, leaf *x509.Certificate, key string, body []byte) {
	began := time.Now()
	var req api.AcquireRequest
	if err := json.Unmarshal(body, &req); err != nil {
		refuse(w, http.StatusBadRequest, "malformed acquire request")
		return
	}
	instance, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		refuse(w, http.StatusUnauthorized, "the certificate carries no usable key")
		return
	}
	// Rule 3: a bind that names this instance key, signed by the authority
	// the replica holds for the bind's tenant.
	bind, err := session.VerifyBind(req.Bind, req.BindSignature)
	if err != nil {
		refuse(w, http.StatusBadRequest, "the bind does not verify")
		return
	}
	if err := bind.Doc.Targets(leaf.PublicKey); err != nil {
		refuse(w, http.StatusForbidden, "the bind names another guest")
		return
	}
	if pin := bind.Doc.KeyService; pin == nil || pin.LaunchKey != string(s.cfg.LaunchKey) || !sameImage(pin.Image, s.doc.Image) {
		refuse(w, http.StatusForbidden, "the bind trusts another key service")
		return
	}
	if err := api.VerifyEncryptionKey(instance, req.EncryptionKey, req.EncryptionKeySignature); err != nil {
		refuse(w, http.StatusBadRequest, "the encryption key is not signed by the guest's instance key")
		return
	}
	digest := session.DocumentDigest(bind.Raw)

	// Rules 1 and 2: the verdict on the evidence of the key this connection
	// proved, from the guest's open, which stands now.
	if status, reason := s.standing(r.Context(), key); status != 0 {
		refuse(w, status, "%s", reason)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g, known := s.guests[key]
	if !known || !s.cfg.Now().Before(g.until) {
		refuse(w, http.StatusConflict, "the guest has no open session with this key service")
		return
	}
	owner, registered := s.tenants[bind.Doc.Tenant]
	if !registered || !bind.SignedBy([]byte(owner.authorityPEM)) {
		// One answer for both, so that nobody learns which tenants exist.
		refuse(w, http.StatusForbidden, "the bind is not signed by an authority this key service holds for its tenant")
		return
	}
	// Rule 3, its other half: the guest's receipt for this bind, signed
	// under the one-time key its evidence bound. The instance key and this
	// channel outlive the bind, so a session that broke out of its sandbox
	// holds both, and could present a bind another binder signed for this
	// guest. It cannot sign the receipt: the guest erased that key before
	// anything of the session ran.
	if _, err := session.VerifyBindReceipt(session.Policy{AllowBound: true}, leaf.PublicKey, g.oneTime, bind, req.Receipt); err != nil {
		s.log.Warn("a bind was presented without the guest's receipt for it", "instance_key", key, "error", err)
		refuse(w, http.StatusForbidden, "the bind comes without the guest's receipt for it, signed by its one-time key")
		return
	}
	// Rule 6: one bind to an instance key.
	switch {
	case g.bind == "" && s.cfg.Now().After(bind.Doc.Expiry()):
		refuse(w, http.StatusForbidden, "the bind has expired")
		return
	case g.bind != "" && g.bind != digest:
		s.log.Warn("a second bind was presented for an instance key", "instance_key", key)
		refuse(w, http.StatusForbidden, "the key service has accepted another bind for this guest")
		return
	}
	// Rule 4: only what the bind's policy declares as the key service's.
	var out api.AcquireResponse
	for _, name := range req.Credentials {
		declared, ok := bind.Doc.Policy.Credential(name)
		if !ok || declared.Source != session.SourceKeyService {
			refuse(w, http.StatusForbidden, "the bind does not declare credential %q as the key service's", name)
			return
		}
		value, err := s.cfg.Store.Get(context.Background(), storePath(bind.Doc.Tenant, name))
		if errors.Is(err, secrets.ErrNotFound) {
			refuse(w, http.StatusNotFound, "the tenant has stored no credential %q", name)
			return
		}
		if err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, types.ErrorCodeInternal, "the credential could not be read")
			return
		}
		if len(value) > declared.Limit() {
			refuse(w, http.StatusForbidden, "credential %q is larger than the bind allows", name)
			return
		}
		sealed, err := api.Seal(req.EncryptionKey, key, digest, name, value)
		if err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, types.ErrorCodeInternal, "the credential could not be sealed")
			return
		}
		out.Credentials = append(out.Credentials, api.Sealed{Name: name, Ciphertext: sealed})
	}
	g.bind = digest
	s.log.Info("released to a bound guest", "instance_key", key, "tenant", bind.Doc.Tenant, "session", bind.Doc.Session,
		"bind", digest, "credentials", len(out.Credentials), "took_us", time.Since(began).Microseconds())
	writeJSON(w, out)
}

func sameImage(a, b session.Image) bool {
	return (&session.KeyService{Image: a}).Equal(&session.KeyService{Image: b})
}

func storePath(tenant, name string) string { return tenant + "/" + name }

// owner admits a tenant's request under a token for this replica, signed by
// one of keys.
func (s *Service) owner(r *http.Request, body []byte, keys ...*ecdsa.PublicKey) error {
	verifier := operatorauth.Verifier{Keys: keys, ClockSkew: tokenClockSkew, Audience: s.audience}
	return verifier.Authorize(r, body)
}

// registerAuthority takes a tenant's first authority key: trust on first
// use, under proof that the registrant holds the key.
func (s *Service) registerAuthority(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("tenant")
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
		refuse(w, http.StatusBadRequest, "a tenant is named by an RFC 1123 subdomain")
		return
	}
	body, ok := httputil.ReadCappedBody(w, r, api.MaxRequestBytes)
	if !ok {
		return
	}
	var req api.AuthorityRequest
	if err := json.Unmarshal(body, &req); err != nil {
		refuse(w, http.StatusBadRequest, "malformed authority request")
		return
	}
	keys, err := operatorauth.ParsePublicKeysPEM([]byte(req.Authority))
	if err != nil || len(keys) != 1 {
		refuse(w, http.StatusBadRequest, "authority must be one public key, PEM")
		return
	}
	if err := s.owner(r, body, keys[0]); err != nil {
		s.log.Warn("an authority registration was refused", "tenant", name, "error", err)
		refuse(w, http.StatusUnauthorized, "the request is not signed by the authority it registers")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch held, registered := s.tenants[name]; {
	case registered && held.authority.Equal(keys[0]):
		// A repeat of the registration.
	case registered:
		refuse(w, http.StatusConflict, "the tenant has an authority already")
		return
	case len(s.tenants) >= s.cfg.MaxTenants:
		refuse(w, http.StatusServiceUnavailable, "the key service holds as many tenants as it can")
		return
	default:
		s.tenants[name] = &tenant{authority: keys[0], authorityPEM: req.Authority, credentials: map[string]bool{}}
		s.log.Info("registered a tenant's authority", "tenant", name)
	}
	writeJSON(w, struct{}{})
}

// putCredential stores one credential of a tenant, under its authority.
func (s *Service) putCredential(w http.ResponseWriter, r *http.Request) {
	name, credential := r.PathValue("tenant"), r.PathValue("name")
	if !session.ValidCredentialName(credential) {
		refuse(w, http.StatusBadRequest, "malformed credential name")
		return
	}
	body, ok := httputil.ReadCappedBody(w, r, api.MaxRequestBytes)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	owner, registered := s.tenants[name]
	if !registered || s.owner(r, body, owner.authority) != nil {
		// One answer for both, so that nobody learns which tenants exist.
		refuse(w, http.StatusUnauthorized, "the request is not signed by the tenant's authority")
		return
	}
	var req api.CredentialRequest
	if err := json.Unmarshal(body, &req); err != nil || len(req.Value) == 0 || len(req.Value) > session.MaxCredentialBytes {
		refuse(w, http.StatusBadRequest, "a credential is 1 to %d bytes", session.MaxCredentialBytes)
		return
	}
	if !owner.credentials[credential] && len(owner.credentials) >= api.MaxCredentialsPerTenant {
		refuse(w, http.StatusForbidden, "the tenant stores as many credentials as it may")
		return
	}
	if _, err := s.cfg.Store.Put(r.Context(), storePath(name, credential), req.Value); err != nil {
		s.log.Warn("a credential could not be stored", "tenant", name, "error", err)
		refuse(w, http.StatusServiceUnavailable, "the key service could not store the credential")
		return
	}
	owner.credentials[credential] = true
	s.log.Info("stored a credential", "tenant", name, "name", credential, "bytes", len(req.Value))
	writeJSON(w, struct{}{})
}
