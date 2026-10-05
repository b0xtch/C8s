package sessionagent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/keyservice"
)

const (
	// keyServiceRetry bounds the pause between attempts to open the guest's
	// session with its key service, which starts at keyServiceFirstRetry.
	keyServiceRetry      = 30 * time.Second
	keyServiceFirstRetry = 250 * time.Millisecond
	// CollateralWait is how long a guest waits for its host's first answer
	// with the vendor's documents before it tries its key service without
	// them.
	CollateralWait = 15 * time.Second
	// keyServiceTimeout bounds one call to the key service.
	keyServiceTimeout = time.Minute
	// certRenewAhead is how long before its end the certificate the guest
	// presents to its key service is replaced, or a quarter of its life for
	// one that lives less than four hours.
	certRenewAhead = time.Hour
	// memberAttempts is how many connections a guest opens at its bind to
	// find a replica of its key service that the bind names, when its
	// session is with another, and memberTimeout bounds each.
	memberAttempts = 3
	memberTimeout  = 10 * time.Second
)

// renewAhead is how long before its end the guest replaces cert, the
// certificate it presents to its key service.
func renewAhead(cert *tls.Certificate) time.Duration {
	return min(certRenewAhead, cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore)/4)
}

// keyService is the guest's session with the key service its launch
// document pins.
type keyService struct {
	client *keyservice.Client
	// key is what the key service seals its releases to, and signature the
	// instance key's word for it.
	key       *keyservice.EncryptionKey
	signature string

	// mu makes one attempt to open the session at a time.
	mu sync.Mutex
	// open is closed once the session is open.
	open chan struct{}
	// replica is the replica the session was last opened with, by its
	// instance key as a bind gives one: a replica keeps a guest's session to
	// itself. mu guards it.
	replica string
	// cert is the certificate the guest presents to the key service: its
	// instance key, with evidence of it.
	certMu sync.Mutex
	cert   *tls.Certificate
}

// newKeyService prepares the guest's session with the key service its launch
// document pins. Nothing is sent yet.
func (a *Agent) newKeyService(pin *session.KeyService) (*keyService, error) {
	if a.cfg.Engine == nil {
		return nil, errors.New("the launch document pins a key service, and this image has nothing to verify one with")
	}
	ks := &keyService{open: make(chan struct{})}
	var err error
	if ks.key, err = keyservice.NewEncryptionKey(); err != nil {
		return nil, err
	}
	if ks.signature, err = keyservice.SignEncryptionKey(a.key, ks.key.Public()); err != nil {
		return nil, err
	}
	ks.client, err = keyservice.NewClient(keyservice.Options{
		Pin:    pin,
		Engine: a.cfg.Engine,
		Certificate: func() (*tls.Certificate, error) {
			return a.keyServiceCertificate(ks)
		},
		// A guest has no road to the vendor of its own: it judges the key
		// service by the documents its host answered with, each held to the
		// vendor's signature and dates.
		Judging: func(ctx context.Context) context.Context {
			return session.AllowHandedDocuments(session.WithCollateralSource(ctx, a.keptCollateral))
		},
		Dial: a.cfg.KeyServiceDial,
		Now:  a.cfg.Now,
	})
	if err != nil {
		return nil, err
	}
	return ks, nil
}

// keyServiceCertificate is the certificate the guest presents to its key
// service, made anew when the last one nears its end.
func (a *Agent) keyServiceCertificate(ks *keyService) (*tls.Certificate, error) {
	ks.certMu.Lock()
	defer ks.certMu.Unlock()
	if ks.cert != nil && a.cfg.Now().Before(ks.cert.Leaf.NotAfter.Add(-renewAhead(ks.cert))) {
		return ks.cert, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), attestTimeout)
	defer cancel()
	cert, _, err := a.provider().Provision(ctx)
	if err != nil {
		return nil, err
	}
	ks.cert = cert
	return cert, nil
}

// keptCollateral is the vendor's documents as the guest's host last answered
// with them: what the guest serves its own verifiers.
func (a *Agent) keptCollateral(context.Context) []session.CollateralDocument {
	blob := a.collateral.Load()
	if blob == nil {
		return nil
	}
	var answer session.CollateralResponse
	if json.Unmarshal(*blob, &answer) != nil {
		return nil
	}
	return answer.Documents
}

// isOpen reports whether the guest's session with its key service is open.
func (ks *keyService) isOpen() bool {
	select {
	case <-ks.open:
		return true
	default:
		return false
	}
}

// openKeyService opens the guest's session with its key service, once.
func (a *Agent) openKeyService(ctx context.Context) error {
	ks := a.keyService
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if ks.isOpen() {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, keyServiceTimeout)
	defer cancel()
	replica, err := ks.client.Open(ctx, a.launch, a.signature)
	if err != nil {
		return fmt.Errorf("open a session with the key service: %w", err)
	}
	ks.replica = replica
	close(ks.open)
	a.log.Info("opened a session with the key service", "replica", replica)
	return nil
}

// OpenKeyService opens the guest's session with the key service its launch
// document pins, and tries again until it holds or ctx ends. A guest does
// this while it is nobody's, so that the key service has judged its evidence
// before a bind arrives. A guest whose launch document pins none returns at
// once.
func (a *Agent) OpenKeyService(ctx context.Context) {
	if a.keyService == nil {
		return
	}
	for pause := keyServiceFirstRetry; ; pause = min(2*pause, keyServiceRetry) {
		err := a.openKeyService(ctx)
		if err == nil {
			return
		}
		a.log.Warn("the key service is not reached yet", "error", err, "retry_in", pause.String())
		select {
		case <-ctx.Done():
			return
		case <-time.After(pause):
		}
	}
}

// KeepKeyServiceOpen opens the guest's session with its key service, as
// OpenKeyService does, and opens it again whenever the certificate the guest
// presents there is replaced while the guest is still nobody's. The key
// service keeps its verdict no longer than the certificate that carried the
// evidence lasts, so a guest that waits longer for its bind shows it a fresh
// quote. It returns once the guest is bound, or ctx ends.
func (a *Agent) KeepKeyServiceOpen(ctx context.Context) {
	a.OpenKeyService(ctx)
	ks := a.keyService
	if ks == nil || !ks.isOpen() {
		return
	}
	for {
		ks.certMu.Lock()
		cert := ks.cert
		ks.certMu.Unlock()
		if cert == nil {
			return
		}
		// Half way between when the certificate is due to be replaced and
		// its end: the next connection presents another.
		again := cert.Leaf.NotAfter.Add(-renewAhead(cert) / 2)
		select {
		case <-ctx.Done():
			return
		case <-time.After(max(again.Sub(a.cfg.Now()), 0)):
		}
		a.measured.RLock()
		bound := a.bind != nil || a.retired
		a.measured.RUnlock()
		if bound {
			return
		}
		if err := a.reopenKeyService(ctx, "under a new certificate"); err != nil {
			a.log.Warn("the session with the key service was not opened again", "error", err, "retry_in", keyServiceRetry.String())
			select {
			case <-ctx.Done():
				return
			case <-time.After(keyServiceRetry):
			}
		}
	}
}

// reopenKeyService opens the guest's session with its key service over a new
// connection, which presents the guest's newest certificate and ends at
// whichever replica answers: one the client is held to, if it is held to
// some. why says what for, in the guest's log.
func (a *Agent) reopenKeyService(ctx context.Context, why string) error {
	ks := a.keyService
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, keyServiceTimeout)
	defer cancel()
	ks.client.Close()
	replica, err := ks.client.Open(ctx, a.launch, a.signature)
	if err != nil {
		return err
	}
	ks.replica = replica
	a.log.Info("opened the session with the key service again, "+why, "replica", replica)
	return nil
}

// holdToMembers has the guest deal with its key service, from its bind on,
// through none but the replicas the bind names. Before its bind a guest
// judges its key service on the vendor's documents as its host hands them
// over, which a host can choose from before a revocation. The binder judged
// the replicas it names on documents it fetched itself, and its authority
// signed the bind.
//
// A guest whose session is with another replica opens one with a replica the
// bind names, and fails if it reaches none: its host leads it elsewhere, or
// the binder's list is of replicas that are gone. A connection that ends at
// a key the bind does not name is sent nothing. A bind that names no key
// service leaves the guest with none to deal with.
func (a *Agent) holdToMembers(ctx context.Context, bind *session.SignedBind) error {
	ks := a.keyService
	if ks == nil {
		return nil
	}
	var members []string
	if named := bind.Doc.KeyService; named != nil {
		members = named.Members
	}
	ks.mu.Lock()
	ks.client.Hold(members)
	with := ks.replica
	ks.mu.Unlock()
	if len(members) == 0 {
		a.log.Info("the bind names no key service, and the guest deals with its pool's no more")
		return nil
	}
	if slices.Contains(members, with) {
		return nil
	}
	a.log.Warn("the session with the key service is with a replica the bind does not name", "replica", with, "named", len(members))
	var err error
	for range memberAttempts {
		attempt, cancel := context.WithTimeout(ctx, memberTimeout)
		err = a.reopenKeyService(attempt, "with a replica the bind names")
		cancel()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return fmt.Errorf("no replica of the key service that the bind names was reached: %w", err)
}

// acquire takes the credentials the bind declares as its key service's and
// puts them where the sandbox finds them, showing the key service the
// guest's receipt for the bind. Each arrives sealed to this guest, this bind
// and its own name.
func (a *Agent) acquire(ctx context.Context, bind *session.SignedBind, receipt *session.SignedReceipt) error {
	var names []string
	for _, c := range bind.Doc.Policy.Credentials {
		if c.Source == session.SourceKeyService {
			names = append(names, c.Name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	began := time.Now()
	// The bind passed acceptable, so the guest has a key service and the
	// bind's is that one.
	ks := a.keyService
	// No bind is taken before the session is open.
	if !ks.isOpen() {
		return errNotReady
	}
	ctx, cancel := context.WithTimeout(ctx, keyServiceTimeout)
	defer cancel()
	asked := time.Now()
	answer, err := ks.client.Acquire(ctx, &keyservice.AcquireRequest{
		Bind: bind.Raw, BindSignature: bind.Signature, Receipt: receipt,
		EncryptionKey: ks.key.Public(), EncryptionKeySignature: ks.signature,
		Credentials: names,
	})
	if err != nil {
		return fmt.Errorf("take the bind's stored credentials: %w", err)
	}
	answered := time.Since(asked)
	sealed := map[string][]byte{}
	for _, c := range answer.Credentials {
		sealed[c.Name] = c.Ciphertext
	}
	digest := session.DocumentDigest(bind.Raw)
	for _, name := range names {
		ciphertext, ok := sealed[name]
		if !ok {
			return fmt.Errorf("the key service released no credential %q", name)
		}
		value, err := ks.key.Open(a.audience, digest, name, ciphertext)
		if err != nil {
			return fmt.Errorf("credential %q: %w", name, err)
		}
		declared, _ := bind.Doc.Policy.Credential(name)
		if len(value) == 0 || len(value) > declared.Limit() {
			return fmt.Errorf("credential %q is not of the size its bind declares", name)
		}
		if _, err := a.creds.put(name, value); err != nil {
			return fmt.Errorf("credential %q: %w", name, err)
		}
	}
	recordStep(ctx, stepCredentials, time.Since(began))
	a.log.Info("took stored credentials from the key service", "count", len(names),
		"took_us", time.Since(began).Microseconds(), "answered_us", answered.Microseconds())
	return nil
}
