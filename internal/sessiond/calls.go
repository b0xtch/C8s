package sessiond

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	sessionv1alpha1 "github.com/confidential-dot-ai/c8s/api/session/v1alpha1"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

const (
	// maxClaimWait bounds how long one Claim waits for a ready TD.
	maxClaimWait = 2 * time.Minute
	// evidenceTimeout bounds the daemon's own request to a guest for what it
	// serves to anyone.
	evidenceTimeout = 10 * time.Second
	// certMargin is how long a certificate relayed with a claim must still
	// be valid for.
	certMargin = 10 * time.Minute
	// maxBindWait bounds one Bind: the guest admits its sandbox within it or
	// the caller asks again.
	maxBindWait = 5 * time.Minute
	// busyRetry is the pause before a guest that said "try again" is asked
	// again.
	busyRetry = 200 * time.Millisecond
	// maxSignatureBytes bounds a bind's signature.
	maxSignatureBytes = 4096
)

var (
	requestIDRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	// A session's name is an RFC 1123 label, as its bind names it.
	sessionRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

func checkRequestID(id string) error {
	if !requestIDRE.MatchString(id) {
		return status.Error(codes.InvalidArgument, "request_id must be 1 to 128 of A-Z a-z 0-9 . _ -")
	}
	return nil
}

// Claim reserves a ready TD of a pool for a session, in the daemon's own
// record. It asks the guest nothing: the guest learns of the claim from the
// bind, and raises its fence then.
func (d *Daemon) Claim(ctx context.Context, req *sessionv1alpha1.ClaimRequest) (*sessionv1alpha1.Claimed, error) {
	if err := checkRequestID(req.GetRequestId()); err != nil {
		return nil, err
	}
	if !sessionRE.MatchString(req.GetSession()) {
		return nil, status.Error(codes.InvalidArgument, "session must be an RFC 1123 label")
	}
	wait := req.GetWait().AsDuration()
	if wait < 0 || wait > maxClaimWait {
		return nil, status.Errorf(codes.InvalidArgument, "wait must be between 0 and %s", maxClaimWait)
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		d.mu.Lock()
		pool, ok := d.pools[req.GetPool()]
		if !ok {
			d.mu.Unlock()
			return nil, status.Errorf(codes.NotFound, "no pool %q", req.GetPool())
		}
		if answer, err := d.repeatedClaim(req); answer != nil || err != nil {
			d.mu.Unlock()
			return answer, err
		}
		t := d.oldestReady(pool)
		if t == nil {
			changed, hint := d.changed, d.retryHint(pool)
			d.mu.Unlock()
			select {
			case <-changed:
				continue
			case <-ctx.Done():
				return nil, status.FromContextError(ctx.Err()).Err()
			case <-deadline.C:
				return nil, exhausted(pool.cfg.name, hint)
			}
		}
		picked := time.Now()
		t.rec.State = StateClaimed
		t.rec.Claim = &claim{RequestID: req.GetRequestId(), Session: req.GetSession()}
		t.busy = true
		err := d.save(t)
		d.notify()
		d.mu.Unlock()
		if err != nil {
			d.end(t, "its record could not be kept", "")
			return nil, status.Error(codes.Internal, "the claim could not be recorded")
		}
		answer, err := d.claimed(ctx, t, pool, picked)
		if err == nil {
			return answer, nil
		}
		// A TD whose evidence the daemon neither kept nor could fetch is
		// not offered again, and the claim goes on to the next.
		d.log.Warn("a ready TD could not be claimed", "td", t.rec.ID, "error", err)
		d.mu.Lock()
		t.rec.Claim, t.busy = nil, false
		d.endLocked(t, "gave no evidence for its claim", "")
		d.mu.Unlock()
		if ctx.Err() != nil {
			return nil, status.FromContextError(ctx.Err()).Err()
		}
	}
}

// repeatedClaim answers a Claim that was made before, or that the session's
// state rules out. Nil and nil is a new claim. The caller holds the lock.
func (d *Daemon) repeatedClaim(req *sessionv1alpha1.ClaimRequest) (*sessionv1alpha1.Claimed, error) {
	for _, t := range d.tds {
		for _, r := range t.rec.Released {
			if r.Claim == req.GetRequestId() {
				return nil, status.Error(codes.FailedPrecondition, "the claim ended unbound, and its TD returned to the pool")
			}
		}
		c := t.rec.Claim
		if c == nil {
			continue
		}
		if c.RequestID == req.GetRequestId() {
			if c.Session != req.GetSession() || t.rec.Pool != req.GetPool() {
				return nil, status.Error(codes.InvalidArgument, "request_id was used for another claim")
			}
			if c.Answer == nil {
				return nil, status.Error(codes.Aborted, "the first request with this id is still in progress")
			}
			var answer sessionv1alpha1.Claimed
			if err := proto.Unmarshal(c.Answer, &answer); err != nil {
				return nil, status.Error(codes.Internal, "the first answer could not be read back")
			}
			return &answer, nil
		}
		if c.Session == req.GetSession() && t.rec.State != StateEnded {
			return nil, status.Errorf(codes.AlreadyExists, "session %s has a TD", c.Session)
		}
	}
	return nil, nil
}

// oldestReady picks the pool's ready TD that has waited longest, so that
// none waits out its age limit behind younger ones. The caller holds the
// lock.
func (d *Daemon) oldestReady(pool *poolState) *td {
	var oldest *td
	for _, t := range d.tds {
		if t.rec.Pool == pool.cfg.name && t.rec.State == StateReady && !t.busy &&
			(oldest == nil || t.rec.Created.Before(oldest.rec.Created)) {
			oldest = t
		}
	}
	return oldest
}

// retryHint is when a claim that found the pool empty may find a TD: the
// time a TD of the pool last took to boot. The caller holds the lock.
func (d *Daemon) retryHint(pool *poolState) time.Duration {
	if pool.bootTime > 0 {
		return pool.bootTime
	}
	return 10 * time.Second
}

func exhausted(pool string, hint time.Duration) error {
	st := status.Newf(codes.ResourceExhausted, "pool %s has no ready TD", pool)
	if detailed, err := st.WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(hint)}); err == nil {
		st = detailed
	}
	return st.Err()
}

// claimed answers a claim with what the claimed guest said of itself when it
// was last asked, and starts the claim's grace. picked is when the claim took
// the TD.
func (d *Daemon) claimed(ctx context.Context, t *td, pool *poolState, picked time.Time) (*sessionv1alpha1.Claimed, error) {
	d.mu.Lock()
	offered, leaf, collateral := t.offered, t.leaf, t.collateral
	d.mu.Unlock()
	// A ready guest says the same of itself until it is bound, and a guest
	// that somebody bound around the daemon refuses the bind this claim
	// leads to. A daemon that took the TD over from an earlier one has kept
	// nothing yet, and a certificate about to run out is of no use to a
	// binder: the guest is asked then, over a new connection, which it
	// answers under the certificate it serves now.
	var evidence *sessionv1alpha1.Evidence
	var guest time.Duration
	if offered != nil && lasts(leaf, d.now()) {
		evidence = &sessionv1alpha1.Evidence{
			Certificate: leaf, LaunchDocument: offered.Launch, LaunchSignature: []byte(offered.Signature),
			Events: offered.Events, Phase: string(session.PhaseReady), Collateral: collateral,
		}
	} else {
		ctx, cancel := context.WithTimeout(ctx, evidenceTimeout)
		defer cancel()
		asked := time.Now()
		t.guests.reconnect()
		var err error
		if evidence, err = t.guests.evidence(ctx, t.rec.Address); err != nil {
			return nil, err
		}
		if session.Phase(evidence.GetPhase()) != session.PhaseReady {
			return nil, fmt.Errorf("the guest is %s, not ready: somebody bound it", evidence.GetPhase())
		}
		guest = time.Since(asked)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	t.busy = false
	if t.rec.State != StateClaimed {
		return nil, errors.New("the TD ended while it was claimed")
	}
	t.rec.Claim.BindBy = d.now().Add(time.Duration(pool.cfg.BindGrace))
	answer := &sessionv1alpha1.Claimed{
		Td: t.rec.ID, Host: d.cfg.Host, Evidence: evidence, BindBy: timestamppb.New(t.rec.Claim.BindBy),
	}
	kept, err := proto.Marshal(answer)
	if err != nil {
		return nil, err
	}
	t.rec.Claim.Answer = kept
	if err := d.save(t); err != nil {
		return nil, err
	}
	d.armLapse(t)
	d.log.Info("claimed a TD", "td", t.rec.ID, "pool", t.rec.Pool, "session", t.rec.Claim.Session,
		"took_us", time.Since(picked).Microseconds(), "guest_us", guest.Microseconds())
	return answer, nil
}

// lasts reports whether a guest's certificate is good for long enough that
// a caller who is handed it now can still use it.
func lasts(leaf []byte, now time.Time) bool {
	cert, err := x509.ParseCertificate(leaf)
	return err == nil && now.Add(certMargin).Before(cert.NotAfter)
}

// Bind hands a claimed TD its bind and answers with the guest's receipt for
// it. The call is a stream both ways. Its first message is the bind, with a
// message sealed for the guest if its sender had one by then: the session's
// first command, credentials its binder holds, or both. A sealed message may
// also come alone in the next message, and is carried to the guest, which
// opens it while it still takes the bind. The first answer is the receipt,
// with what the guest says became of a sealed message that came with the
// bind. What became of one that came after it, and the sealed answer of one
// the guest took, follow in a later message. The daemon reads none of
// either.
//
// A call whose bind came with no sealed message ends once its caller has
// closed its side, having sent one or not.
func (d *Daemon) Bind(stream sessionv1alpha1.Sessions_BindServer) error {
	req, err := stream.Recv()
	if err != nil {
		return status.Error(codes.InvalidArgument, "the call's first message is the bind")
	}
	if n := len(req.GetSealed()); n > session.MaxSealedBytes {
		return status.Errorf(codes.InvalidArgument, "sealed is at most %d bytes", session.MaxSealedBytes)
	}
	ctx := stream.Context()
	// One answer goes out at a time, and the receipt before any other.
	var sending sync.Mutex
	send := func(answer *sessionv1alpha1.Bound) error {
		sending.Lock()
		defer sending.Unlock()
		return stream.Send(answer)
	}
	relaying := make(chan *td, 1)
	receipted := make(chan struct{})
	// late is what a sealed message that comes in the call's next message
	// comes to: nil when the bind brought its own.
	var late chan error
	if len(req.GetSealed()) == 0 {
		late = make(chan error, 1)
		go func() { late <- d.lateSealed(stream, relaying, receipted, send) }()
	}
	answer, wait, err := d.bind(ctx, req, relaying)
	if err != nil {
		return err
	}
	if err := send(answer); err != nil {
		return err
	}
	close(receipted)
	if wait != nil {
		result, err := wait()
		if err != nil {
			d.log.Warn("the answer to a sealed message was lost", "td", req.GetTd(), "error", err)
			return status.Error(codes.Unavailable, "the guest's answer to the sealed message was lost: send the same request again")
		}
		return send(&sessionv1alpha1.Bound{SealedStatus: result.Sealed, SealedAnswer: result.Answer})
	}
	// The caller may still send its sealed message, which the guest answers
	// whenever it comes: by now, that it came too late, unless this call
	// repeats one whose message the guest took.
	if late != nil {
		return <-late
	}
	return nil
}

// lateSealed carries a sealed message that comes alone in the next message
// of a Bind call to the guest, once the bind has been sent there, and sends
// back what became of it after the receipt. It returns once the caller has
// said all it will.
func (d *Daemon) lateSealed(stream sessionv1alpha1.Sessions_BindServer, relaying <-chan *td, receipted <-chan struct{}, send func(*sessionv1alpha1.Bound) error) error {
	next, err := stream.Recv()
	if err != nil || len(next.GetSealed()) == 0 {
		// The caller has no more to say, or the call is over.
		return nil
	}
	if len(next.GetSealed()) > session.MaxSealedBytes {
		return status.Errorf(codes.InvalidArgument, "sealed is at most %d bytes", session.MaxSealedBytes)
	}
	ctx := stream.Context()
	var t *td
	select {
	case t = <-relaying:
	case <-ctx.Done():
		return nil
	}
	if t == nil {
		// The bind was never sent to a guest.
		return nil
	}
	d.mu.Lock()
	address := t.rec.Address
	d.mu.Unlock()
	answer, err := t.guests.sealed(ctx, address, next.GetSealed())
	if err != nil {
		// The guest took it or did not: its sender sends what it sealed over
		// a connection of its own, which the guest answers either way.
		d.log.Warn("a sealed message sent after its bind got no answer", "error", err)
		answer = &session.SealedReply{Sealed: session.SealedTooLate}
	}
	select {
	case <-receipted:
	case <-ctx.Done():
		return nil
	}
	return send(&sessionv1alpha1.Bound{SealedStatus: answer.Sealed, SealedAnswer: answer.Answer})
}

// bind is the bind itself: it records it, hands it to the guest and returns
// the guest's first answer, with how to wait for the sealed answer of a
// sealed message if the guest took one. relaying is told the TD once its
// guest has been sent the bind, now or by an earlier call, and nil if it
// never was: a sealed message that follows the bind is sent to the guest
// after the bind, on a connection opened after it, which is one the guest's
// fence lets in.
func (d *Daemon) bind(ctx context.Context, req *sessionv1alpha1.BindRequest, relaying chan<- *td) (*sessionv1alpha1.Bound, sealedWait, error) {
	began := time.Now()
	var told sync.Once
	tell := func(t *td) { told.Do(func() { relaying <- t }) }
	defer tell(nil)
	if err := checkRequestID(req.GetRequestId()); err != nil {
		return nil, nil, err
	}
	if n := len(req.GetBind()); n == 0 || n > session.MaxBindSize {
		return nil, nil, status.Errorf(codes.InvalidArgument, "bind must be 1 to %d bytes", session.MaxBindSize)
	}
	if n := len(req.GetSignature()); n == 0 || n > maxSignatureBytes {
		return nil, nil, status.Errorf(codes.InvalidArgument, "signature must be 1 to %d bytes", maxSignatureBytes)
	}
	sum := sha256.New()
	sum.Write(req.GetBind())
	sum.Write([]byte{0})
	sum.Write(req.GetSignature())
	digest := hex.EncodeToString(sum.Sum(nil))

	d.mu.Lock()
	t, ok := d.tds[req.GetTd()]
	if !ok {
		d.mu.Unlock()
		return nil, nil, status.Error(codes.NotFound, "no such TD")
	}
	replay := false
	switch b := t.rec.Bind; {
	case b != nil && b.RequestID != req.GetRequestId():
		d.mu.Unlock()
		return nil, nil, status.Error(codes.FailedPrecondition, "the TD was sent a bind by another request")
	case b != nil && b.Digest != digest:
		d.mu.Unlock()
		return nil, nil, status.Error(codes.InvalidArgument, "request_id was used for another bind")
	case b != nil && b.Answer != nil && len(req.GetSealed()) == 0:
		defer d.mu.Unlock()
		var answer sessionv1alpha1.Bound
		if err := proto.Unmarshal(b.Answer, &answer); err != nil {
			return nil, nil, status.Error(codes.Internal, "the first answer could not be read back")
		}
		// What became of a sealed message is said to whoever sent one. The
		// guest has the bind, and answers a message that followed it as it
		// did the first time.
		answer.SealedStatus = ""
		tell(t)
		return &answer, nil, nil
	case t.busy:
		d.mu.Unlock()
		return nil, nil, status.Error(codes.Aborted, "another request for this TD is still in progress")
	case t.rec.State == StateEnded:
		reason := t.rec.Ended.Reason
		d.mu.Unlock()
		return nil, nil, status.Errorf(codes.FailedPrecondition, "the TD ended: %s", reason)
	case b != nil && b.Answer != nil:
		// The same bind again, with a sealed message: the guest answers it
		// as it answered the first, and says what became of this message.
		// Only the guest keeps a sealed answer.
		replay = true
	case b == nil && t.rec.State != StateClaimed:
		state := t.rec.State
		d.mu.Unlock()
		return nil, nil, status.Errorf(codes.FailedPrecondition, "the TD is %s, not claimed: a claim lapses when its grace runs out", state)
	}
	// A new bind, or the same one again after an answer that was lost: the
	// guest answers a bind it has taken as it answered the first time.
	if t.lapse != nil {
		t.lapse.Stop()
	}
	if !replay {
		t.rec.Bind = &bound{RequestID: req.GetRequestId(), Digest: digest}
		t.rec.State = StateBound
	}
	t.busy = true
	address := t.rec.Address
	var err error
	if !replay {
		err = d.save(t)
	}
	d.mu.Unlock()
	if err != nil {
		d.end(t, "its record could not be kept", "")
		return nil, nil, status.Error(codes.Internal, "the bind could not be recorded")
	}

	asked := time.Now()
	relayed, err := d.relayBind(ctx, t, address, req, func() { tell(t) })
	guest := time.Since(asked)
	d.mu.Lock()
	defer d.mu.Unlock()
	t.busy = false
	var refused *refusal
	switch {
	case errors.As(err, &refused):
		// Whatever the guest made of those bytes, it is not offered again.
		d.endLocked(t, "the guest refused its bind", "")
		return nil, nil, status.Errorf(codes.FailedPrecondition, "the guest refused the bind and its TD is ended: %s", refused.message)
	case err != nil:
		if t.rec.State == StateEnded {
			return nil, nil, status.Errorf(codes.FailedPrecondition, "the TD ended: %s", t.rec.Ended.Reason)
		}
		// Whether the guest took the bind is not known: the same request
		// again finds out.
		d.log.Warn("a bind's answer was lost", "td", t.rec.ID, "error", err)
		return nil, nil, status.Error(codes.Unavailable, "the guest did not answer the bind: send the same request again")
	}
	if t.rec.State == StateEnded {
		return nil, nil, status.Errorf(codes.FailedPrecondition, "the TD ended: %s", t.rec.Ended.Reason)
	}
	evidence := relayed.evidence
	// The vendor's documents as the guest last handed them over: the binder's
	// verifier may want them, and the guest is not asked again for them.
	if len(evidence.GetCollateral()) == 0 {
		evidence.Collateral = t.collateral
	}
	answer := &sessionv1alpha1.Bound{Evidence: evidence, Receipt: relayed.receipt, SealedStatus: relayed.sealed}
	if replay {
		return answer, relayed.wait, nil
	}
	if t.rec.Bind.Answer, err = proto.Marshal(answer); err != nil {
		return nil, nil, status.Error(codes.Internal, "the answer could not be kept")
	}
	if session.Phase(evidence.GetPhase()) == session.PhaseRunning {
		t.rec.State = StateRunning
	}
	if err := d.save(t); err != nil {
		d.log.Error("a TD's record could not be kept", "td", t.rec.ID, "error", err)
	}
	d.log.Info("bound a TD", "td", t.rec.ID, "session", t.session(), "phase", evidence.GetPhase(),
		"took_us", time.Since(began).Microseconds(), "guest_us", guest.Microseconds(), "answer_bytes", len(t.rec.Bind.Answer),
		"sealed", relayed.sealed)
	d.notify()
	return answer, relayed.wait, nil
}

// relayBind posts the bind until the guest answers it for good. A guest that
// took a sealed message with it answers that later, over the same request,
// which lives until then.
func (d *Daemon) relayBind(ctx context.Context, t *td, address string, req *sessionv1alpha1.BindRequest, wrote func()) (*boundAnswer, error) {
	ctx, cancel := context.WithTimeout(ctx, maxBindWait)
	// The TD's end ends the wait.
	stop := context.AfterFunc(t.ctx, cancel)
	done := func() {
		stop()
		cancel()
	}
	for {
		answer, err := t.guests.bind(ctx, address, req.GetBind(), req.GetSignature(), req.GetSealed(), wrote)
		if err == nil && answer.wait != nil {
			wait := answer.wait
			answer.wait = func() (*session.SealedReply, error) {
				defer done()
				return wait()
			}
			return answer, nil
		}
		if !errors.Is(err, errBusy) {
			done()
			return answer, err
		}
		select {
		case <-ctx.Done():
			done()
			return nil, ctx.Err()
		case <-time.After(busyRetry):
		}
	}
}

// Destroy ends the TD of a session.
func (d *Daemon) Destroy(_ context.Context, req *sessionv1alpha1.DestroyRequest) (*sessionv1alpha1.Session, error) {
	if err := checkRequestID(req.GetRequestId()); err != nil {
		return nil, err
	}
	if !sessionRE.MatchString(req.GetSession()) {
		return nil, status.Error(codes.InvalidArgument, "session must be an RFC 1123 label")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	destroyed := func(t *td) *sessionv1alpha1.Session {
		return &sessionv1alpha1.Session{
			Name: req.GetSession(), Pool: t.rec.Pool, Td: t.rec.ID, Host: d.cfg.Host,
			State: sessionv1alpha1.SessionState_SESSION_STATE_DESTROYED,
		}
	}
	var live, last *td
	for _, t := range d.tds {
		// A repeat of the request that gave a claim back.
		for _, r := range t.rec.Released {
			if r.Destroy == req.GetRequestId() {
				if r.Session != req.GetSession() {
					return nil, status.Error(codes.InvalidArgument, "request_id was used to destroy another session")
				}
				return destroyed(t), nil
			}
		}
		if t.session() != req.GetSession() {
			if t.rec.Ended != nil && t.rec.Ended.RequestID == req.GetRequestId() {
				return nil, status.Error(codes.InvalidArgument, "request_id was used to destroy another session")
			}
			continue
		}
		if t.rec.State != StateEnded {
			live = t
		} else if last == nil || t.rec.Ended.At.After(last.rec.Ended.At) {
			last = t
		}
	}
	switch {
	case live != nil && d.releasable(live):
		// The session's TD took nothing of it: the pool has it again.
		d.log.Info("a claim was given back", "td", live.rec.ID, "session", req.GetSession())
		d.release(live, req.GetRequestId())
		return destroyed(live), nil
	case live != nil:
		d.endLocked(live, "destroyed", req.GetRequestId())
		last = live
	case last == nil:
		return nil, status.Errorf(codes.NotFound, "no session %q", req.GetSession())
	}
	return destroyed(last), nil
}

// GetEvidence returns what a TD's guest serves to anyone.
func (d *Daemon) GetEvidence(ctx context.Context, req *sessionv1alpha1.EvidenceRequest) (*sessionv1alpha1.Evidence, error) {
	d.mu.Lock()
	t, ok := d.tds[req.GetTd()]
	if !ok {
		d.mu.Unlock()
		return nil, status.Error(codes.NotFound, "no such TD")
	}
	state, address := t.rec.State, t.rec.Address
	d.mu.Unlock()
	switch state {
	case StateEnded:
		return nil, status.Error(codes.FailedPrecondition, "the TD ended")
	case StateBooting:
		return nil, status.Error(codes.Unavailable, "the TD does not serve yet")
	}
	// Anyone may ask, so the daemon bounds how many it asks its guests for at
	// once.
	select {
	case d.relays <- struct{}{}:
		defer func() { <-d.relays }()
	default:
		return nil, status.Error(codes.ResourceExhausted, "too many evidence requests in flight")
	}
	ctx, cancel := context.WithTimeout(ctx, evidenceTimeout)
	defer cancel()
	evidence, err := t.guests.evidence(ctx, address)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "the guest did not answer")
	}
	return evidence, nil
}
