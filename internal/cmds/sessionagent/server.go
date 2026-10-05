package sessionagent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/httputil"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/disclosure"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	maxConcurrentAttests = 4
	// maxInflightRequests covers eight commands, four attestations and room
	// for credentials, at up to MaxRequestBytes of unauthenticated body each.
	maxInflightRequests = 24
	attestTimeout       = 30 * time.Second
	// tokenClockSkew is wide because a guest's clock starts from a
	// host-supplied value. Tokens travel only inside the attested channel and
	// every mutating route is idempotent, so the wider window adds no replay.
	tokenClockSkew = 5 * time.Minute
)

// Handler serves the agent API. Every route but the health probe, the state,
// the bind and Intel's documents requires a token from a key the
// guest's bind authorizes for that route, bound to this guest and to the
// request's method, path and body.
func (a *Agent) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+session.PathHealth, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET "+session.PathState, a.serveState)
	mux.HandleFunc("POST "+session.PathBind, a.letIn(a.boundedTo(session.MaxBindRequestBytes, a.serveBind)))
	mux.HandleFunc("POST "+session.PathBindSealed, a.afterBind(a.boundedTo(session.MaxBindRequestBytes, a.serveBindSealed)))
	mux.HandleFunc("POST "+session.PathAttest, a.authorized(session.Access.AttestKeys, a.serveAttest))
	mux.HandleFunc("POST "+session.PathExec, a.authorized(session.Access.ExecKeys, a.serveExec))
	mux.HandleFunc("PUT "+session.PathCredentials+"{name}", a.authorized(session.Access.CredentialKeys, a.serveCredential))
	mux.HandleFunc("POST "+session.PathForward, a.serveForward)
	mux.HandleFunc("GET "+session.PathCollateral, a.serveCollateral)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A request for what the guest does not serve gets a code like any
		// other refusal, where the mux would answer in words of its own.
		if _, pattern := mux.Handler(r); pattern == "" {
			if servedByAnotherMethod(mux, r) {
				a.refuse(w, http.StatusMethodNotAllowed, disclosure.MethodNotAllowed)
				return
			}
			a.refuse(w, http.StatusNotFound, disclosure.NotFound)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// routeMethods are the methods the agent's routes take.
var routeMethods = []string{http.MethodGet, http.MethodPost, http.MethodPut}

// servedByAnotherMethod reports whether the request's path is a route of the
// mux under a method the request did not use.
func servedByAnotherMethod(mux *http.ServeMux, r *http.Request) bool {
	for _, method := range routeMethods {
		if method == r.Method {
			continue
		}
		probe := *r
		probe.Method = method
		if _, pattern := mux.Handler(&probe); pattern != "" {
			return true
		}
	}
	return false
}

// say answers a caller the guest has not authenticated with one message of
// its disclosure schema. A value the schema does not let that message carry
// is not sent: the caller is told the guest could not answer.
func (a *Agent) say(w http.ResponseWriter, status int, message string, v any) {
	body, err := disclosure.Encode(message, v)
	if err != nil {
		a.log.Error("an answer was held back: it is beyond the disclosure schema", "error", err)
		status = http.StatusInternalServerError
		body, _ = disclosure.Encode(disclosure.MessageRefusal, disclosure.Refusal{Error: disclosure.Internal})
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// refuse answers a caller the guest has not authenticated with a code and
// nothing else.
func (a *Agent) refuse(w http.ResponseWriter, status int, code disclosure.Code) {
	a.say(w, status, disclosure.MessageRefusal, disclosure.Refusal{Error: code})
}

// letIn admits a bind by the connection it came on, before any of its body is
// read. One to a guest that takes none yet is refused on its headers: the
// guest has taken in nothing of the caller's and stays as it was booted, with
// every connection it had. The first that is let in raises the fence: every
// other connection the guest accepted before it is closed, so nothing sent to
// the guest before its bind reaches the session. A bind from a connection the
// fence ended is refused on its headers too.
func (a *Agent) letIn(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// A guest whose launch document lists no machine takes no bind at
		// all, and sending it again changes nothing.
		if a.unpinned {
			w.Header().Set("Connection", "close")
			w.Header().Set("Cache-Control", "no-store")
			a.refuse(w, http.StatusConflict, disclosure.BindNoMachine)
			return
		}
		// A guest whose pool has a key service takes no bind until the key
		// service has judged it. Refused on its headers, the bind was not
		// read, and its sender may send it again.
		if !a.takesBinds() {
			w.Header().Set("Connection", "close")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Retry-After", "1")
			a.refuse(w, http.StatusServiceUnavailable, disclosure.NotReady)
			return
		}
		admitted, closed := a.fence.arrive(connOf(r.Context()))
		if !admitted {
			// Closing keeps the server from reading the body to reuse the
			// connection.
			w.Header().Set("Connection", "close")
			w.Header().Set("Cache-Control", "no-store")
			a.refuse(w, http.StatusConflict, disclosure.Fenced)
			return
		}
		if closed > 0 {
			a.log.Info("a bind arrived, and the connections from before it are closed", "closed", closed)
		}
		next(w, r)
	}
}

// afterBind admits what follows a bind by the connection it came on, before
// any of its body is read: a sealed message sent after its bind. A guest no
// bind has reached reads none, and neither does one from a connection the
// fence ended.
func (a *Agent) afterBind(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.fence.follows(connOf(r.Context())) {
			w.Header().Set("Connection", "close")
			w.Header().Set("Cache-Control", "no-store")
			a.refuse(w, http.StatusConflict, disclosure.Fenced)
			return
		}
		next(w, r)
	}
}

// hold takes one of the places the agent has for requests it is reading or
// answering, or answers that there is none. The caller gives it back with
// release, which may be called more than once.
func (a *Agent) hold(w http.ResponseWriter) (release func(), ok bool) {
	select {
	case a.inflight <- struct{}{}:
		return sync.OnceFunc(func() { <-a.inflight }), true
	default:
		w.Header().Set("Retry-After", "1")
		a.refuse(w, http.StatusTooManyRequests, disclosure.Busy)
		return nil, false
	}
}

// bounded reads a request's body within the limits an unauthenticated peer
// gets: a capped size, and a cap on how many are held at once.
func (a *Agent) bounded(next func(http.ResponseWriter, *http.Request, []byte)) http.HandlerFunc {
	return a.boundedTo(session.MaxRequestBytes, next)
}

// boundedTo is bounded for a route whose requests may be up to limit bytes.
func (a *Agent) boundedTo(limit int64, next func(http.ResponseWriter, *http.Request, []byte)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		release, ok := a.hold(w)
		if !ok {
			return
		}
		defer release()
		body, ok := a.body(w, r, limit)
		if !ok {
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next(w, r, body)
	}
}

// body reads a request's body within limit, and refuses the request if it
// is larger or does not arrive.
func (a *Agent) body(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	body, err := readutil.ReadAll(r.Body, limit)
	switch {
	case errors.Is(err, readutil.ErrTooLarge):
		a.refuse(w, http.StatusRequestEntityTooLarge, disclosure.TooLarge)
		return nil, false
	case err != nil:
		a.refuse(w, http.StatusBadRequest, disclosure.Malformed)
		return nil, false
	}
	return body, true
}

// authorized admits the request only under a valid token from one of the keys
// the guest's bind grants this route. The token covers the body, so the
// body is read first, within bounds.
func (a *Agent) authorized(keys func(session.Access) []*ecdsa.PublicKey, next func(http.ResponseWriter, *http.Request, []byte)) http.HandlerFunc {
	return a.bounded(func(w http.ResponseWriter, r *http.Request, body []byte) {
		if _, ok := a.grantedKey(w, r, body, keys); ok {
			next(w, r, body)
		}
	})
}

// grantedKey checks the request's token against the keys the guest's
// documents grant a route, and answers the refusal itself. It returns which of
// those keys signed, by its place among them. The keys are looked up per
// request: a guest has none until it is bound. A refusal says nothing about
// why: the reason goes to the log.
func (a *Agent) grantedKey(w http.ResponseWriter, r *http.Request, body []byte, keys func(session.Access) []*ecdsa.PublicKey) (int, bool) {
	access, _ := a.grants()
	granted := keys(access)
	// A guest grants no key, and then no token is even parsed:
	// nothing of a caller's choosing is read before the guest is somebody's.
	if len(granted) == 0 {
		a.refuse(w, http.StatusUnauthorized, disclosure.Unauthorized)
		return 0, false
	}
	key, err := a.verifier(granted).AuthorizedBy(r, body)
	if err != nil {
		a.log.Warn("request refused", "path", r.URL.Path, "error", err)
		a.refuse(w, http.StatusUnauthorized, disclosure.Unauthorized)
		return 0, false
	}
	return key, true
}

// serveState tells anyone how far along the guest is and what it measured:
// see session.StateResponse. None of it costs a quote.
func (a *Agent) serveState(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	a.say(w, http.StatusOK, disclosure.MessageState, a.state())
}

// state is what the guest says of itself to anyone.
func (a *Agent) state() session.StateResponse {
	a.measured.RLock()
	phase, events := a.stateLocked()
	bind, quote, quoteState, readyCert := a.bind, a.bindQuote, a.bindQuoteState, a.readyCert
	prepared := phase == session.PhaseReady && a.preparedLocked()
	a.measured.RUnlock()

	state := session.StateResponse{
		Phase: phase, InstanceKey: a.keyDER, Prepared: prepared,
		Launch: a.launch, Signature: a.signature, Events: events, BindQuote: quoteState, Attestation: quote,
	}
	if bind != nil {
		state.Bind, state.BindSignature, state.ReadyCertificate = bind.Raw, bind.Signature, readyCert
	}
	return state
}

// verifier checks a token against keys, for this guest alone. The same key
// can be granted on many guests, and a token names the one it is for: what
// one guest was sent is of no use at another.
func (a *Agent) verifier(keys []*ecdsa.PublicKey) operatorauth.Verifier {
	return operatorauth.Verifier{Keys: keys, ClockSkew: tokenClockSkew, Audience: a.audience}
}

// serveBind takes the guest's bind. No token guards it: the bind's own
// signature and the guest it names are what admit it.
func (a *Agent) serveBind(w http.ResponseWriter, r *http.Request, body []byte) {
	var req session.BindRequest
	ctx, trace := withBindTrace(r.Context())
	if !decodeStrict(body, &req) || len(req.Bind) == 0 {
		a.refuse(w, http.StatusBadRequest, disclosure.Malformed)
		return
	}
	traced(ctx, "decoded")
	replayed, answer, err := a.BindWith(ctx, req.Bind, req.Signature, req.Sealed)
	var refusal *bindRefusal
	switch {
	case errors.Is(err, errAlreadyBound):
		a.refuse(w, http.StatusConflict, disclosure.AlreadyBound)
	case errors.Is(err, errRetired):
		a.refuse(w, http.StatusGone, disclosure.Retired)
	case errors.Is(err, errFenced):
		a.refuse(w, http.StatusConflict, disclosure.Fenced)
	case errors.Is(err, errNoMachine):
		a.refuse(w, http.StatusConflict, disclosure.BindNoMachine)
	case errors.Is(err, errNotReady):
		w.Header().Set("Retry-After", "1")
		a.refuse(w, http.StatusServiceUnavailable, disclosure.NotReady)
	case errors.As(err, &refusal):
		// Why, in the guest's own words, stays in the guest's log.
		a.log.Warn("a bind was refused", "code", refusal.code, "error", refusal.err)
		a.refuse(w, http.StatusBadRequest, refusal.code)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// The caller gave up on a bind another request is still completing.
		a.refuse(w, http.StatusServiceUnavailable, disclosure.BindIncomplete)
	case err != nil:
		a.log.Error("bind failed", "error", err)
		a.refuse(w, http.StatusInternalServerError, disclosure.BindFailed)
	default:
		a.measured.RLock()
		phase, _ := a.stateLocked()
		admission := a.admission
		a.measured.RUnlock()
		traced(ctx, "admitted")
		a.say(w, http.StatusOK, disclosure.MessageBound, session.BindResponse{
			Phase: phase, Replayed: replayed, Sealed: answer.Sealed, Admission: admission,
			Receipt: answer.Receipt, Attestation: answer.Attestation,
		})
		// The receipt goes out now. What follows it comes as further
		// documents, each when the guest has it: the sealed answer of a
		// sealed message, once the guest has acted on it, and for a caller
		// that reads on, the guest's state once the quote over the bind's
		// nonce is settled.
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		traced(ctx, "answered")
		if !replayed {
			trace.log(a.log)
		}
		var sealed chan *session.SealedReply
		if answer.Sealed == session.SealedTaken {
			sealed = make(chan *session.SealedReply, 1)
			go func() {
				// A caller that went away gets none. The guest acts on the
				// message all the same, and its answer is kept for the bind
				// sent again.
				defer close(sealed)
				if result, err := a.sealedReply(r.Context()); err == nil {
					sealed <- result
				}
			}()
		}
		var quoted <-chan struct{}
		if answer.Attestation == nil && r.Header.Get(session.BindQuoteHeader) == session.BindQuoteFollows {
			quoted = a.bindQuoteSettled()
		}
		for sealed != nil || quoted != nil {
			message, document := "", any(nil)
			select {
			case result, ok := <-sealed:
				if sealed = nil; !ok {
					return
				}
				message, document = disclosure.MessageSealed, result
			case <-quoted:
				quoted = nil
				message, document = disclosure.MessageState, a.state()
			case <-r.Context().Done():
				return
			}
			body, err := disclosure.Encode(message, document)
			if err != nil {
				a.log.Error("an answer was held back: it is beyond the disclosure schema", "error", err)
				return
			}
			writeDocument(w, body)
		}
	}
}

// serveBindSealed takes a sealed message that follows its bind instead of
// coming with it: see Agent.LateSealed. Like the bind it needs no token:
// what admits it is that it opens under the guest's one-time key and that
// bind, and that a key the bind grants signed each part inside.
func (a *Agent) serveBindSealed(w http.ResponseWriter, r *http.Request, body []byte) {
	var req session.SealedRequest
	if !decodeStrict(body, &req) || len(req.Sealed) == 0 {
		a.refuse(w, http.StatusBadRequest, disclosure.Malformed)
		return
	}
	result, err := a.LateSealed(r.Context(), req.Sealed)
	if err != nil {
		a.refuse(w, http.StatusServiceUnavailable, disclosure.BindIncomplete)
		return
	}
	a.say(w, http.StatusOK, disclosure.MessageSealed, result)
}

// bindEvidence is the evidence a bind's sender would ask for next, taken for
// the nonce the bind carries, so that the sender asks for nothing. It comes
// out of the guest's ration like any other quote. Nil is an attempt that
// gave none: the ration had none due, or the quoting service failed.
//
// It is taken while the bind's sandbox is admitted, over the events the
// register holds from then on, and says the guest runs. The admission hands
// it out only if that comes true.
func (a *Agent) bindEvidence(ctx context.Context, bind *session.SignedBind, events []string) *session.AttestResponse {
	if !a.quotes.take() {
		a.log.Warn(noBindQuote, "error", "this guest's fresh quotes are rationed, and none is due")
		return nil
	}
	reportData, err := session.ReportData(&a.key.PublicKey, bind.Doc.EvidenceNonce(), events)
	if err == nil {
		quoting, cancel := context.WithTimeout(ctx, attestTimeout)
		defer cancel()
		quoting, times := timedQuote(quoting)
		began := time.Now()
		var evidence teetypes.AttestationEvidence
		if evidence, err = a.tee.Evidence(quoting, reportData); err == nil {
			a.log.Info("took the quote over the bind's nonce", "took_us", time.Since(began).Microseconds(), "report_us", times.Report.Microseconds(),
				"connect_us", times.Connect.Microseconds(), "service_us", times.Service.Microseconds())
			return &session.AttestResponse{
				Evidence: evidence, Launch: a.launch, Signature: a.signature, Events: events, Phase: session.PhaseRunning,
				Bind: bind.Raw, BindSignature: bind.Signature,
			}
		}
	}
	a.log.Warn(noBindQuote, "error", err)
	return nil
}

// noBindQuote is what the guest logs for an attempt at the quote over its
// bind's nonce that gave none.
const noBindQuote = "no quote was taken over the bind's nonce"

// attestation takes a quote bound to nonce and to what the guest has measured,
// and says what that is. unavailable tells a quoting service that failed from
// a guest that could not ask it.
func (a *Agent) attestation(ctx context.Context, nonce []byte) (_ *session.AttestResponse, unavailable bool, _ error) {
	// The register cannot move while the quote is taken, so the events this
	// response reports are the ones the quote's register holds. While a
	// sandbox is being admitted the register is ahead of what the guest says,
	// and the quote waits until the two agree again.
	a.measured.RLock()
	for a.settling != nil {
		settling := a.settling
		a.measured.RUnlock()
		select {
		case <-settling:
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
		a.measured.RLock()
	}
	phase, events := a.stateLocked()
	bind := a.bind
	reportData, err := session.ReportData(&a.key.PublicKey, nonce, events)
	if err != nil {
		a.measured.RUnlock()
		return nil, false, err
	}
	ctx, cancel := context.WithTimeout(ctx, attestTimeout)
	defer cancel()
	evidence, err := a.tee.Evidence(ctx, reportData)
	a.measured.RUnlock()
	if err != nil {
		return nil, true, err
	}
	resp := &session.AttestResponse{Evidence: evidence, Launch: a.launch, Signature: a.signature, Events: events, Phase: phase}
	if bind != nil {
		resp.Bind, resp.BindSignature = bind.Raw, bind.Signature
	}
	return resp, false, nil
}

func (a *Agent) serveAttest(w http.ResponseWriter, r *http.Request, body []byte) {
	var req session.AttestRequest
	if !decodeStrict(body, &req) || len(req.Nonce) != session.NonceSize {
		httputil.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "attest needs one 32-byte nonce")
		return
	}
	// Each quote costs a round trip to the host's quoting service.
	select {
	case a.attests <- struct{}{}:
		defer func() { <-a.attests }()
	default:
		w.Header().Set("Retry-After", "1")
		httputil.WriteError(w, http.StatusTooManyRequests, types.ErrorCodeTooManyRequests, "too many attestations in flight")
		return
	}
	// That service is every guest's. This one takes its share and no more: a
	// quote that is nearly due is waited for here, and a caller further back
	// is told when to return.
	wait, booked := a.quotes.reserve()
	if !booked {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
		httputil.WriteError(w, http.StatusTooManyRequests, types.ErrorCodeTooManyRequests, "this guest's fresh quotes are rationed")
		return
	}
	if wait > 0 {
		select {
		case <-time.After(wait):
		case <-r.Context().Done():
			return
		}
	}
	resp, unavailable, err := a.attestation(r.Context(), req.Nonce)
	switch {
	case unavailable:
		a.log.Warn("evidence generation failed", "error", err)
		httputil.WriteError(w, http.StatusBadGateway, types.ErrorCodeAttestationUnavailable, "attestation unavailable")
	case err != nil:
		httputil.WriteError(w, http.StatusInternalServerError, types.ErrorCodeInternal, "attestation unavailable")
	default:
		writeJSON(w, http.StatusOK, resp)
	}
}

func (a *Agent) serveExec(w http.ResponseWriter, r *http.Request, body []byte) {
	var req session.ExecRequest
	if !decodeStrict(body, &req) {
		httputil.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "malformed exec request")
		return
	}
	if err := req.Validate(); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, err.Error())
		return
	}
	if !a.sandboxRunning() {
		httputil.WriteError(w, http.StatusConflict, types.ErrorCodeInvalidRequest, "the sandbox has not been admitted yet")
		return
	}
	result, err := a.execs.run(r.Context(), &req)
	switch {
	case errors.Is(err, errExecBusy):
		w.Header().Set("Retry-After", "1")
		httputil.WriteError(w, http.StatusTooManyRequests, types.ErrorCodeTooManyRequests, err.Error())
	case errors.Is(err, errExecEvicted):
		httputil.WriteError(w, http.StatusConflict, types.ErrorCodeInvalidRequest, err.Error())
	case err != nil:
		// The command line and its output are tenant data: neither is logged.
		a.log.Warn("exec failed", "id", req.ID, "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, types.ErrorCodeInternal, "command could not be run")
	default:
		writeJSON(w, http.StatusOK, result)
	}
}

func (a *Agent) serveCredential(w http.ResponseWriter, r *http.Request, body []byte) {
	name := r.PathValue("name")
	_, declared := a.grants()
	var decl session.Credential
	ok := false
	for _, c := range declared {
		if c.Name == name {
			decl, ok = c, true
		}
	}
	if !ok {
		httputil.WriteError(w, http.StatusNotFound, types.ErrorCodeInvalidRequest, "the guest's bind declares no such credential")
		return
	}
	if decl.Source == session.SourceKeyService {
		httputil.WriteError(w, http.StatusForbidden, types.ErrorCodeInvalidRequest, "the bind has this credential come from its key service, and from nobody else")
		return
	}
	var req session.CredentialRequest
	if !decodeStrict(body, &req) || len(req.Value) == 0 || len(req.Value) > decl.Limit() {
		httputil.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "credential value is missing or exceeds its declared size")
		return
	}
	// A credential is for the measured sandbox, never for a guest still
	// waiting to admit one.
	if !a.sandboxRunning() {
		httputil.WriteError(w, http.StatusConflict, types.ErrorCodeInvalidRequest, "the sandbox has not been admitted yet")
		return
	}
	held, err := a.creds.put(name, req.Value)
	switch {
	case errors.Is(err, errCredentialHeld):
		a.log.Warn("credential refused", "name", name, "error", err)
		httputil.WriteError(w, http.StatusConflict, types.ErrorCodeInvalidRequest, err.Error())
		return
	case err != nil:
		a.log.Warn("credential write failed", "name", name, "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, types.ErrorCodeInternal, "credential could not be stored")
		return
	}
	a.log.Info("credential released", "name", name, "bytes", len(req.Value), "held", held)
	// A repeat of what the guest took is answered as held, and nothing is
	// written again.
	status := http.StatusCreated
	if held {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]bool{"held": held})
}

// decodeStrict accepts exactly one JSON value with no unknown fields.
func decodeStrict(body []byte, out any) bool {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return false
	}
	return dec.Decode(new(any)) == io.EOF
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
