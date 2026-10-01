package podagent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/httputil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/podcvm"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	maxConcurrentAttests = 4
	attestTimeout        = 30 * time.Second
	// tokenClockSkew is wide because a guest's clock starts from a
	// host-supplied value. Tokens travel only inside the attested channel and
	// every mutating route is idempotent, so the wider window adds no replay.
	tokenClockSkew = 5 * time.Minute
)

// Handler serves the agent API. Every route but the health probe requires a
// token from a key the launch document authorizes for that route, bound to the
// request's method, path and body.
func (a *Agent) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+podcvm.PathHealth, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("POST "+podcvm.PathAttest, a.authorized(a.doc.AttestKeys(), a.serveAttest))
	mux.HandleFunc("POST "+podcvm.PathExec, a.authorized(a.doc.ExecKeys(), a.serveExec))
	mux.HandleFunc("PUT "+podcvm.PathCredentials+"{name}", a.authorized(a.doc.CredentialKeys(), a.serveCredential))
	return mux
}

// authorized reads the bounded body and admits the request only under a valid
// token. A refusal says nothing about why: the reason goes to the log.
func (a *Agent) authorized(keys []*ecdsa.PublicKey, next func(http.ResponseWriter, *http.Request, []byte)) http.HandlerFunc {
	verifier := operatorauth.Verifier{Keys: keys, ClockSkew: tokenClockSkew}
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := httputil.ReadCappedBody(w, r, podcvm.MaxRequestBytes)
		if !ok {
			return
		}
		if err := verifier.Authorize(r, body); err != nil {
			a.log.Warn("request refused", "path", r.URL.Path, "error", err)
			httputil.WriteError(w, http.StatusUnauthorized, types.ErrorCodeInvalidToken, "unauthorized")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next(w, r, body)
	}
}

func (a *Agent) serveAttest(w http.ResponseWriter, r *http.Request, body []byte) {
	var req podcvm.AttestRequest
	if !decodeStrict(body, &req) || len(req.Nonce) != podcvm.NonceSize {
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
	// Phase and events are read once, so the transcript and the response agree
	// even if the workload is admitted while the quote is in flight.
	phase, events := a.state()
	reportData, err := podcvm.ReportData(&a.key.PublicKey, req.Nonce, events)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, types.ErrorCodeInternal, "attestation unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), attestTimeout)
	defer cancel()
	evidence, err := a.tee.Evidence(ctx, reportData)
	if err != nil {
		a.log.Warn("evidence generation failed", "error", err)
		httputil.WriteError(w, http.StatusBadGateway, types.ErrorCodeAttestationUnavailable, "attestation unavailable")
		return
	}
	writeJSON(w, http.StatusOK, podcvm.AttestResponse{
		Evidence: evidence, Launch: a.launch, Signature: a.signature, Events: events, Phase: phase,
	})
}

func (a *Agent) serveExec(w http.ResponseWriter, r *http.Request, body []byte) {
	var req podcvm.ExecRequest
	if !decodeStrict(body, &req) {
		httputil.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "malformed exec request")
		return
	}
	if err := req.Validate(); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, err.Error())
		return
	}
	if phase, _ := a.state(); phase != podcvm.PhaseRunning {
		httputil.WriteError(w, http.StatusConflict, types.ErrorCodeInvalidRequest, "the workload has not been admitted yet")
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
	decl, ok := a.doc.Credential(name)
	if !ok {
		httputil.WriteError(w, http.StatusNotFound, types.ErrorCodeInvalidRequest, "the launch document declares no such credential")
		return
	}
	var req podcvm.CredentialRequest
	if !decodeStrict(body, &req) || len(req.Value) == 0 || len(req.Value) > decl.Limit() {
		httputil.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "credential value is missing or exceeds its declared size")
		return
	}
	// A credential is for the measured workload, never for a guest still
	// waiting to admit one.
	if phase, _ := a.state(); phase != podcvm.PhaseRunning {
		httputil.WriteError(w, http.StatusConflict, types.ErrorCodeInvalidRequest, "the workload has not been admitted yet")
		return
	}
	replaced, err := a.creds.put(name, req.Value)
	if err != nil {
		a.log.Warn("credential write failed", "name", name, "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, types.ErrorCodeInternal, "credential could not be stored")
		return
	}
	a.log.Info("credential released", "name", name, "bytes", len(req.Value), "replaced", replaced)
	status := http.StatusCreated
	if replaced {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]bool{"replaced": replaced})
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
