package sessionagent

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/httputil"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// hostListener accepts connections from the guest's host, and from nobody
// else, each with handInTimeout on its reads and writes.
type hostListener interface {
	Accept() (io.ReadWriteCloser, error)
	Close() error
}

// notePlatform keeps which of Intel's documents this guest's evidence is
// judged against, from the first evidence that names any.
func (a *Agent) notePlatform(env teetypes.AttestationEvidence) {
	if a.platform.Load() != nil {
		return
	}
	if platform, err := session.CollateralPlatformOf(env); err == nil {
		a.platform.Store(platform)
	}
}

// TakeHandIns takes what the guest's host hands in on ln, one connection at a
// time, until ln ends: see session.CollateralVsockPort.
//
// The host is told which platform this guest's quotes come from, and answers
// with Intel's documents for it. The guest keeps the answer as bytes, reads
// none of it and acts on none of it: it is what PathCollateral answers with,
// for a verifier to check. A host that hands in anything else has cost that
// verifier a fetch from Intel.
func (a *Agent) TakeHandIns(ln hostListener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		a.takeHandIn(conn)
	}
}

func (a *Agent) takeHandIn(conn io.ReadWriteCloser) {
	defer conn.Close()
	platform := a.platform.Load()
	if platform == nil {
		return
	}
	hello, err := json.Marshal(platform)
	if err != nil {
		return
	}
	if _, err := conn.Write(append(hello, '\n')); err != nil {
		return
	}
	// Whoever only asks which platform this is sends nothing, and leaves
	// what the guest holds as it is.
	blob, err := readutil.ReadAll(conn, session.MaxCollateralBytes)
	if err != nil {
		a.log.Warn("a hand-in from the host was not taken", "error", err)
		return
	}
	if len(blob) == 0 {
		return
	}
	a.KeepCollateral(blob)
	a.log.Info("the host handed in Intel's documents", "bytes", len(blob))
}

// KeepCollateral keeps blob as the guest's answer to PathCollateral: what its
// host handed in, unread.
func (a *Agent) KeepCollateral(blob []byte) { a.collateral.Store(&blob) }

// serveCollateral answers with what the host last handed in, byte for byte:
// see session.CollateralResponse. Anyone may ask. Intel publishes these
// documents, and the guest vouches for none of them.
func (a *Agent) serveCollateral(w http.ResponseWriter, _ *http.Request) {
	blob := a.collateral.Load()
	if blob == nil {
		httputil.WriteError(w, http.StatusNotFound, types.ErrorCodeInvalidRequest, "this guest's host has handed it none of Intel's documents")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(*blob)
}
