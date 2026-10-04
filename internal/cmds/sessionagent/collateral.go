package sessionagent

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/disclosure"
)

// askPace is how often a guest asks its host for Intel's documents. Intel
// signs them anew about once an hour and a verifier takes one for two hours
// from Intel's date on it. A host keeps a set for ten minutes, so a guest
// that asks every ten serves none older than eighty.
type askPace struct {
	// every is the time between two asks that were answered.
	every time.Duration
	// first is how soon the guest asks again after an ask that was not. It
	// doubles from there, up to retry.
	first, retry time.Duration
	// answer bounds one ask. A host with none of the documents fetches them
	// from Intel before it answers.
	answer time.Duration
}

var collateralPace = askPace{
	every: 10 * time.Minute, first: 250 * time.Millisecond, retry: 30 * time.Second, answer: 12 * time.Second,
}

// errNoDocuments is a host that answered an ask with no bytes.
var errNoDocuments = errors.New("the host has none of Intel's documents now")

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

// AskHost asks the guest's host for Intel's documents for this guest's
// platform, now and again until ctx ends: see session.HostConfig. dial opens
// a connection to the host's port.
//
// The host is told which platform this guest's quotes come from, and answers
// with Intel's documents for it. The guest keeps the answer as bytes, reads
// none of it and acts on none of it: it is what PathCollateral answers with,
// for a verifier to check. A host that answers with anything else has cost
// that verifier a fetch from Intel.
func (a *Agent) AskHost(ctx context.Context, dial func(context.Context) (net.Conn, error)) {
	a.askHost(ctx, dial, collateralPace, pause)
}

// pause waits for d, and reports false once ctx has ended.
func pause(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

func (a *Agent) askHost(ctx context.Context, dial func(context.Context) (net.Conn, error), pace askPace,
	wait func(context.Context, time.Duration) bool) {
	platform := a.platform.Load()
	if platform == nil {
		// Evidence that names no Intel platform is judged by none of Intel's
		// documents, and the guest has nothing to ask for.
		return
	}
	// The one thing the guest says on this channel: which platform it is.
	hello, err := disclosure.Encode(disclosure.MessagePlatform, platform)
	if err != nil {
		a.log.Warn("this guest's platform is not one it names to its host", "error", err)
		return
	}
	retry, answered, failing := pace.first, false, false
	for {
		next := pace.every
		size, err := a.ask(ctx, dial, hello, pace.answer)
		switch {
		case err == nil:
			if !answered || failing {
				a.log.Info("took Intel's documents for this platform from the host", "bytes", size)
			}
			retry, answered, failing = pace.first, true, false
		case ctx.Err() != nil:
			return
		default:
			if !failing {
				a.log.Warn("the host answered with none of Intel's documents, and this guest's verifiers ask Intel", "error", err)
			}
			next, failing = retry, true
			retry = min(2*retry, pace.retry)
		}
		if !wait(ctx, next) {
			return
		}
	}
}

// ask is one connection: the guest's line, then the host's answer until the
// host is done.
func (a *Agent) ask(ctx context.Context, dial func(context.Context) (net.Conn, error), hello []byte, limit time.Duration) (int, error) {
	conn, err := dial(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := conn.SetDeadline(time.Now().Add(limit)); err != nil {
		return 0, err
	}
	if _, err := conn.Write(hello); err != nil {
		return 0, err
	}
	// More than a guest takes is not taken, in part or whole.
	blob, err := readutil.ReadAll(conn, session.MaxCollateralBytes)
	if err != nil {
		return 0, err
	}
	if len(blob) == 0 {
		return 0, errNoDocuments
	}
	a.KeepCollateral(blob)
	return len(blob), nil
}

// KeepCollateral keeps blob as the guest's answer to PathCollateral: what its
// host answered with, unread.
func (a *Agent) KeepCollateral(blob []byte) {
	a.collateral.Store(&blob)
	a.keptOnce.Do(func() {
		// Stage makes the channel; an agent made any other way has no waiter.
		if a.kept != nil {
			close(a.kept)
		}
	})
}

// AwaitCollateral returns once the guest holds an answer of its host's, or
// after limit without one.
func (a *Agent) AwaitCollateral(ctx context.Context, limit time.Duration) {
	select {
	case <-a.kept:
	case <-time.After(limit):
	case <-ctx.Done():
	}
}

// serveCollateral answers with what the host last answered the guest with,
// byte for byte: see session.CollateralResponse. Anyone may ask. Intel
// publishes these documents, and the guest vouches for none of them.
func (a *Agent) serveCollateral(w http.ResponseWriter, _ *http.Request) {
	blob := a.collateral.Load()
	if blob == nil {
		a.refuse(w, http.StatusNotFound, disclosure.NoCollateral)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(*blob)
}
