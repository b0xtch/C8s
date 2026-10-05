package session

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/pkg/session/disclosure"
)

// The agent serves these over RA-TLS on AgentPort. PathAttest, PathExec,
// PathCredentials and PathForward require an operatorauth token signed by a
// key the guest's bind authorizes for that route. PathState answers anyone
// with what is public anyway: see StateResponse. PathBind is authorized by the
// bind's own signature. PathFence answers anyone too: see FenceResponse. So
// does PathCollateral: see CollateralResponse.
const (
	AgentPort = 8443

	PathHealth      = "/healthz"
	PathState       = "/v1/state"
	PathBind        = "/v1/bind"
	PathFence       = "/v1/fence"
	PathAttest      = "/v1/attest"
	PathExec        = "/v1/exec"
	PathCredentials = "/v1/credentials/"
	PathForward     = "/v1/forward"
	PathCollateral  = "/v1/collateral"
)

// MaxCollateralBytes bounds what a guest takes from its host as Intel's
// documents, and so what it answers PathCollateral with: Intel's four
// documents are a tenth of it.
const MaxCollateralBytes = 256 << 10

// CollateralResponse is what a host answers its guest's ask with and a guest
// answers GET PathCollateral with, byte for byte: Intel's documents for the
// guest's platform, as the host last fetched them (HostConfig.CollateralPort).
// The guest does not read it and vouches for none of it. Each document is
// signed by Intel, and a verifier holds it to that signature and to Intel's
// own date on it: see WithCollateralSource. A guest whose host answered with
// nothing answers 404.
type CollateralResponse struct {
	Documents []CollateralDocument `json:"documents"`
}

// ImageStoreSerial is the serial of the disk a guest reads its host's image
// store from: public images the host keeps for every guest it launches, so
// that a guest need not ask a registry for them. See imagestore.Store.
const ImageStoreSerial = "c8s-images"

// ForwardProtocol is what a request to PathForward upgrades its connection
// to. After the agent's 101 the connection carries the bytes of one stream to
// the sandbox's port, unframed, in both directions. Either end finishes its
// input with a TLS close_notify and may go on reading: a TCP half-close would
// not survive every proxy on the way.
const ForwardProtocol = "c8s-forward/1"

// ForwardRequest asks for a stream to one TCP port of the sandbox. The port
// is on the loopback of the sandbox's own network namespace, and the guest's
// documents must open it: see Forward.
type ForwardRequest struct {
	Port int `json:"port"`
}

// MaxForwardRequestBytes bounds the body of a request to PathForward.
const MaxForwardRequestBytes = 256

// Wire limits, shared so client and agent refuse the same things.
const (
	MaxRequestBytes  = 2 << 20
	MaxExecArgs      = 256
	MaxExecArgBytes  = 128 * 1024
	MaxExecStdin     = 1 << 20
	MaxExecOutput    = 1 << 20
	MaxExecTimeout   = 600
	DefaultExecLimit = 60
)

// AttestRequest asks for evidence bound to this nonce and the instance key.
type AttestRequest struct {
	Nonce []byte `json:"nonce"`
}

// AttestResponse carries fresh evidence plus everything a verifier needs to
// recompute what the guest measured. Nothing here is trusted until the
// evidence verifies and binds it: see Client.Attest.
type AttestResponse struct {
	Evidence teetypes.AttestationEvidence `json:"evidence"`
	// Launch is the exact launch.yaml the guest verified and measured.
	Launch    []byte `json:"launch"`
	Signature string `json:"signature"`
	// Events are the canonical digests extended after the launch-key seed.
	Events []string `json:"events"`
	Phase  Phase    `json:"phase"`
	// Bind and BindSignature are the bind of a bound guest, exactly as it
	// measured it.
	Bind          []byte `json:"bind,omitempty"`
	BindSignature string `json:"bind_signature,omitempty"`
}

// StateResponse is what a guest says about itself to anyone who asks: its
// phase, its key and the documents it measured. All of it is public. The
// launch document names nobody, and the bind reached the guest through its
// host. None of it is trusted until evidence binds it.
type StateResponse struct {
	Phase Phase `json:"phase"`
	// InstanceKey is the PKIX DER of the key the guest serves under.
	InstanceKey []byte `json:"instance_key"`
	// Prepared is set by an unbound guest once it is done with everything it
	// does ahead of a bind: the images its launch document lists are unpacked
	// or given up on, its memory reserve is accepted, and its session with
	// the key service its launch document pins is open. A host offers the
	// guest to a session only when this says so. Until then a bind that names
	// a listed image waits for it, and a guest that still waits for its key
	// service takes no bind at all.
	Prepared bool `json:"prepared,omitempty"`
	// Launch and Signature are the launch document the guest measured.
	Launch    []byte `json:"launch"`
	Signature string `json:"signature"`
	// Events are the canonical digests extended after the launch-key seed.
	Events []string `json:"events"`
	// Bind and BindSignature are the bind of a bound guest, exactly as it
	// measured it.
	Bind          []byte `json:"bind,omitempty"`
	BindSignature string `json:"bind_signature,omitempty"`
	// BindQuote says where the quote over the bind's nonce stands, once the
	// guest runs its sandbox: BindQuoteTrying, BindQuoteTaken or
	// BindQuoteGivenUp. A binder that reads the last asks the guest for an
	// attestation itself.
	BindQuote string `json:"bind_quote,omitempty"`
	// Attestation is the evidence a bound guest took over its bind's nonce,
	// once it has it: what its answer to the bind held, or what followed the
	// receipt in that answer. It is served as it was taken, and asking for
	// the state has no guest take a quote.
	Attestation *AttestResponse `json:"attestation,omitempty"`
}

// Where the quote a bound guest takes over its bind's nonce stands.
const (
	BindQuoteTrying  = string(disclosure.QuoteTrying)
	BindQuoteTaken   = string(disclosure.QuoteTaken)
	BindQuoteGivenUp = string(disclosure.QuoteGivenUp)
)

// BindRequest hands a guest its one bind.
type BindRequest struct {
	Bind      []byte `json:"bind"`
	Signature string `json:"signature"`
}

// BindResponse reports the guest's phase once the bind is measured and its
// sandbox admitted.
type BindResponse struct {
	Phase Phase `json:"phase"`
	// Replayed: the guest was already bound by this same bind.
	Replayed bool `json:"replayed,omitempty"`
	// Admission is how the guest spent the time between measuring the bind
	// and running its sandbox, step by step in order.
	Admission []AdmissionStep `json:"admission,omitempty"`
	// Receipt is the guest's own word on the bind, signed by its instance key
	// over the bind's nonce: see BindReceipt. The sender goes on with it,
	// and holds the quote that follows to it.
	Receipt *SignedReceipt `json:"receipt,omitempty"`
	// Attestation is what an attestation request for the bind's nonce would
	// have been answered, over the register as the bind left it. The guest
	// begins to take it as soon as that register is final, and the answer
	// carries it only if it is there by the time the sandbox runs: the answer
	// does not wait for it. The guest then serves it with its state
	// (StateResponse). It is missing for good when the guest's ration of
	// quotes had none to give: then the sender asks. Nothing in it is trusted
	// until its evidence verifies and binds it.
	Attestation *AttestResponse `json:"attestation,omitempty"`
}

// AdmissionStep is one step of admitting a sandbox and how long the guest
// took over it, by its own clock. It is for whoever tunes a platform, and
// tells the bind's sender nothing the host could not time from outside:
// what the guest fetches, writes and starts all passes through the host.
type AdmissionStep struct {
	Name   string `json:"name"`
	Micros int64  `json:"us"`
}

// FenceResponse answers POST PathFence, which a guest's host sends when it
// claims the guest for a session.
//
// A guest that is bound says so, and nothing changes. A guest still unbound
// closes every other connection it accepted before the request and takes no
// bind from one, then answers ready. Whoever held a connection to the guest
// before, and whatever they had sent on it, can bind it no more: a bind after
// this answer arrived on the connection that carried this request, or on one
// opened after it.
//
// An answer of ready also says the guest has read no bind. One that is
// reading a bind when the request comes answers 409 instead and changes
// nothing: it holds a caller's bytes, so its host treats it as bound and
// does not claim it.
//
// The route needs no key. It ends connections to a guest that belongs to
// nobody, which its host can do anyway.
type FenceResponse struct {
	Phase Phase `json:"phase"`
	// Closed is how many connections the fence ended.
	Closed int `json:"closed"`
}

// ExecRequest runs one command in the sandbox context. ID makes the call
// idempotent: a repeated ID returns the first result and runs nothing.
type ExecRequest struct {
	ID             string            `json:"id"`
	Argv           []string          `json:"argv"`
	Env            map[string]string `json:"env,omitempty"`
	Cwd            string            `json:"cwd,omitempty"`
	Stdin          []byte            `json:"stdin,omitempty"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty"`
}

// ExecResponse is the complete, bounded result of one command.
type ExecResponse struct {
	ExitCode        int    `json:"exit_code"`
	Stdout          []byte `json:"stdout"`
	Stderr          []byte `json:"stderr"`
	StdoutTruncated bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated bool   `json:"stderr_truncated,omitempty"`
	TimedOut        bool   `json:"timed_out,omitempty"`
	DurationMillis  int64  `json:"duration_ms"`
}

// CredentialRequest releases one credential value into the guest.
type CredentialRequest struct {
	Value []byte `json:"value"`
}

var execIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Validate bounds an exec request before it is signed or run.
func (r *ExecRequest) Validate() error {
	if !execIDRE.MatchString(r.ID) {
		return fmt.Errorf("exec id must be 32 lowercase hex characters")
	}
	if len(r.Argv) == 0 || r.Argv[0] == "" {
		return fmt.Errorf("argv must name a command")
	}
	if len(r.Argv) > MaxExecArgs {
		return fmt.Errorf("argv has more than %d entries", MaxExecArgs)
	}
	total := 0
	for _, arg := range r.Argv {
		total += len(arg)
		for i := 0; i < len(arg); i++ {
			if arg[i] == 0 {
				return fmt.Errorf("argv contains NUL")
			}
		}
	}
	if total > MaxExecArgBytes {
		return fmt.Errorf("argv exceeds %d bytes", MaxExecArgBytes)
	}
	if len(r.Env) > maxEnvVars {
		return fmt.Errorf("env has more than %d entries", maxEnvVars)
	}
	envBytes := 0
	for k, v := range r.Env {
		if !envNameRE.MatchString(k) {
			return fmt.Errorf("env name %q is not a valid identifier", k)
		}
		for i := 0; i < len(v); i++ {
			if v[i] == 0 {
				return fmt.Errorf("env %s contains NUL", k)
			}
		}
		envBytes += len(k) + len(v)
	}
	if envBytes > maxEnvBytes {
		return fmt.Errorf("env exceeds %d bytes", maxEnvBytes)
	}
	if r.Cwd != "" && (len(r.Cwd) > maxArgBytes || !path.IsAbs(r.Cwd) || path.Clean(r.Cwd) != r.Cwd || strings.ContainsRune(r.Cwd, 0)) {
		return fmt.Errorf("cwd must be an absolute, clean path of at most %d bytes", maxArgBytes)
	}
	if len(r.Stdin) > MaxExecStdin {
		return fmt.Errorf("stdin exceeds %d bytes", MaxExecStdin)
	}
	if r.TimeoutSeconds < 0 || r.TimeoutSeconds > MaxExecTimeout {
		return fmt.Errorf("timeout_seconds must be 0..%d", MaxExecTimeout)
	}
	return nil
}
