package podcvm

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// The agent serves these over RA-TLS on AgentPort. Every route except
// PathHealth requires an operatorauth token signed by a key the launch
// document authorizes for that route.
const (
	AgentPort = 8443

	PathHealth      = "/healthz"
	PathAttest      = "/v1/attest"
	PathExec        = "/v1/exec"
	PathCredentials = "/v1/credentials/"
)

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
}

// ExecRequest runs one command in the workload context. ID makes the call
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
