package session

import (
	"crypto/ecdsa"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

var (
	credentialRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,61}[a-z0-9])?$`)
	envNameRE    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// Sandbox is the one OCI image the guest runs for its session: the agent or
// harness and its tools. Command, args and env are exact: the host chooses
// none of them.
type Sandbox struct {
	// Image must be digest-pinned: name@sha256:<64 hex>.
	Image      string            `json:"image"`
	Command    []string          `json:"command,omitempty"`
	Args       []string          `json:"args,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	WorkingDir string            `json:"workingDir,omitempty"`
}

// Access lists who may drive a bound guest. Nothing is implicit: the authority
// that signs a bind holds only the rights the bind grants it, and the pool's
// launch key holds none.
type Access struct {
	// Exec keys may run commands and request fresh attestation.
	Exec []string `json:"exec,omitempty"`
	// Credentials keys may release credentials and request fresh attestation.
	Credentials []string `json:"credentials,omitempty"`
	// Forward keys may open streams to the ports the forward area lists and
	// request fresh attestation. A key that may run commands is not thereby
	// one of them.
	Forward []string `json:"forward,omitempty"`
}

// Forward opens TCP ports of the sandbox to streams from outside the guest.
// The sandbox's network namespace holds a loopback interface and nothing
// else, so no connection reaches it from anywhere. A stream is opened by the
// agent, for a key Access.Forward names, from inside that namespace to one of
// these ports on its loopback, and carried in the caller's attested TLS
// session. The caller names a port and never an address.
type Forward struct {
	// Ports lists the ports in ascending order.
	Ports []int `json:"ports"`
}

// SandboxProxyPort is where a sandbox finds its egress proxy, on the
// loopback of its own network namespace. The agent listens there, so no
// forward area opens it: a stream to it would lend the sandbox's egress to
// whoever holds a forward key.
const SandboxProxyPort = 3128

// Credential declares one secret the sandbox may be handed after attestation.
type Credential struct {
	Name     string `json:"name"`
	MaxBytes int    `json:"maxBytes,omitempty"`
	// Source is where the secret comes from. Empty, a key the bind grants
	// hands it over. SourceKeyService, the guest takes it from the bind's key
	// service when it is bound, and no key may hand it over. SourceBinder,
	// the binder may seal it with the bind, or a key the bind grants hands
	// it over.
	Source string `json:"source,omitempty"`
}

// ValidCredentialName reports whether name can name a credential.
func ValidCredentialName(name string) bool { return credentialRE.MatchString(name) }

// Limit is the effective size cap for this credential.
func (c Credential) Limit() int {
	if c.MaxBytes == 0 {
		return defaultCredentialN
	}
	return c.MaxBytes
}

// validateEgress checks an egress policy, named field in its errors. The
// policy is the sandbox's: a guest that runs no sandbox image has nothing
// behind the proxy that enforces it, and a rule nothing enforces is refused.
func validateEgress(field string, egress *Egress, sandbox *Sandbox) error {
	if egress == nil {
		return nil
	}
	if sandbox == nil {
		return fmt.Errorf("%s needs a sandbox image: only a sandbox's connections leave through the proxy that enforces it", field)
	}
	if err := egress.validate(); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}

// validateForward checks a forward area together with the keys it is for.
// field prefixes the names in its errors. Like an egress policy the area is
// about the sandbox's network namespace, which a guest that runs no sandbox
// image does not have. An area that opens nothing, a key with nothing to open
// and a port nobody may open are each refused: they would be measured and
// mean nothing.
func validateForward(field string, forward *Forward, sandbox *Sandbox, keys []string) error {
	if forward == nil {
		if len(keys) > 0 {
			return fmt.Errorf("%saccess.forward names keys, but no %sforward area opens a port to them", field, field)
		}
		return nil
	}
	if sandbox == nil {
		return fmt.Errorf("%sforward needs a sandbox image: a stream is opened in the sandbox's network namespace", field)
	}
	if len(forward.Ports) == 0 || len(forward.Ports) > maxForwardPorts {
		return fmt.Errorf("%sforward.ports must list 1..%d ports; leave the area out to open none", field, maxForwardPorts)
	}
	last := 0
	for _, port := range forward.Ports {
		switch {
		case port < 1 || port > 65535:
			return fmt.Errorf("%sforward.ports: %d is not a TCP port", field, port)
		case port <= last:
			return fmt.Errorf("%sforward.ports must be in ascending order, each port once", field)
		case port == SandboxProxyPort:
			return fmt.Errorf("%sforward.ports: %d is the sandbox's egress proxy, which is opened to nobody outside the guest", field, port)
		}
		last = port
	}
	if len(keys) == 0 {
		return fmt.Errorf("%sforward opens ports but %saccess.forward names no key that could open a stream to them", field, field)
	}
	return nil
}

// Opens reports whether the area opens port. A nil area opens none.
func (f *Forward) Opens(port int) bool {
	return f != nil && slices.Contains(f.Ports, port)
}

// validateAccess checks the keys that may drive a guest and the credentials
// they may release. field prefixes the names in its errors.
func validateAccess(field string, access Access, credentials []Credential) error {
	if err := validateKeys(field+"access.exec", access.Exec); err != nil {
		return err
	}
	if err := validateKeys(field+"access.credentials", access.Credentials); err != nil {
		return err
	}
	if err := validateKeys(field+"access.forward", access.Forward); err != nil {
		return err
	}
	if len(credentials) > maxCredentials {
		return fmt.Errorf("at most %d credentials may be declared", maxCredentials)
	}
	handed := 0
	for _, c := range credentials {
		// Sealed with the bind or put over a connection, a key the bind
		// grants signs for it.
		if c.Source == "" || c.Source == SourceBinder {
			handed++
		}
	}
	if handed > 0 && len(access.Credentials) == 0 {
		return fmt.Errorf("credentials are declared but %saccess.credentials names no key that could release them", field)
	}
	seen := make(map[string]bool, len(credentials))
	for _, c := range credentials {
		if c.Source != "" && c.Source != SourceKeyService && c.Source != SourceBinder {
			return fmt.Errorf("credential %q source must be empty, %s or %s", c.Name, SourceKeyService, SourceBinder)
		}
		if !credentialRE.MatchString(c.Name) {
			return fmt.Errorf("credential name %q must match %s", c.Name, credentialRE)
		}
		if seen[c.Name] {
			return fmt.Errorf("duplicate credential %q", c.Name)
		}
		seen[c.Name] = true
		if c.MaxBytes < 0 || c.MaxBytes > MaxCredentialBytes {
			return fmt.Errorf("credential %q maxBytes must be 0 (default) or 1..%d", c.Name, MaxCredentialBytes)
		}
	}
	return nil
}

func (w *Sandbox) validate() error {
	if _, err := w.Digest(); err != nil {
		return err
	}
	for name, list := range map[string][]string{"command": w.Command, "args": w.Args} {
		if len(list) > maxArgs {
			return fmt.Errorf("%s has more than %d entries", name, maxArgs)
		}
		for _, arg := range list {
			if len(arg) > maxArgBytes || strings.ContainsRune(arg, 0) {
				return fmt.Errorf("%s entries must be at most %d bytes with no NUL", name, maxArgBytes)
			}
		}
	}
	if len(w.Command) > 0 && w.Command[0] == "" {
		return fmt.Errorf("command[0] must not be empty")
	}
	if len(w.Env) > maxEnvVars {
		return fmt.Errorf("env has more than %d entries", maxEnvVars)
	}
	total := 0
	for k, v := range w.Env {
		if !envNameRE.MatchString(k) {
			return fmt.Errorf("env name %q is not a valid identifier", k)
		}
		if strings.ContainsRune(v, 0) {
			return fmt.Errorf("env %s contains NUL", k)
		}
		total += len(k) + len(v)
	}
	if total > maxEnvBytes {
		return fmt.Errorf("env exceeds %d bytes", maxEnvBytes)
	}
	if w.WorkingDir != "" && (!path.IsAbs(w.WorkingDir) || path.Clean(w.WorkingDir) != w.WorkingDir) {
		return fmt.Errorf("workingDir must be an absolute, clean path")
	}
	return nil
}

// Digest returns the sandbox image's canonical "sha256:<hex>" digest.
func (w *Sandbox) Digest() (string, error) {
	i := strings.LastIndex(w.Image, "@")
	if i <= 0 {
		return "", fmt.Errorf("image %q must be digest-pinned as name@sha256:<64 hex>", w.Image)
	}
	return runtimemeasure.CanonicalDigest(w.Image)
}

func validateKeys(field string, keys []string) error {
	if len(keys) > maxAccessKeys {
		return fmt.Errorf("%s has more than %d keys", field, maxAccessKeys)
	}
	var seen []*ecdsa.PublicKey
	for _, raw := range keys {
		key, err := parsePublicKey(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
		for _, prev := range seen {
			if key.Equal(prev) {
				return fmt.Errorf("%s lists one key twice", field)
			}
		}
		seen = append(seen, key)
	}
	return nil
}

// ExecKeys returns the parsed keys allowed to run commands.
func (a Access) ExecKeys() []*ecdsa.PublicKey { return mustKeys(a.Exec) }

// CredentialKeys returns the parsed keys allowed to release credentials.
func (a Access) CredentialKeys() []*ecdsa.PublicKey { return mustKeys(a.Credentials) }

// ForwardKeys returns the parsed keys allowed to open streams to the
// sandbox's forwarded ports.
func (a Access) ForwardKeys() []*ecdsa.PublicKey { return mustKeys(a.Forward) }

// AttestKeys returns every key allowed to request fresh attestation.
func (a Access) AttestKeys() []*ecdsa.PublicKey {
	out := a.ExecKeys()
	for _, key := range slices.Concat(a.CredentialKeys(), a.ForwardKeys()) {
		dup := false
		for _, have := range out {
			dup = dup || key.Equal(have)
		}
		if !dup {
			out = append(out, key)
		}
	}
	return out
}

// mustKeys parses keys Validate already accepted; an unparseable entry is
// dropped, which can only shrink the authorized set.
func mustKeys(raw []string) []*ecdsa.PublicKey {
	out := make([]*ecdsa.PublicKey, 0, len(raw))
	for _, r := range raw {
		if key, err := parsePublicKey(r); err == nil {
			out = append(out, key)
		}
	}
	return out
}

// Credential returns the declaration for name.
func (p *BindPolicy) Credential(name string) (Credential, bool) {
	return findCredential(p.Credentials, name)
}

func findCredential(declared []Credential, name string) (Credential, bool) {
	for _, c := range declared {
		if c.Name == name {
			return c, true
		}
	}
	return Credential{}, false
}
