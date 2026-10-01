// Package podcvm is the pod-CVM contract: the signed launch document a worker
// CVM boots from, what the guest measures, the in-guest agent's wire API, and
// the client trust gate that verifies all of it before releasing anything.
// See docs/pod-cvm.md.
package podcvm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

const (
	// SchemaVersion names the strict launch document schema.
	SchemaVersion = "c8s-pod-launch/v1"

	// MaxDocumentSize bounds launch.yaml. The document is measured, so every
	// byte is also a byte a verifier must fetch and hash.
	MaxDocumentSize = 256 * 1024

	maxSignatureSize   = 4096
	maxAccessKeys      = 16
	maxCredentials     = 32
	maxArgs            = 256
	maxArgBytes        = 4096
	maxEnvVars         = 256
	maxEnvBytes        = 32 * 1024
	maxPublicKeyBytes  = 8192
	defaultCredentialN = 64 * 1024

	// MaxCredentialBytes caps one released credential.
	MaxCredentialBytes = 64 * 1024
)

// Document is the signed launch.yaml of one pod CVM. It carries no secrets, so
// a verifier can be handed the exact bytes the guest measured.
type Document struct {
	SchemaVersion string `yaml:"schemaVersion" json:"schema_version"`
	// ID is unique per launch, so two sandboxes never share a document digest.
	ID string `yaml:"id" json:"id"`
	// Tenant is the single security context this CVM belongs to.
	Tenant      string       `yaml:"tenant" json:"tenant"`
	Sandbox     string       `yaml:"sandbox" json:"sandbox"`
	Image       Image        `yaml:"image" json:"image"`
	Workload    *Workload    `yaml:"workload,omitempty" json:"workload,omitempty"`
	Access      Access       `yaml:"access" json:"access"`
	Credentials []Credential `yaml:"credentials,omitempty" json:"credentials,omitempty"`
}

// Image pins the guest build this document was signed for. Same wire shape as
// the node launch document: RTMR[0] floats with VM shape and RTMR[3] carries
// the launch binding, so neither is pinned here.
type Image struct {
	Platform    string         `yaml:"platform" json:"platform"`
	Measurement string         `yaml:"measurement" json:"measurement"`
	RTMRs       map[int]string `yaml:"rtmrs,omitempty" json:"rtmrs,omitempty"`
}

// Workload is the one OCI image the guest pulls and runs. Command, args and
// env are exact: the host chooses none of them.
type Workload struct {
	// Image must be digest-pinned: name@sha256:<64 hex>.
	Image      string            `yaml:"image" json:"image"`
	Command    []string          `yaml:"command,omitempty" json:"command,omitempty"`
	Args       []string          `yaml:"args,omitempty" json:"args,omitempty"`
	Env        map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
	WorkingDir string            `yaml:"workingDir,omitempty" json:"working_dir,omitempty"`
}

// Access lists who may drive the agent. Nothing is implicit: the launch key
// signs the document and holds only the rights the document grants it.
type Access struct {
	// Exec keys may run commands and request fresh attestation.
	Exec []string `yaml:"exec,omitempty" json:"exec,omitempty"`
	// Credentials keys may release credentials and request fresh attestation.
	Credentials []string `yaml:"credentials,omitempty" json:"credentials,omitempty"`
}

// Credential declares one secret the workload may be handed after attestation.
type Credential struct {
	Name     string `yaml:"name" json:"name"`
	MaxBytes int    `yaml:"maxBytes,omitempty" json:"max_bytes,omitempty"`
}

// Limit is the effective size cap for this credential.
func (c Credential) Limit() int {
	if c.MaxBytes == 0 {
		return defaultCredentialN
	}
	return c.MaxBytes
}

var (
	idRE         = regexp.MustCompile(`^[0-9a-f]{32}$`)
	credentialRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,61}[a-z0-9])?$`)
	envNameRE    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// Parse strictly validates launch.yaml bytes. It authenticates nothing: guests
// use VerifySigned, verifiers check the signature against a pinned key.
func Parse(data []byte) (*Document, error) {
	if len(data) == 0 || len(data) > MaxDocumentSize {
		return nil, fmt.Errorf("launch document must contain 1..%d bytes", MaxDocumentSize)
	}
	var tree yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&tree); err != nil {
		return nil, fmt.Errorf("parse launch YAML: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("launch document must contain exactly one YAML document")
	}
	if err := checkYAML(&tree, 0); err != nil {
		return nil, err
	}
	dec = yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode launch document: %w", err)
	}
	if err := doc.Validate(); err != nil {
		return nil, err
	}
	return &doc, nil
}

// checkYAML rejects the YAML features that let two readers disagree about one
// document: anchors, aliases, merge keys, duplicate and non-canonical keys.
func checkYAML(n *yaml.Node, depth int) error {
	if depth > 16 {
		return fmt.Errorf("launch YAML nesting exceeds 16 levels")
	}
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return fmt.Errorf("launch YAML anchors and aliases are forbidden")
	}
	if n.Kind == yaml.MappingNode {
		seen := make(map[string]bool, len(n.Content)/2)
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Value == "<<" {
				return fmt.Errorf("invalid launch YAML mapping key")
			}
			// Integer keys occur only in the RTMR map; 01 and 1 must not collapse.
			if k.Tag != "!!str" && (k.Tag != "!!int" || (k.Value != "1" && k.Value != "2")) {
				return fmt.Errorf("noncanonical launch YAML mapping key %q", k.Value)
			}
			if seen[k.Value] {
				return fmt.Errorf("duplicate launch YAML key %q", k.Value)
			}
			seen[k.Value] = true
		}
	}
	for _, child := range n.Content {
		if err := checkYAML(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks every field. A document that passes is safe to enforce.
func (d *Document) Validate() error {
	if d.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schemaVersion must be %s", SchemaVersion)
	}
	if !idRE.MatchString(d.ID) {
		return fmt.Errorf("id must be 32 lowercase hex characters")
	}
	if errs := validation.IsDNS1123Subdomain(d.Tenant); len(errs) > 0 {
		return fmt.Errorf("tenant must be an RFC1123 subdomain")
	}
	if errs := validation.IsDNS1123Label(d.Sandbox); len(errs) > 0 {
		return fmt.Errorf("sandbox must be an RFC1123 label")
	}
	if err := d.Image.validate(); err != nil {
		return err
	}
	if d.Workload != nil {
		if err := d.Workload.validate(); err != nil {
			return fmt.Errorf("workload: %w", err)
		}
	}
	if err := validateKeys("access.exec", d.Access.Exec); err != nil {
		return err
	}
	if err := validateKeys("access.credentials", d.Access.Credentials); err != nil {
		return err
	}
	if len(d.Credentials) > maxCredentials {
		return fmt.Errorf("at most %d credentials may be declared", maxCredentials)
	}
	if len(d.Credentials) > 0 && len(d.Access.Credentials) == 0 {
		return fmt.Errorf("credentials are declared but access.credentials names no key that could release them")
	}
	seen := make(map[string]bool, len(d.Credentials))
	for _, c := range d.Credentials {
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

func (i Image) validate() error {
	if !registerHex(i.Measurement) {
		return fmt.Errorf("image.measurement must be 96 lowercase hex characters")
	}
	switch i.Platform {
	case "tdx":
		if len(i.RTMRs) != 2 || !registerHex(i.RTMRs[1]) || !registerHex(i.RTMRs[2]) {
			return fmt.Errorf("TDX image must pin exactly RTMR[1] and RTMR[2]")
		}
	case "snp":
		if len(i.RTMRs) != 0 {
			return fmt.Errorf("SNP image cannot carry RTMR pins")
		}
	default:
		return fmt.Errorf("image.platform must be tdx or snp")
	}
	return nil
}

// Family is the TEE family the image pins describe.
func (i Image) Family() teetypes.Family {
	if i.Platform == "tdx" {
		return teetypes.FamilyTDX
	}
	return teetypes.FamilySNP
}

func (w *Workload) validate() error {
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

// Digest returns the workload image's canonical "sha256:<hex>" digest.
func (w *Workload) Digest() (string, error) {
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

func parsePublicKey(raw string) (*ecdsa.PublicKey, error) {
	if len(raw) > maxPublicKeyBytes {
		return nil, fmt.Errorf("public key is too large")
	}
	return runtimemeasure.ParsePublicKeyPEM([]byte(raw))
}

// ExecKeys returns the parsed keys allowed to run commands.
func (d *Document) ExecKeys() []*ecdsa.PublicKey { return mustKeys(d.Access.Exec) }

// CredentialKeys returns the parsed keys allowed to release credentials.
func (d *Document) CredentialKeys() []*ecdsa.PublicKey { return mustKeys(d.Access.Credentials) }

// AttestKeys returns every key allowed to request fresh attestation.
func (d *Document) AttestKeys() []*ecdsa.PublicKey {
	out := d.ExecKeys()
	for _, key := range d.CredentialKeys() {
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
func (d *Document) Credential(name string) (Credential, bool) {
	for _, c := range d.Credentials {
		if c.Name == name {
			return c, true
		}
	}
	return Credential{}, false
}

// VerifySigned authenticates data under the launch public key (exact PEM
// bytes) before parsing it, so unauthenticated bytes never reach the parser.
func VerifySigned(launchPubPEM, data []byte, signature string) (*Document, error) {
	if len(data) == 0 || len(data) > MaxDocumentSize {
		return nil, fmt.Errorf("launch document must contain 1..%d bytes", MaxDocumentSize)
	}
	if len(signature) > maxSignatureSize {
		return nil, fmt.Errorf("launch signature is too large")
	}
	key, err := parsePublicKey(string(launchPubPEM))
	if err != nil {
		return nil, fmt.Errorf("launch public key: %w", err)
	}
	if err := operatorauth.VerifyDetached([]*ecdsa.PublicKey{key}, data, signature); err != nil {
		return nil, fmt.Errorf("launch document signature: %w", err)
	}
	return Parse(data)
}

// LaunchDigest is the canonical digest of the exact launch.yaml bytes, in the
// form runtimemeasure events hash.
func LaunchDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func registerHex(s string) bool {
	if len(s) != sha512.Size384*2 || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
