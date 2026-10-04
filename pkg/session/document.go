// Package session is the confidential session contract: the signed launch
// document a pool's TDs boot from, the bind that makes one of them a session's,
// what the guest measures, the guest agent's wire API, and the verifier that
// checks all of it before anything is released. See docs/sessions.md.
package session

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

const (
	// LaunchSchemaVersion names the strict launch document schema.
	LaunchSchemaVersion = "c8s-session-launch/v1"

	// MaxDocumentSize bounds launch.yaml. The document is measured, so every
	// byte is also a byte a verifier must fetch and hash.
	MaxDocumentSize = 256 * 1024

	maxSignatureSize   = 4096
	maxAccessKeys      = 16
	maxCredentials     = 32
	maxForwardPorts    = 16
	maxArgs            = 256
	maxArgBytes        = 4096
	maxEnvVars         = 256
	maxEnvBytes        = 32 * 1024
	maxPublicKeyBytes  = 8192
	defaultCredentialN = 64 * 1024

	// MaxCredentialBytes caps one released credential.
	MaxCredentialBytes = 64 * 1024
)

// Document is the signed launch.yaml of a pool: every TD of the pool boots
// from the same one. It names no tenant and grants nothing, so a TD that has
// measured it belongs to nobody until it takes a bind. It carries no secrets,
// and a verifier can be handed the exact bytes the guest measured.
type Document struct {
	SchemaVersion string `yaml:"schemaVersion" json:"schema_version"`
	// Pool and Class name the pool and the VM shape its TDs are launched in,
	// for whoever reads the evidence. Machine is what holds a host to a shape.
	Pool  string `yaml:"pool" json:"pool"`
	Class string `yaml:"class" json:"class"`
	Image Image  `yaml:"image" json:"image"`
	// AgeLimitSeconds bounds how long a TD waits for its bind, counted on its
	// own clock from the moment it measured this document. Past it the guest
	// takes no bind and ends. 0 sets no bound.
	AgeLimitSeconds int `yaml:"ageLimitSeconds,omitempty" json:"age_limit_seconds,omitempty"`
	// Prestage lists public images a TD unpacks before any tenant arrives,
	// from its host's image store and from nowhere else, so that a bind which
	// names one of them starts it at once. Nothing of an image runs before a
	// bind names it, and what a bind does not name is removed.
	Prestage []string `yaml:"prestage,omitempty" json:"prestage,omitempty"`
	// Machine, when set, lists the virtual machines this guest may be. Unset,
	// its host may build it any. See Machine.
	Machine *Machine `yaml:"machine,omitempty" json:"machine,omitempty"`
}

// Machine pins the virtual machine a host built around the guest. A TD's
// firmware measures what its host hands it, the memory map and the ACPI
// tables among it, into RTMR[0]. An image's reference values leave that
// register out: it differs with the vCPUs, the memory, where the memory sits
// and the devices. A document that lists values for it is good only for a
// guest whose register holds one of them, so a host can build this guest no
// machine the document's signer did not record.
type Machine struct {
	// RTMR0 lists the values in ascending order, each once.
	RTMR0 []string `yaml:"rtmr0" json:"rtmr0"`
}

// MaxMachines bounds the list: a signer records one value for each shape and
// each VMM build it launches.
const MaxMachines = 8

// Allows reports whether a guest whose RTMR[0] holds rtmr0 may run under the
// document. A nil area allows every machine.
func (m *Machine) Allows(rtmr0 []byte) bool {
	return m == nil || slices.Contains(m.RTMR0, hex.EncodeToString(rtmr0))
}

func (m *Machine) validate(platform string) error {
	if m == nil {
		return nil
	}
	if platform != "tdx" {
		return fmt.Errorf("machine pins RTMR[0], which only a TDX guest has")
	}
	if len(m.RTMR0) == 0 || len(m.RTMR0) > MaxMachines {
		return fmt.Errorf("machine.rtmr0 must list 1..%d values; leave the area out to pin no machine", MaxMachines)
	}
	last := ""
	for _, value := range m.RTMR0 {
		if !registerHex(value) {
			return fmt.Errorf("machine.rtmr0 values must be 96 lowercase hex characters")
		}
		if value <= last {
			return fmt.Errorf("machine.rtmr0 must be in ascending order, each value once")
		}
		last = value
	}
	return nil
}

// MaxPrestage bounds the images a guest unpacks ahead: each is written to
// every guest's scratch volume, whether or not a tenant ever names it.
const MaxPrestage = 4

// Bounds on Document.AgeLimitSeconds. The floor leaves a binder time to
// verify and bind; the ceiling keeps the field a bound.
const (
	MinAgeLimit = time.Minute
	MaxAgeLimit = 7 * 24 * time.Hour
)

// AgeLimit is how long a TD waits for its bind, or 0 for no bound.
func (d *Document) AgeLimit() time.Duration {
	return time.Duration(d.AgeLimitSeconds) * time.Second
}

// Image pins the guest build this document was signed for. Same wire shape as
// the node launch document: RTMR[0] floats with VM shape and RTMR[3] carries
// the launch binding, so neither is pinned here.
type Image struct {
	Platform    string         `yaml:"platform" json:"platform"`
	Measurement string         `yaml:"measurement" json:"measurement"`
	RTMRs       map[int]string `yaml:"rtmrs,omitempty" json:"rtmrs,omitempty"`
}

var decimalRE = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

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
	// One document, one spelling: the one this package writes. YAML has many
	// for the same content (flow and block style, quoting, the old booleans),
	// and a reader that is not this one may take some of them for another
	// content. None survives a rendering, so a document must be its own.
	canonical, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, fmt.Errorf("render launch document: %w", err)
	}
	if !bytes.Equal(canonical, data) {
		return nil, errors.New("launch document is not in canonical form: the form 'c8s session launch-config new' writes it in")
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
	// One spelling to a number. 0x50, 0o120, 080, +80, 8_0 and 80.0 are each a
	// number to this parser, and another number or none to the next.
	if n.Kind == yaml.ScalarNode && (n.Tag == "!!float" || (n.Tag == "!!int" && !decimalRE.MatchString(n.Value))) {
		return fmt.Errorf("launch YAML number %q must be written in plain decimal", n.Value)
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
	if d.SchemaVersion != LaunchSchemaVersion {
		return fmt.Errorf("schemaVersion must be %s", LaunchSchemaVersion)
	}
	if errs := validation.IsDNS1123Label(d.Pool); len(errs) > 0 {
		return fmt.Errorf("pool must be an RFC1123 label")
	}
	if errs := validation.IsDNS1123Label(d.Class); len(errs) > 0 {
		return fmt.Errorf("class must be an RFC1123 label")
	}
	if err := d.Image.validate(); err != nil {
		return err
	}
	if err := d.Machine.validate(d.Image.Platform); err != nil {
		return err
	}
	if limit := d.AgeLimit(); d.AgeLimitSeconds != 0 && (limit < MinAgeLimit || limit > MaxAgeLimit) {
		return fmt.Errorf("ageLimitSeconds must be 0 or between %d and %d", int(MinAgeLimit/time.Second), int(MaxAgeLimit/time.Second))
	}
	if len(d.Prestage) > MaxPrestage {
		return fmt.Errorf("prestage lists more than %d images", MaxPrestage)
	}
	seen := map[string]bool{}
	for _, image := range d.Prestage {
		digest, err := (&Sandbox{Image: image}).Digest()
		if err != nil {
			return fmt.Errorf("prestage: %w", err)
		}
		if seen[digest] {
			return fmt.Errorf("prestage lists %s twice", digest)
		}
		seen[digest] = true
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

func parsePublicKey(raw string) (*ecdsa.PublicKey, error) {
	if len(raw) > maxPublicKeyBytes {
		return nil, fmt.Errorf("public key is too large")
	}
	return runtimemeasure.ParsePublicKeyPEM([]byte(raw))
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
func DocumentDigest(data []byte) string {
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
