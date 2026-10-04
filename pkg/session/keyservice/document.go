// Package keyservice is the contract of the session key service
// (docs/session-key-service.md): its launch document, what a guest and an
// owner ask of it, and how a release is sealed. The client in this package is
// what a guest's agent and an owner's tool reach it with.
//
// A key service is an attested guest. Whoever talks to one holds it to a pin
// (session.KeyService) before sending it anything: its image, and the key
// that signed the launch document it measured, which is its policy.
package keyservice

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

const (
	// LaunchSchemaVersion is the one version of a key service's launch
	// document.
	LaunchSchemaVersion = "c8s-key-service-launch/v1"
	// MaxPools bounds the pools one key service serves.
	MaxPools = 64

	maxSignatureSize = 4096
	maxPublicKeySize = 8192
)

// Document is the signed launch document of a key service: its policy. The
// key service measures it at boot, so whoever verifies the key service knows
// which guests it releases to. It carries no secret.
type Document struct {
	SchemaVersion string `yaml:"schemaVersion"`
	// Image is the key service's own image. A document signed for one build
	// is not honoured by another.
	Image session.Image `yaml:"image"`
	// Machine lists the virtual machines a replica may be, under the rule of
	// a pool's launch document: a replica on another machine ends before it
	// serves, and one whose document lists none serves its state and
	// releases nothing.
	Machine *session.Machine `yaml:"machine,omitempty"`
	// Pools are the session guests the key service serves. A guest of no
	// listed pool is told nothing and given nothing.
	Pools []Pool `yaml:"pools"`
}

// Pool is one kind of session guest: its measured image, and the public key,
// PEM, its launch documents are signed with.
type Pool struct {
	Image     session.Image `yaml:"image"`
	LaunchKey string        `yaml:"launchKey"`
	// AcceptTCBStatus names Intel TCB statuses, besides UpToDate, that the
	// key service accepts of this pool's guests: see
	// session.Policy.AcceptTCBStatus.
	AcceptTCBStatus []string `yaml:"acceptTCBStatus,omitempty"`
}

// Parse strictly validates a key service's launch document. It authenticates
// nothing: see VerifySigned.
func Parse(data []byte) (*Document, error) {
	var doc Document
	if err := session.ParseCanonicalYAML(data, &doc); err != nil {
		return nil, err
	}
	if err := doc.Validate(); err != nil {
		return nil, err
	}
	return &doc, nil
}

// Validate checks every field.
func (d *Document) Validate() error {
	if d.SchemaVersion != LaunchSchemaVersion {
		return fmt.Errorf("schemaVersion must be %s", LaunchSchemaVersion)
	}
	if _, err := d.Image.Identity(); err != nil {
		return err
	}
	if err := d.Machine.Validate(d.Image); err != nil {
		return err
	}
	if len(d.Pools) == 0 || len(d.Pools) > MaxPools {
		return fmt.Errorf("pools must list 1 to %d pools", MaxPools)
	}
	for i, pool := range d.Pools {
		if _, err := pool.Image.Identity(); err != nil {
			return fmt.Errorf("pools[%d]: %w", i, err)
		}
		if pool.Image.Platform != d.Image.Platform {
			return fmt.Errorf("pools[%d]: its image is for another platform than the key service's", i)
		}
		if len(pool.LaunchKey) > maxPublicKeySize {
			return fmt.Errorf("pools[%d]: launchKey is too large", i)
		}
		if _, err := runtimemeasure.ParsePublicKeyPEM([]byte(pool.LaunchKey)); err != nil {
			return fmt.Errorf("pools[%d]: launchKey: %w", i, err)
		}
		if err := session.ValidateTCBStatuses(pool.AcceptTCBStatus); err != nil {
			return fmt.Errorf("pools[%d]: acceptTCBStatus: %w", i, err)
		}
	}
	return nil
}

// VerifySigned authenticates data under the launch public key (exact PEM
// bytes) before parsing it.
func VerifySigned(launchPubPEM, data []byte, signature string) (*Document, error) {
	if len(signature) > maxSignatureSize {
		return nil, errors.New("launch signature is too large")
	}
	key, err := runtimemeasure.ParsePublicKeyPEM(launchPubPEM)
	if err != nil {
		return nil, fmt.Errorf("launch public key: %w", err)
	}
	if err := operatorauth.VerifyDetached([]*ecdsa.PublicKey{key}, data, signature); err != nil {
		return nil, fmt.Errorf("launch document signature: %w", err)
	}
	return Parse(data)
}

// PoolOptions names one pool a new key service serves: the manifest of its
// guest image, and the pool's public launch key.
type PoolOptions struct {
	ManifestPath  string
	LaunchKeyPath string
	// AcceptTCBStatus is what the key service accepts of this pool's guests
	// besides UpToDate: see Pool.
	AcceptTCBStatus []string
}

// BundleOptions describes a new key service's launch bundle.
type BundleOptions struct {
	// Dir is the bundle directory to create.
	Dir string
	// ManifestPath is the manifest.json of the key service's own image.
	ManifestPath string
	// KeyPath is an existing launch private key. Empty generates one.
	KeyPath string
	// Machines lists the RTMR[0] values a replica may hold, in any order.
	// Empty writes a document that lists none: a replica booted from it
	// serves only what says which machine it is.
	Machines []string
	Pools    []PoolOptions
}

// NewBundle writes and signs a key service's launch document, in the layout
// of a session pool's bundle: the launcher that boots one boots the other.
// Dir must not exist, and a failed run removes it.
func NewBundle(opts BundleOptions) (err error) {
	if opts.Dir == "" || opts.ManifestPath == "" {
		return errors.New("--out and --image-manifest are required")
	}
	if len(opts.Pools) == 0 {
		return errors.New("a key service serves at least one pool")
	}
	doc := Document{SchemaVersion: LaunchSchemaVersion}
	if doc.Image, err = session.ImageFromManifest(opts.ManifestPath, 0); err != nil {
		return err
	}
	if len(opts.Machines) > 0 {
		doc.Machine = &session.Machine{RTMR0: slices.Sorted(slices.Values(opts.Machines))}
	}
	for _, pool := range opts.Pools {
		image, err := session.ImageFromManifest(pool.ManifestPath, 0)
		if err != nil {
			return fmt.Errorf("pool: %w", err)
		}
		launchKey, err := session.ReadBounded(pool.LaunchKeyPath, maxPublicKeySize)
		if err != nil {
			return fmt.Errorf("pool: launch key: %w", err)
		}
		doc.Pools = append(doc.Pools, Pool{Image: image, LaunchKey: string(launchKey), AcceptTCBStatus: pool.AcceptTCBStatus})
	}
	data, err := yaml.Marshal(&doc)
	if err != nil {
		return fmt.Errorf("render launch document: %w", err)
	}
	// Prove the rendering parses under the rules the key service applies.
	if _, err := Parse(data); err != nil {
		return fmt.Errorf("rendered launch document: %w", err)
	}
	if err := os.Mkdir(opts.Dir, 0o700); err != nil {
		return fmt.Errorf("create bundle directory: %w", err)
	}
	defer func() {
		if err != nil {
			os.RemoveAll(opts.Dir)
		}
	}()
	var key *ecdsa.PrivateKey
	if opts.KeyPath != "" {
		if key, err = certutil.LoadECPrivateKeyFile(opts.KeyPath); err != nil {
			return fmt.Errorf("launch key: %w", err)
		}
	} else {
		if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return fmt.Errorf("generate launch key: %w", err)
		}
		keyPEM, err := certutil.MarshalECKeyPEM(key)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(opts.Dir, session.BundleKeyFile), keyPEM, 0o600); err != nil {
			return err
		}
	}
	pub, err := session.PublicKeyPEM(&key.PublicKey)
	if err != nil {
		return err
	}
	signature, err := operatorauth.SignDetached(key, data)
	if err != nil {
		return err
	}
	opkey := filepath.Join(opts.Dir, session.OpkeyDir)
	if err := os.Mkdir(opkey, 0o700); err != nil {
		return err
	}
	for name, content := range map[string][]byte{
		session.PubkeyFile:    pub,
		session.DocumentFile:  data,
		session.SignatureFile: []byte(signature + "\n"),
	} {
		if err := os.WriteFile(filepath.Join(opkey, name), content, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// Pin is what a guest's launch document and an owner's bind pin of the key
// service that booted from the bundle in dir, reached at url.
func Pin(dir, url string) (*session.KeyService, error) {
	opkey := filepath.Join(dir, session.OpkeyDir)
	pub, err := session.ReadBounded(filepath.Join(opkey, session.PubkeyFile), maxPublicKeySize)
	if err != nil {
		return nil, err
	}
	data, err := session.ReadBounded(filepath.Join(opkey, session.DocumentFile), session.MaxDocumentSize)
	if err != nil {
		return nil, err
	}
	signature, err := session.ReadBounded(filepath.Join(opkey, session.SignatureFile), maxSignatureSize)
	if err != nil {
		return nil, err
	}
	doc, err := VerifySigned(pub, data, string(signature))
	if err != nil {
		return nil, err
	}
	return &session.KeyService{URL: url, Image: doc.Image, LaunchKey: string(pub)}, nil
}
