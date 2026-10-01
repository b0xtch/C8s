package podcvm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// A bundle is one sandbox's launch input. The opkeydata directory is exactly
// what the host attaches to the guest; the private key sits beside it.
//
//	<dir>/launch.key              launch private key (only when generated here)
//	<dir>/opkeydata/pubkey        exact PEM the guest measures
//	<dir>/opkeydata/launch.yaml
//	<dir>/opkeydata/launch.yaml.sig
const (
	BundleKeyFile = "launch.key"
	OpkeyDir      = "opkeydata"
	PubkeyFile    = "pubkey"
	DocumentFile  = "launch.yaml"
	SignatureFile = DocumentFile + ".sig"
)

// BundleOptions describes a new sandbox's launch bundle.
type BundleOptions struct {
	Dir          string
	ManifestPath string
	// VCPUs selects the launch digest on SEV-SNP, where it covers vCPU count.
	VCPUs int
	// KeyPath signs with an existing launch key; empty generates one in Dir.
	KeyPath  string
	Tenant   string
	Sandbox  string
	Workload *Workload
	// ExecKeys and CredentialKeys are public key PEMs granted access in
	// addition to the launch key, which is granted both unless NoLaunchKeyAccess.
	ExecKeys          []string
	CredentialKeys    []string
	NoLaunchKeyAccess bool
	Credentials       []Credential
}

// NewBundle writes and signs one sandbox's launch document. Dir must not
// exist; a failed run removes it, so a half-written bundle is never attached.
func NewBundle(opts BundleOptions) (err error) {
	if opts.Dir == "" || opts.ManifestPath == "" || opts.Tenant == "" || opts.Sandbox == "" {
		return errors.New("--out, --image-manifest, --tenant and --sandbox are required")
	}
	image, err := ImageFromManifest(opts.ManifestPath, opts.VCPUs)
	if err != nil {
		return err
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
		if err := writeNew(filepath.Join(opts.Dir, BundleKeyFile), keyPEM, 0o600); err != nil {
			return err
		}
	}
	pub, err := PublicKeyPEM(&key.PublicKey)
	if err != nil {
		return err
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return fmt.Errorf("generate launch id: %w", err)
	}
	doc := Document{
		SchemaVersion: SchemaVersion,
		ID:            hex.EncodeToString(id[:]),
		Tenant:        opts.Tenant,
		Sandbox:       opts.Sandbox,
		Image:         image,
		Workload:      opts.Workload,
		Access:        Access{Exec: opts.ExecKeys, Credentials: opts.CredentialKeys},
		Credentials:   opts.Credentials,
	}
	if !opts.NoLaunchKeyAccess {
		doc.Access.Exec = append([]string{string(pub)}, doc.Access.Exec...)
		doc.Access.Credentials = append([]string{string(pub)}, doc.Access.Credentials...)
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("render launch document: %w", err)
	}
	// Prove the rendering parses under the rules the guest applies.
	if _, err := Parse(data); err != nil {
		return fmt.Errorf("rendered launch document: %w", err)
	}
	signature, err := operatorauth.SignDetached(key, data)
	if err != nil {
		return err
	}
	opkey := filepath.Join(opts.Dir, OpkeyDir)
	if err := os.Mkdir(opkey, 0o700); err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		data []byte
	}{
		{PubkeyFile, pub},
		{DocumentFile, data},
		{SignatureFile, []byte(signature + "\n")},
	} {
		if err := writeNew(filepath.Join(opkey, f.name), f.data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// Bundle is the public half of a launch bundle, as a verifier loads it.
type Bundle struct {
	LaunchKey []byte
	Launch    []byte
	Signature string
	Document  *Document
}

// LoadBundle reads <dir>/opkeydata and checks the document's signature.
func LoadBundle(dir string) (*Bundle, error) {
	opkey := filepath.Join(dir, OpkeyDir)
	pub, err := ReadBounded(filepath.Join(opkey, PubkeyFile), maxPublicKeyBytes)
	if err != nil {
		return nil, err
	}
	data, err := ReadBounded(filepath.Join(opkey, DocumentFile), MaxDocumentSize)
	if err != nil {
		return nil, err
	}
	signature, err := ReadBounded(filepath.Join(opkey, SignatureFile), maxSignatureSize)
	if err != nil {
		return nil, err
	}
	doc, err := VerifySigned(pub, data, string(signature))
	if err != nil {
		return nil, err
	}
	return &Bundle{LaunchKey: pub, Launch: data, Signature: string(signature), Document: doc}, nil
}

// ImageFromManifest turns a build's manifest.json into launch document image
// pins. An SNP manifest has one launch digest per vCPU count, which vcpus
// selects.
func ImageFromManifest(path string, vcpus int) (Image, error) {
	identity, err := runtimemeasure.LoadImageManifest(path)
	if err != nil {
		return Image{}, fmt.Errorf("--image-manifest: %w", err)
	}
	variants := identity.LaunchDigests()
	switch identity.Family() {
	case teetypes.FamilyTDX:
		if vcpus != 0 {
			return Image{}, errors.New("--vcpus applies to SNP manifests only: a TDX image has one measurement for every VM shape")
		}
		image := Image{Platform: "tdx", Measurement: hex.EncodeToString(variants[0].Digest[:]), RTMRs: map[int]string{}}
		for idx, value := range identity.RTMRs() {
			image.RTMRs[idx] = hex.EncodeToString(value[:])
		}
		return image, nil
	case teetypes.FamilySNP:
		if vcpus == 0 && len(variants) > 1 {
			return Image{}, fmt.Errorf("--vcpus is required: %s pins %d SNP launch digests, one per vCPU count", path, len(variants))
		}
		for _, v := range variants {
			if vcpus == 0 || v.Label == fmt.Sprintf("smp%d", vcpus) {
				return Image{Platform: "snp", Measurement: hex.EncodeToString(v.Digest[:])}, nil
			}
		}
		return Image{}, fmt.Errorf("--vcpus %d: %s pins no SNP launch digest for that vCPU count", vcpus, path)
	default:
		return Image{}, fmt.Errorf("--image-manifest: %s pins TEE family %q, want tdx or sev-snp", path, identity.Family())
	}
}

// PublicKeyPEM renders a launch public key in the one encoding every tool
// here writes, so the bytes a signer derives equal the bytes a guest measured.
func PublicKeyPEM(pub *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("encode public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ReadBounded reads a regular, non-empty file of at most limit bytes.
func ReadBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, fmt.Errorf("%s must be a regular file containing 1..%d bytes", path, limit)
	}
	data, err := readutil.ReadAll(f, limit)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	return f.Close()
}
