package session

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// A bundle is a pool's launch input. The opkeydata directory is exactly what
// the host attaches to each of the pool's guests; the private key sits beside
// it.
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

// BundleOptions describes a new pool's launch bundle.
type BundleOptions struct {
	Dir          string
	ManifestPath string
	// VCPUs selects the launch digest on SEV-SNP, where it covers vCPU count.
	VCPUs int
	// KeyPath signs with an existing launch key; empty generates one in Dir.
	KeyPath string
	Pool    string
	Class   string
	// AgeLimit bounds how long a TD waits for its bind. Whole seconds; 0 sets
	// no bound.
	AgeLimit time.Duration
	// Prestage lists the images a TD unpacks ahead of its bind.
	Prestage []string
	// Machines lists the RTMR[0] values the guest may hold, in any order: the
	// machines its host may build it. Empty pins none.
	Machines []string
}

// NewBundle writes and signs a pool's launch document. Dir must not exist; a
// failed run removes it, so a half-written bundle is never attached.
//
// The launch key creates unbound TDs and nothing else: the document grants it
// no access, so it cannot drive one before or after a bind.
func NewBundle(opts BundleOptions) (err error) {
	if opts.Dir == "" || opts.ManifestPath == "" {
		return errors.New("--out and --image-manifest are required")
	}
	if opts.Pool == "" || opts.Class == "" {
		return errors.New("--pool and --class are required")
	}
	if opts.AgeLimit%time.Second != 0 {
		return errors.New("an age limit is whole seconds")
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
	doc := Document{
		SchemaVersion:   LaunchSchemaVersion,
		Pool:            opts.Pool,
		Class:           opts.Class,
		Image:           image,
		AgeLimitSeconds: int(opts.AgeLimit / time.Second),
		Prestage:        opts.Prestage,
	}
	if len(opts.Machines) > 0 {
		doc.Machine = &Machine{RTMR0: slices.Sorted(slices.Values(opts.Machines))}
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

// A binding is the owner's record of one TD it bound: everything a verifier
// needs to tell that guest from any other, and the key to drive it.
//
//	<dir>/pubkey           the pool's launch key the guest was verified under
//	<dir>/launch.yaml      the launch document the guest measured
//	<dir>/launch.yaml.sig
//	<dir>/bind.json        the bind
//	<dir>/bind.json.sig    the authority's signature over it
//	<dir>/access.key       a key the bind grants access to (only when generated here)
const (
	BindFile          = "bind.json"
	BindSignatureFile = BindFile + ".sig"
	AccessKeyFile     = "access.key"
)

// Binding is the public half of a binding directory, as a verifier loads it.
type Binding struct {
	LaunchKey []byte
	Launch    []byte
	Bind      *SignedBind
}

// WriteBinding records a bind for the TD it was written for. Dir must not
// exist. accessKeyPEM, when given, is stored beside the documents.
func WriteBinding(dir string, launchKey []byte, td *ReadyTD, bind *SignedBind, accessKeyPEM []byte) (err error) {
	if err := os.Mkdir(dir, 0o700); err != nil {
		return fmt.Errorf("create binding directory: %w", err)
	}
	defer func() {
		if err != nil {
			os.RemoveAll(dir)
		}
	}()
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{PubkeyFile, launchKey, 0o644},
		{DocumentFile, td.Launch, 0o644},
		{SignatureFile, []byte(td.Signature + "\n"), 0o644},
		{BindFile, bind.Raw, 0o644},
		{BindSignatureFile, []byte(bind.Signature + "\n"), 0o644},
	}
	if accessKeyPEM != nil {
		files = append(files, struct {
			name string
			data []byte
			mode os.FileMode
		}{AccessKeyFile, accessKeyPEM, 0o600})
	}
	for _, f := range files {
		if err := writeNew(filepath.Join(dir, f.name), f.data, f.mode); err != nil {
			return err
		}
	}
	return nil
}

// ownBinding refuses a binding directory, or a file of the binding in it,
// that another user owns or could change, and a access key another user
// could read. A kept verdict beside them answers to LoadVerdict.
func ownBinding(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !ownedByUs(info) {
		return fmt.Errorf("binding %s: mode %s, or another user's: it must be this user's directory, open to nobody else", dir, info.Mode())
	}
	for name, mask := range map[string]os.FileMode{
		PubkeyFile: 0o022, DocumentFile: 0o022, SignatureFile: 0o022, BindFile: 0o022, BindSignatureFile: 0o022,
		AccessKeyFile: 0o077,
	} {
		info, err := os.Lstat(filepath.Join(dir, name))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&mask != 0 || !ownedByUs(info) {
			return fmt.Errorf("binding file %s: mode %s, or another user's", filepath.Join(dir, name), info.Mode())
		}
	}
	return nil
}

// LoadBinding reads a binding directory and checks both signatures: the launch
// document's under the stored launch key and the bind's under the authority it
// names. Whether that key and that authority are the right ones is for the
// policy the caller builds from them.
//
// A binding is trusted as its access key is: the directory must be this
// user's and open to nobody else, and every file in it this user's and
// writable by nobody else, the access key readable by nobody else either.
func LoadBinding(dir string) (*Binding, error) {
	if err := ownBinding(dir); err != nil {
		return nil, err
	}
	pub, err := ReadBounded(filepath.Join(dir, PubkeyFile), maxPublicKeyBytes)
	if err != nil {
		return nil, err
	}
	launch, err := ReadBounded(filepath.Join(dir, DocumentFile), MaxDocumentSize)
	if err != nil {
		return nil, err
	}
	launchSig, err := ReadBounded(filepath.Join(dir, SignatureFile), maxSignatureSize)
	if err != nil {
		return nil, err
	}
	if _, err := VerifySigned(pub, launch, string(launchSig)); err != nil {
		return nil, err
	}
	raw, err := ReadBounded(filepath.Join(dir, BindFile), MaxBindSize)
	if err != nil {
		return nil, err
	}
	bindSig, err := ReadBounded(filepath.Join(dir, BindSignatureFile), maxSignatureSize)
	if err != nil {
		return nil, err
	}
	bind, err := VerifyBind(raw, string(bindSig))
	if err != nil {
		return nil, err
	}
	return &Binding{LaunchKey: pub, Launch: launch, Bind: bind}, nil
}

// Policy is the policy that accepts exactly the guest this binding records,
// for image, under the authority that signed the bind.
func (b *Binding) Policy(image runtimemeasure.ImageIdentity) Policy {
	return Policy{Image: image, LaunchKey: b.LaunchKey, Launch: b.Launch, Authority: []byte(b.Bind.Doc.Authority), Bind: b.Bind.Raw}
}
