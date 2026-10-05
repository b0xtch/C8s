package simtee

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// The files of a simulated authority's directory. Each certificate is PEM,
// and each key the PEM of its SEC 1 encoding beside it.
const (
	rootFile       = "root"
	platformCAFile = "platform-ca"
	signerFile     = "signer"
	platformFile   = "platform"

	certSuffix, keySuffix = ".pem", ".key"

	// VendorFile holds the address, host:port, at which the directory's
	// documents are served: see Handler. Whoever serves them writes it.
	VendorFile = "vendor"

	// maxFileBytes bounds one file of the directory.
	maxFileBytes = 64 << 10
)

// Directory is a simulated authority as its directory holds it: the
// authority, and the one platform it certified, which every guest launched
// from the directory quotes under, as the guests of a host quote under their
// host's.
type Directory struct {
	Authority *Authority
	Platform  *Platform
}

// NewDirectory makes a development authority and one platform under it, and
// writes both to dir, which must not exist. The keys in it make any quote
// and any document: whoever reads the directory is the vendor.
func NewDirectory(dir string, now time.Time) (*Directory, error) {
	if _, err := os.Lstat(dir); err == nil {
		return nil, fmt.Errorf("%s already exists", dir)
	}
	authority, err := NewAuthority(now)
	if err != nil {
		return nil, err
	}
	platform, err := authority.NewPlatform(now)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	for name, part := range map[string]*issuer{
		rootFile: &authority.Root, platformCAFile: &authority.PlatformCA, signerFile: &authority.Signer, platformFile: &platform.issuer,
	} {
		key, err := x509.MarshalECPrivateKey(part.Key)
		if err != nil {
			return nil, err
		}
		for path, block := range map[string]*pem.Block{
			filepath.Join(dir, name+certSuffix): {Type: "CERTIFICATE", Bytes: part.Cert.Raw},
			filepath.Join(dir, name+keySuffix):  {Type: "EC PRIVATE KEY", Bytes: key},
		} {
			if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
				return nil, err
			}
		}
	}
	return &Directory{Authority: authority, Platform: platform}, nil
}

func readBounded(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxFileBytes {
		return nil, fmt.Errorf("%s is more than %d bytes", path, maxFileBytes)
	}
	return os.ReadFile(path)
}

func loadCert(dir, name string) (*x509.Certificate, error) {
	data, err := readBounded(filepath.Join(dir, name+certSuffix))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s%s holds no certificate", name, certSuffix)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s%s: %w", name, certSuffix, err)
	}
	// A directory that holds anything but a simulated authority is not read:
	// no key of a real one is ever put to this use.
	if err := Marked(cert); err != nil {
		return nil, fmt.Errorf("%s%s: %w", name, certSuffix, err)
	}
	return cert, nil
}

func loadIssuer(dir, name string) (issuer, error) {
	cert, err := loadCert(dir, name)
	if err != nil {
		return issuer{}, err
	}
	data, err := readBounded(filepath.Join(dir, name+keySuffix))
	if err != nil {
		return issuer{}, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return issuer{}, fmt.Errorf("%s%s holds no key", name, keySuffix)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return issuer{}, fmt.Errorf("%s%s: %w", name, keySuffix, err)
	}
	if public, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !public.Equal(&key.PublicKey) {
		return issuer{}, fmt.Errorf("%s%s is not the key of %s%s", name, keySuffix, name, certSuffix)
	}
	return issuer{Cert: cert, Key: key}, nil
}

// LoadDirectory reads the authority and the platform NewDirectory wrote.
func LoadDirectory(dir string) (*Directory, error) {
	authority, platform := &Authority{}, &Platform{}
	var err error
	for name, part := range map[string]*issuer{
		rootFile: &authority.Root, platformCAFile: &authority.PlatformCA, signerFile: &authority.Signer, platformFile: &platform.issuer,
	} {
		if *part, err = loadIssuer(dir, name); err != nil {
			return nil, fmt.Errorf("simulated authority %s: %w", dir, err)
		}
	}
	platform.Chain = chainPEM(platform.Cert, authority.PlatformCA.Cert, authority.Root.Cert)
	return &Directory{Authority: authority, Platform: platform}, nil
}

// LoadRoot reads the root of the authority in dir, and nothing else of it:
// what a verifier of its platforms' quotes takes in place of the vendor's.
func LoadRoot(dir string) (*x509.Certificate, error) {
	root, err := loadCert(dir, rootFile)
	if err != nil {
		return nil, fmt.Errorf("simulated authority %s: %w", dir, err)
	}
	if !root.IsCA || root.CheckSignatureFrom(root) != nil {
		return nil, fmt.Errorf("simulated authority %s: its root signs itself as no authority's does", dir)
	}
	return root, nil
}

// LoadVendor reads the address the documents of the authority in dir are
// served at.
func LoadVendor(dir string) (string, error) {
	data, err := readBounded(filepath.Join(dir, VendorFile))
	if err != nil {
		return "", fmt.Errorf("simulated authority %s: nobody serves its documents: %w", dir, err)
	}
	address := string(trimSpace(data))
	if address == "" {
		return "", fmt.Errorf("simulated authority %s: %s names no address", dir, VendorFile)
	}
	return address, nil
}

func trimSpace(data []byte) []byte {
	for len(data) > 0 && (data[len(data)-1] == '\n' || data[len(data)-1] == '\r' || data[len(data)-1] == ' ') {
		data = data[:len(data)-1]
	}
	return data
}

const (
	// HardwareFile is the name of the file a launcher puts on a simulated
	// guest's launch volume, and MaxHardwareBytes the most it holds.
	HardwareFile     = "simtee.json"
	MaxHardwareBytes = 64 << 10
	// RegisterPath is where a simulated guest keeps RTMR[3]: a file in its
	// memory, which its init makes and its agent extends.
	RegisterPath = "/run/c8s-simtee/rtmr3"
)

// Hardware is what stands for the hardware of one simulated guest: what a
// launcher hands the guest in place of a TDX module. Nothing measures a
// simulated guest, and nothing inside a guest can measure its own first
// memory, so the launcher says what the registers of the guest's image hold,
// and hands over the key the platform's quotes are certified under.
type Hardware struct {
	// MRTD and RTMR are the registers a TDX module and the guest's firmware
	// would have filled by the time the guest's first program runs: the
	// measurement of the image's firmware, of the machine, and of the image's
	// kernel and what it booted. Hex, 48 bytes each.
	MRTD string    `json:"mrtd"`
	RTMR [3]string `json:"rtmr"`
	// PlatformKey is the platform's key, PEM, and Chain its certificate, the
	// platform CA's and the root's, PEM.
	PlatformKey string `json:"platformKey"`
	Chain       string `json:"chain"`
}

// NewHardware is what a launcher hands a guest of the image whose registers
// are mrtd and rtmr1 and rtmr2, on a machine it describes by machine: a
// class's shape, in any words. RTMR[0] is the digest of those words, so that
// two shapes are two machines, as on TDX.
func (d *Directory) NewHardware(mrtd, rtmr1, rtmr2 [48]byte, machine string) (*Hardware, error) {
	key, err := x509.MarshalECPrivateKey(d.Platform.Key)
	if err != nil {
		return nil, err
	}
	rtmr0 := sha512.Sum384([]byte("c8s simulated TEE: machine\x00" + machine))
	return &Hardware{
		MRTD:        hex.EncodeToString(mrtd[:]),
		RTMR:        [3]string{hex.EncodeToString(rtmr0[:]), hex.EncodeToString(rtmr1[:]), hex.EncodeToString(rtmr2[:])},
		PlatformKey: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: key})),
		Chain:       string(d.Platform.Chain),
	}, nil
}

// Encode is the hardware as its file holds it.
func (h *Hardware) Encode() ([]byte, error) { return json.Marshal(h) }

// ParseHardware reads what a launcher handed a simulated guest.
func ParseHardware(data []byte) (*Hardware, error) {
	var h Hardware
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, fmt.Errorf("simulated hardware: %w", err)
	}
	if _, _, err := h.registers(); err != nil {
		return nil, err
	}
	return &h, nil
}

func register(value string) (out [48]byte, err error) {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != len(out) {
		return out, errors.New("simulated hardware: a register is not 48 bytes of hex")
	}
	copy(out[:], raw)
	return out, nil
}

// registers are MRTD and RTMR 0 to 2.
func (h *Hardware) registers() (mrtd [48]byte, rtmr [3][48]byte, err error) {
	if mrtd, err = register(h.MRTD); err != nil {
		return mrtd, rtmr, err
	}
	for i, value := range h.RTMR {
		if rtmr[i], err = register(value); err != nil {
			return mrtd, rtmr, err
		}
	}
	return mrtd, rtmr, nil
}

// Machine is a simulated guest's hardware as the guest runs on it: the
// registers its host said its image fills, a quoting enclave of its own, and
// the authority its platform's quotes chain to.
type Machine struct {
	MRTD [48]byte
	RTMR [3][48]byte
	// Root is the authority's root: what a simulated guest holds another
	// simulated guest's evidence to.
	Root   *x509.Certificate
	quoter *Quoter
}

// Boot is what a guest does with the hardware its launcher handed it: it
// reads the registers, and makes the attestation key of this boot, which the
// platform's key certifies.
func (h *Hardware) Boot() (*Machine, error) {
	mrtd, rtmr, err := h.registers()
	if err != nil {
		return nil, err
	}
	var chain []*x509.Certificate
	for rest := []byte(h.Chain); ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("simulated hardware: %w", err)
		}
		chain = append(chain, cert)
	}
	if len(chain) != 3 {
		return nil, fmt.Errorf("simulated hardware: its chain is %d certificates, want the platform's, its CA's and the root's", len(chain))
	}
	if err := Marked(chain...); err != nil {
		return nil, fmt.Errorf("simulated hardware: %w", err)
	}
	block, _ := pem.Decode([]byte(h.PlatformKey))
	if block == nil {
		return nil, errors.New("simulated hardware: it holds no platform key")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("simulated hardware: %w", err)
	}
	if public, ok := chain[0].PublicKey.(*ecdsa.PublicKey); !ok || !public.Equal(&key.PublicKey) {
		return nil, errors.New("simulated hardware: its key is not its platform certificate's")
	}
	platform := &Platform{issuer: issuer{Cert: chain[0], Key: key}, Chain: []byte(h.Chain)}
	quoter, err := platform.NewQuoter()
	if err != nil {
		return nil, err
	}
	return &Machine{MRTD: mrtd, RTMR: rtmr, Root: chain[2], quoter: quoter}, nil
}

// Quote is the machine's quote over reportData, for a guest whose RTMR[3]
// holds rtmr3.
func (m *Machine) Quote(rtmr3 [48]byte, reportData [64]byte) ([]byte, error) {
	return m.quoter.Quote(&Report{
		MRTD: m.MRTD, RTMR: [4][48]byte{m.RTMR[0], m.RTMR[1], m.RTMR[2], rtmr3}, ReportData: reportData,
	})
}
