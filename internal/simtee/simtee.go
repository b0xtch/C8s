// Package simtee simulates a TDX platform in software: quotes in the vendor's
// format under a development authority of the vendor's algorithms, and the
// four documents a verifier judges such a quote against, signed on request.
//
// It exists for two things. The second baseline of
// docs/session-performance.md runs a session guest with TDX off and a TEE
// simulated in software, so that every check a verifier makes costs what it
// costs on TDX and the difference is what the hardware adds. And a test can
// have this authority say what the vendor's cannot be made to say: that a
// platform's key is revoked, or that its TCB fell behind.
//
// Nothing here protects anything. The keys are in files or in a test's
// memory, and whoever holds them makes any quote. No session image uses it,
// and no verifier accepts this authority unless it was built to
// (the c8s_simtee build tag) and then in place of the vendor's root, never
// beside it.
package simtee

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	pb "github.com/google/go-tdx-guest/proto/tdx"
)

// Marker is in the subject of every certificate of a simulated authority,
// as its organization. The common names are the vendor's, since a verifier's
// library holds a chain to them, so the organization is what tells a reader
// of a certificate what it is.
const Marker = "c8s simulated TEE: for development, protects nothing"

// What a verifier's library holds each certificate's common name to.
const (
	rootName     = "Intel SGX Root CA"
	platformName = "Intel SGX PCK Platform CA"
	pckName      = "Intel SGX PCK Certificate"
	signerName   = "Intel SGX TCB Signing"
)

// RootCRLURL is where the vendor's root says its CRL is. A simulated root
// says the same: a verifier names the document by it, and asks whoever
// stands for the vendor.
const RootCRLURL = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"

// The identity of the vendor's TD quoting enclave, which a verifier holds a
// quote's enclave report to before it reads anything else. A simulated quote
// carries the same values, under a platform key the vendor never certified.
var (
	qeMrSigner   = [32]byte{0xdc, 0x9e, 0x2a, 0x7c, 0x6f, 0x94, 0x8f, 0x17, 0x47, 0x4e, 0x34, 0xa7, 0xfc, 0x43, 0xed, 0x03, 0x0f, 0x7c, 0x15, 0x63, 0xf1, 0xba, 0xbd, 0xdf, 0x63, 0x40, 0xc8, 0x2e, 0x0e, 0x54, 0xa8, 0xc5}
	qeAttributes = [16]byte{0x11}
)

const (
	qeProdID = 2
	// QESVN is the simulated quoting enclave's version, and PCESVN the
	// simulated provisioning enclave's.
	QESVN  = 8
	PCESVN = 13
	// FMSPC and PCEID name the simulated platform's kind: no processor of
	// the vendor's has them.
	FMSPC = "c85100000000"
	PCEID = "0000"
)

// CPUSVN is the simulated platform's CPU security version, a component a
// byte, and TEETCBSVN what its quotes say of the TDX module: version 1 at
// SVN 5, as components 1 and 0. XFAM is the extended features a simulated
// TD says it may use: x87, SSE, AVX and AVX-512 state. A verifier refuses a
// quote that names neither of the first two.
var (
	CPUSVN    = [16]byte{2, 2, 2, 2, 3, 1, 0, 3}
	TEETCBSVN = [16]byte{5, 1, 2}
	XFAM      = [8]byte{0xe7}
)

// issuer is a certificate and the key under it.
type issuer struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// Authority is a development authority in the shape of the vendor's: a
// root, the CA that certifies platforms, and the signer of the documents
// that say where a platform stands.
type Authority struct {
	Root, PlatformCA, Signer issuer
}

// Platform is one simulated machine: the key its quoting enclave's reports
// are signed under, certified by an authority's platform CA.
type Platform struct {
	issuer
	// Chain is the certificate, the platform CA's and the root's, PEM, as a
	// quote carries them.
	Chain []byte
}

func newKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

func serial() (*big.Int, error) {
	// 20 bytes with the top bit clear, as the vendor's.
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	raw[0] = raw[0]&0x7f | 0x01
	return new(big.Int).SetBytes(raw), nil
}

func subject(name string) pkix.Name {
	return pkix.Name{CommonName: name, Organization: []string{Marker}}
}

func keyID(key *ecdsa.PublicKey) []byte {
	raw := elliptic.Marshal(key.Curve, key.X, key.Y) //nolint:staticcheck // the uncompressed point is what a key identifier hashes
	sum := sha256.Sum256(raw)
	return sum[:20]
}

// issue signs template for key under parent, or under key itself when
// parent is nil.
func issue(template *x509.Certificate, key *ecdsa.PrivateKey, parent *issuer) (*x509.Certificate, error) {
	var err error
	if template.SerialNumber, err = serial(); err != nil {
		return nil, err
	}
	template.SubjectKeyId = keyID(&key.PublicKey)
	template.SignatureAlgorithm = x509.ECDSAWithSHA256
	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent.Cert, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// NewAuthority makes a development authority whose certificates are valid
// from an hour before now, the root for thirty years.
func NewAuthority(now time.Time) (*Authority, error) {
	from := now.Add(-time.Hour)
	a := &Authority{}
	var err error
	for _, part := range []*issuer{&a.Root, &a.PlatformCA, &a.Signer} {
		if part.Key, err = newKey(); err != nil {
			return nil, err
		}
	}
	if a.Root.Cert, err = issue(&x509.Certificate{
		Subject: subject(rootName), NotBefore: from, NotAfter: from.AddDate(30, 0, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		CRLDistributionPoints: []string{RootCRLURL},
	}, a.Root.Key, nil); err != nil {
		return nil, fmt.Errorf("the root: %w", err)
	}
	if a.PlatformCA.Cert, err = issue(&x509.Certificate{
		Subject: subject(platformName), NotBefore: from, NotAfter: from.AddDate(15, 0, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		CRLDistributionPoints: []string{RootCRLURL},
	}, a.PlatformCA.Key, &a.Root); err != nil {
		return nil, fmt.Errorf("the platform CA: %w", err)
	}
	if a.Signer.Cert, err = issue(&x509.Certificate{
		Subject: subject(signerName), NotBefore: from, NotAfter: from.AddDate(7, 0, 0),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		CRLDistributionPoints: []string{RootCRLURL},
	}, a.Signer.Key, &a.Root); err != nil {
		return nil, fmt.Errorf("the documents' signer: %w", err)
	}
	return a, nil
}

// sgxExtension is the extension of a PCK certificate that says which
// platform it certifies and at what TCB: the platform's id, a component of
// its CPU SVN an entry, the PCE's SVN, the CPU SVN whole, the PCE's id and
// the platform's kind.
func sgxExtension(ppid [16]byte) (pkix.Extension, error) {
	type entry struct {
		ID    asn1.ObjectIdentifier
		Value any
	}
	oid := func(tail ...int) asn1.ObjectIdentifier {
		return append(asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1}, tail...)
	}
	fmspc, pceID, err := platformKind()
	if err != nil {
		return pkix.Extension{}, err
	}
	var tcb []entry
	for i, svn := range CPUSVN {
		tcb = append(tcb, entry{oid(2, i+1), int(svn)})
	}
	tcb = append(tcb, entry{oid(2, 17), PCESVN}, entry{oid(2, 18), CPUSVN[:]})
	value, err := asn1.Marshal([]entry{
		{oid(1), ppid[:]},
		{oid(2), tcb},
		{oid(3), pceID},
		{oid(4), fmspc},
	})
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{Id: oid(), Value: value}, nil
}

func platformKind() (fmspc, pceID []byte, err error) {
	if fmspc, err = hex.DecodeString(FMSPC); err != nil || len(fmspc) != 6 {
		return nil, nil, errors.New("the simulated FMSPC is not six bytes of hex")
	}
	if pceID, err = hex.DecodeString(PCEID); err != nil || len(pceID) != 2 {
		return nil, nil, errors.New("the simulated PCE id is not two bytes of hex")
	}
	return fmspc, pceID, nil
}

// NewPlatform certifies a new platform key, from an hour before now for
// seven years.
func (a *Authority) NewPlatform(now time.Time) (*Platform, error) {
	key, err := newKey()
	if err != nil {
		return nil, err
	}
	var ppid [16]byte
	if _, err := rand.Read(ppid[:]); err != nil {
		return nil, err
	}
	sgx, err := sgxExtension(ppid)
	if err != nil {
		return nil, err
	}
	from := now.Add(-time.Hour)
	// The six extensions a verifier's library counts: the two key
	// identifiers, the CRL's address, the key usage, the basic constraints
	// and the vendor's own.
	cert, err := issue(&x509.Certificate{
		Subject: subject(pckName), NotBefore: from, NotAfter: from.AddDate(7, 0, 0),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		CRLDistributionPoints: []string{pcs.PckCrlURL("platform")},
		ExtraExtensions:       []pkix.Extension{sgx},
	}, key, &a.PlatformCA)
	if err != nil {
		return nil, fmt.Errorf("the platform's certificate: %w", err)
	}
	if _, err := pcs.PckCertificateExtensions(cert); err != nil {
		return nil, fmt.Errorf("the platform's certificate is none a verifier reads: %w", err)
	}
	return &Platform{issuer: issuer{Cert: cert, Key: key}, Chain: chainPEM(cert, a.PlatformCA.Cert, a.Root.Cert)}, nil
}

func chainPEM(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, cert := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return out
}

// Report is what a quote says of its TD.
type Report struct {
	// MRTD is the measurement of the TD's first memory, and RTMR its four
	// runtime registers.
	MRTD [48]byte
	RTMR [4][48]byte
	// Attributes are the TD's attributes. A simulated TD has none: not
	// the debug attribute either, which a verifier refuses.
	Attributes [8]byte
	// MRConfigID, MROwner and MROwnerConfig are what its host set of it.
	MRConfigID, MROwner, MROwnerConfig [48]byte
	// ReportData is what the TD binds.
	ReportData [64]byte
}

// Quoter makes the quotes of one boot: an attestation key, and the quoting
// enclave's report that binds it, signed once under the platform's key.
type Quoter struct {
	key *ecdsa.PrivateKey
	// certification is everything of a quote that follows the signature
	// over its header and body: the same for every quote of the boot.
	certification *pb.CertificationData
	public        []byte
}

func raw64(x, y *big.Int) []byte {
	out := make([]byte, 64)
	x.FillBytes(out[:32])
	y.FillBytes(out[32:])
	return out
}

func signRaw(key *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	digest := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	return raw64(r, s), nil
}

// NewQuoter makes an attestation key and has the platform certify it, as a
// quoting enclave does when it starts.
func (p *Platform) NewQuoter() (*Quoter, error) {
	key, err := newKey()
	if err != nil {
		return nil, err
	}
	public := raw64(key.X, key.Y)
	// The enclave's report binds the attestation key and its own
	// authenticated data, which the vendor's enclave fills with 32 bytes.
	auth := make([]byte, 32)
	for i := range auth {
		auth[i] = byte(i)
	}
	bound := sha256.Sum256(append(append([]byte{}, public...), auth...))
	// What the enclave is, for whoever reads the quote: no enclave.
	enclave := sha256.Sum256([]byte("c8s simulated TEE: no quoting enclave"))
	report := &pb.EnclaveReport{
		CpuSvn: CPUSVN[:], MiscSelect: 0, Reserved1: make([]byte, 28), Attributes: qeAttributes[:],
		MrEnclave: enclave[:], Reserved2: make([]byte, 32), MrSigner: qeMrSigner[:], Reserved3: make([]byte, 96),
		IsvProdId: qeProdID, IsvSvn: QESVN, Reserved4: make([]byte, 60), ReportData: append(bound[:], make([]byte, 32)...),
	}
	rawReport, err := abi.EnclaveReportToAbiBytes(report)
	if err != nil {
		return nil, fmt.Errorf("the quoting enclave's report: %w", err)
	}
	signature, err := signRaw(p.Key, rawReport)
	if err != nil {
		return nil, err
	}
	chain := &pb.PCKCertificateChainData{CertificateDataType: 5, Size: uint32(len(p.Chain)), PckCertChain: p.Chain}
	inner := &pb.QEReportCertificationData{
		QeReport: report, QeReportSignature: signature,
		QeAuthData:              &pb.QeAuthData{ParsedDataSize: uint32(len(auth)), Data: auth},
		PckCertificateChainData: chain,
	}
	// The enclave's report, its signature, the authenticated data behind a
	// length of two bytes, and the chain behind a type of two and a length
	// of four.
	size := len(rawReport) + len(signature) + 2 + len(auth) + 2 + 4 + len(p.Chain)
	return &Quoter{
		key: key, public: public,
		certification: &pb.CertificationData{CertificateDataType: 6, Size: uint32(size), QeReportCertificationData: inner},
	}, nil
}

// Quote makes a version 4 quote that says report of its TD.
func (q *Quoter) Quote(report *Report) ([]byte, error) {
	header := &pb.Header{
		Version: 4, AttestationKeyType: 2, TeeType: 0x81,
		QeSvn: binary.LittleEndian.AppendUint16(nil, QESVN), PceSvn: binary.LittleEndian.AppendUint16(nil, PCESVN),
		// The vendor's quoting enclave names itself so.
		QeVendorId: []byte{0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07},
		UserData:   make([]byte, 20),
	}
	// What the module is, for whoever reads the quote: no module.
	module := sha512.Sum384([]byte("c8s simulated TEE: no TDX module"))
	body := &pb.TDQuoteBody{
		TeeTcbSvn: TEETCBSVN[:], MrSeam: module[:], MrSignerSeam: make([]byte, 48), SeamAttributes: make([]byte, 8),
		TdAttributes: report.Attributes[:], Xfam: XFAM[:], MrTd: report.MRTD[:],
		MrConfigId: report.MRConfigID[:], MrOwner: report.MROwner[:], MrOwnerConfig: report.MROwnerConfig[:],
		ReportData: report.ReportData[:],
	}
	for i := range report.RTMR {
		body.Rtmrs = append(body.Rtmrs, report.RTMR[i][:])
	}
	rawHeader, err := abi.HeaderToAbiBytes(header)
	if err != nil {
		return nil, fmt.Errorf("the quote's header: %w", err)
	}
	rawBody, err := abi.TdQuoteBodyToAbiBytes(body)
	if err != nil {
		return nil, fmt.Errorf("the quote's body: %w", err)
	}
	signature, err := signRaw(q.key, append(rawHeader, rawBody...))
	if err != nil {
		return nil, err
	}
	quote := &pb.QuoteV4{
		Header: header, TdQuoteBody: body,
		// The signature, the attestation key, and the certification behind
		// a type of two bytes and a length of four.
		SignedDataSize: uint32(64 + 64 + 2 + 4 + int(q.certification.GetSize())),
		SignedData: &pb.Ecdsa256BitQuoteV4AuthData{
			Signature: signature, EcdsaAttestationKey: q.public, CertificationData: q.certification,
		},
	}
	return abi.QuoteToAbiBytes(quote)
}
