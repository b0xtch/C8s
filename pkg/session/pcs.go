package session

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"time"

	"github.com/google/go-tdx-guest/pcs"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
)

// maxCollateralBody bounds one of Intel's documents. The largest, a TCB info,
// is a few kilobytes.
const maxCollateralBody = 256 << 10

// pcsGetter asks Intel's service for one document: one request, an answer
// taken only from where it was asked, and a body that is bounded.
type pcsGetter struct {
	// client is how the service is reached. Nil is this process's own road.
	client *http.Client
}

var pcsClient = &http.Client{
	// A redirect is an answer from somewhere else.
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// vendorDialer opens the connection a verifier's TLS session to Intel's
// service runs on.
type vendorDialer = func(ctx context.Context, network, addr string) (net.Conn, error)

// pcsClientOver is a client that reaches Intel's service over connections
// dial opens. Each still carries a TLS session that ends at Intel, held to
// the system's roots, so whoever carries the bytes reads and changes none.
func pcsClientOver(dial vendorDialer, roots *tls.Config) *http.Client {
	return &http.Client{
		CheckRedirect: pcsClient.CheckRedirect,
		Transport: &http.Transport{
			// No proxy from the environment: the road is the one given.
			DialContext:           dial,
			TLSClientConfig:       roots,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          4,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}
}

// VendorServices lists where a verifier of the platform's evidence asks the
// vendor for its documents, each as host:port. A host that carries such a
// verifier's connections, because the verifier has no network of its own,
// carries them there and nowhere else.
func VendorServices(platform string) ([]string, error) {
	if platform != string(teetypes.PlatformTDX) {
		return nil, fmt.Errorf("no vendor service is known for platform %q", platform)
	}
	root, err := rootCRLURL()
	if err != nil {
		return nil, err
	}
	var services []string
	for _, document := range []string{pcs.TcbInfoURL("000000000000"), pcs.QeIdentityURL(), pcs.PckCrlURL("platform"), root} {
		u, err := url.Parse(document)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" {
			return nil, fmt.Errorf("the vendor's document %q is not at an https address", document)
		}
		port := u.Port()
		if port == "" {
			port = "443"
		}
		if service := net.JoinHostPort(u.Hostname(), port); !slices.Contains(services, service) {
			services = append(services, service)
		}
	}
	return services, nil
}

func (g pcsGetter) Get(document string) (map[string][]string, []byte, error) {
	return g.GetContext(context.Background(), document)
}

func (g pcsGetter) GetContext(ctx context.Context, document string) (map[string][]string, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, document, nil)
	if err != nil {
		return nil, nil, err
	}
	client := g.client
	if client == nil {
		client = pcsClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("%s answered %s", document, resp.Status)
	}
	body, err := readutil.ReadAll(resp.Body, maxCollateralBody)
	if err != nil {
		return nil, nil, fmt.Errorf("read the answer of %s: %w", document, err)
	}
	// Intel's service answers some requests it will not serve with nothing.
	if len(body) == 0 {
		return nil, nil, fmt.Errorf("%s answered with no document", document)
	}
	return resp.Header, body, nil
}

// CollateralPlatform says which of Intel's documents evidence from a platform
// is judged against. A guest reads it from its own quote and tells its host,
// which fetches the documents: see FetchCollateral.
type CollateralPlatform struct {
	// FMSPC is the platform's family, model, stepping, platform type and
	// custom SKU: twelve hex digits from its PCK certificate.
	FMSPC string `json:"fmspc"`
	// CA is which of Intel's PCK CAs certified the platform: "platform" or
	// "processor".
	CA string `json:"ca"`
}

var fmspcRE = regexp.MustCompile(`^[0-9a-f]{12}$`)

// URLs returns where Intel's service keeps the four documents: the TCB info,
// the quoting enclave's identity, the PCK CRL and the root CA CRL. They are
// built here from two values of a fixed shape, so whoever fetches at a
// guest's word fetches nothing else.
func (p CollateralPlatform) URLs() ([]string, error) {
	if !fmspcRE.MatchString(p.FMSPC) {
		return nil, errors.New("an FMSPC is twelve lowercase hex digits")
	}
	if p.CA != "platform" && p.CA != "processor" {
		return nil, errors.New("a PCK CA is platform or processor")
	}
	root, err := rootCRLURL()
	if err != nil {
		return nil, err
	}
	return []string{pcs.TcbInfoURL(p.FMSPC), pcs.QeIdentityURL(), pcs.PckCrlURL(p.CA), root}, nil
}

// CollateralPlatformOf reads the platform from TDX evidence: the PCK
// certificate its quote carries. Evidence of another TEE has none. Nothing
// here checks the evidence, or what it names: whoever fetches at its word
// does, with URLs.
func CollateralPlatformOf(env teetypes.AttestationEvidence) (*CollateralPlatform, error) {
	if env.Platform != teetypes.PlatformTDX {
		return nil, fmt.Errorf("evidence of %q names no Intel platform", env.Platform)
	}
	var envelope struct {
		Quote string `json:"quote"`
	}
	if err := json.Unmarshal(env.Evidence, &envelope); err != nil {
		return nil, fmt.Errorf("TDX evidence: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(envelope.Quote)
	if err != nil {
		return nil, fmt.Errorf("TDX quote encoding: %w", err)
	}
	// A quote ends with its certification chain in PEM, the PCK certificate
	// first. Only that certificate is read here, and none of the report.
	at := bytes.Index(raw, []byte("-----BEGIN CERTIFICATE-----"))
	if at < 0 {
		return nil, errors.New("TDX quote carries no PCK certificate chain")
	}
	block, _ := pem.Decode(raw[at:])
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("TDX quote's PCK certificate is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("PCK certificate: %w", err)
	}
	exts, err := pcs.PckCertificateExtensions(leaf)
	if err != nil {
		return nil, fmt.Errorf("PCK certificate extensions: %w", err)
	}
	platform := &CollateralPlatform{FMSPC: exts.FMSPC}
	switch leaf.Issuer.CommonName {
	case "Intel SGX PCK Platform CA":
		platform.CA = "platform"
	case "Intel SGX PCK Processor CA":
		platform.CA = "processor"
	}
	return platform, nil
}

// issuerChainHeader is the response header that carries the chain a document
// of this kind is signed under, or empty.
func (k collateralKind) issuerChainHeader() string {
	switch k {
	case kindTCBInfo:
		return pcs.TcbInfoIssuerChainPhrase
	case kindQEIdentity:
		return pcs.SgxQeIdentityIssuerChainPhrase
	case kindPCKCRL:
		return pcs.SgxPckCrlIssuerChainPhrase
	}
	return ""
}

// FetchCollateral asks Intel's service for the documents evidence from p is
// judged against, and keeps of each answer what a verifier reads: the body
// and the header with its signing chain. It is for a guest's host. Nothing
// here checks a document: whoever verifies evidence does, and holds each to
// Intel's own date on it.
func FetchCollateral(ctx context.Context, p CollateralPlatform) ([]CollateralDocument, error) {
	return fetchCollateral(ctx, pcsGetter{}, p)
}

func fetchCollateral(ctx context.Context, getter interface {
	GetContext(ctx context.Context, url string) (map[string][]string, []byte, error)
}, p CollateralPlatform) ([]CollateralDocument, error) {
	urls, err := p.URLs()
	if err != nil {
		return nil, err
	}
	docs := make([]CollateralDocument, 0, len(urls))
	for _, url := range urls {
		header, body, err := getter.GetContext(ctx, url)
		if err != nil {
			return nil, err
		}
		doc := CollateralDocument{URL: url, Body: body}
		if name := kindOf(url).issuerChainHeader(); name != "" {
			if chain := header[name]; len(chain) > 0 {
				doc.Header = map[string][]string{name: chain}
			}
		}
		docs = append(docs, doc)
	}
	return docs, nil
}
