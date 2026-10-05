package simtee

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	tdxverify "github.com/google/go-tdx-guest/verify"
)

// A simulated authority is kept in a directory: whoever serves its documents
// reads all of it, a launcher its platform, and a verifier its root and
// nothing else. A guest boots on what its launcher hands it of that
// directory, and its quotes verify under the directory's root, on documents
// asked of whoever serves them, in another process.
func TestGuestOfADirectoryQuotesUnderItsRoot(t *testing.T) {
	now := time.Now()
	dir := filepath.Join(t.TempDir(), "authority")
	made, err := NewDirectory(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDirectory(dir, now); err == nil {
		t.Fatal("a second authority was written over the first")
	}
	loaded, err := LoadDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Authority.Root.Cert.Equal(made.Authority.Root.Cert) || !loaded.Platform.Key.Equal(made.Platform.Key) ||
		string(loaded.Platform.Chain) != string(made.Platform.Chain) {
		t.Fatal("the directory does not read back as it was written")
	}
	root, err := LoadRoot(dir)
	if err != nil || !root.Equal(made.Authority.Root.Cert) {
		t.Fatalf("the directory's root: %v", err)
	}
	// Every key file is its owner's alone.
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 8 {
		t.Fatalf("the directory holds %d files, %v", len(entries), err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s is open to %v", entry.Name(), info.Mode().Perm())
		}
	}

	// Its documents, served to another process.
	vendor := NewVendor(loaded.Authority, time.Now)
	server := httptest.NewServer(Handler(vendor))
	defer server.Close()
	address := strings.TrimPrefix(server.URL, "http://")
	if err := os.WriteFile(filepath.Join(dir, VendorFile), []byte(address+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadVendor(dir); err != nil || got != address {
		t.Fatalf("the address of the directory's documents reads as %q, %v", got, err)
	}
	remote := NewRemote(address, nil)

	// What a launcher hands a guest, and what the guest makes of it.
	var mrtd, rtmr1, rtmr2 [48]byte
	copy(mrtd[:], "the image's firmware")
	copy(rtmr1[:], "its kernel")
	copy(rtmr2[:], "what the kernel booted")
	hardware, err := loaded.NewHardware(mrtd, rtmr1, rtmr2, "4 vCPUs, 16 GiB")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := hardware.Encode()
	if err != nil {
		t.Fatal(err)
	}
	handed, err := ParseHardware(encoded)
	if err != nil {
		t.Fatal(err)
	}
	machine, err := handed.Boot()
	if err != nil {
		t.Fatal(err)
	}
	if machine.MRTD != mrtd || machine.RTMR[1] != rtmr1 || machine.RTMR[2] != rtmr2 || !machine.Root.Equal(root) {
		t.Fatal("the guest's registers are not the ones its launcher declared")
	}
	// Two shapes are two machines.
	other, err := loaded.NewHardware(mrtd, rtmr1, rtmr2, "2 vCPUs, 4 GiB")
	if err != nil {
		t.Fatal(err)
	}
	if other.RTMR[0] == hardware.RTMR[0] || other.RTMR[1] != hardware.RTMR[1] {
		t.Fatal("the machine's register does not tell two shapes apart, or another register does")
	}

	var rtmr3 [48]byte
	copy(rtmr3[:], "what the guest extended")
	var bound [64]byte
	copy(bound[:], "bound")
	raw, err := machine.Quote(rtmr3, bound)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := abi.QuoteToProto(raw)
	if err != nil {
		t.Fatal(err)
	}
	quote := parsed.(*pb.QuoteV4)
	body := quote.GetTdQuoteBody()
	if string(body.GetMrTd()) != string(mrtd[:]) || string(body.GetRtmrs()[3]) != string(rtmr3[:]) || string(body.GetReportData()) != string(bound[:]) {
		t.Fatal("the quote does not say what the guest holds")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	at := time.Now()
	verify := func(getter interface {
		Get(string) (map[string][]string, []byte, error)
	}, roots *x509.CertPool) error {
		return tdxverify.TdxQuote(quote, &tdxverify.Options{
			GetCollateral: true, CheckRevocations: true, Getter: getter, TrustedRoots: roots,
			Now: &tdxverify.TimeSet{PckCertChain: at, TcbInfo: at, QeIdentity: at, PckCrl: at, RootCaCrl: at},
		})
	}
	if err := verify(remote, roots); err != nil {
		t.Fatalf("the guest's quote, on documents another process serves: %v", err)
	}
	asked := vendor.Asked()
	slices.Sort(asked)
	want := []string{pcs.PckCrlURL("platform"), pcs.QeIdentityURL(), pcs.TcbInfoURL(FMSPC), RootCRLURL}
	slices.Sort(want)
	if !slices.Equal(asked, want) {
		t.Fatalf("the verifier asked the directory's server for %v, want %v", asked, want)
	}
	// The vendor's own root did not certify this guest's platform.
	if err := verify(remote, nil); err == nil {
		t.Fatal("a simulated guest's quote verified under the vendor's root")
	}
	// A document nobody serves, and a server that is gone.
	if _, _, err := remote.Get("https://api.trustedservices.intel.com/another"); err == nil {
		t.Fatal("the directory's server answered for a document it does not have")
	}
	server.Close()
	if _, _, err := remote.Get(RootCRLURL); err == nil {
		t.Fatal("a server that is gone answered")
	}
}

// The directory's server answers one question in one way.
func TestSimulatedVendorIsAskedByADocumentsAddress(t *testing.T) {
	authority, err := NewAuthority(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(Handler(NewVendor(authority, time.Now)))
	defer server.Close()
	for name, tc := range map[string]struct {
		method, query string
		want          int
	}{
		"a document it has":       {http.MethodGet, "?document=" + RootCRLURL, http.StatusOK},
		"no document named":       {http.MethodGet, "", http.StatusBadRequest},
		"a document it has not":   {http.MethodGet, "?document=https://example.com/x", http.StatusNotFound},
		"anything but a question": {http.MethodPost, "?document=" + RootCRLURL, http.StatusMethodNotAllowed},
	} {
		req, err := http.NewRequest(tc.method, server.URL+"/"+tc.query, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("%s: answered %d, want %d", name, resp.StatusCode, tc.want)
		}
	}
	// A verifier with no network of its own asks over the road it is given.
	dialed := 0
	remote := NewRemote("vendor.invalid:1", func(_ context.Context, network, _ string) (net.Conn, error) {
		dialed++
		return net.Dial(network, strings.TrimPrefix(server.URL, "http://"))
	})
	if _, body, err := remote.Get(RootCRLURL); err != nil || len(body) == 0 || dialed != 1 {
		t.Fatalf("over a road of its own: %v, %d dials", err, dialed)
	}
}

// A directory that holds anything but a simulated authority is not read: a
// certificate that does not say it is simulated, a key that is another's, or
// what is no certificate at all.
func TestDirectoryOfAnotherAuthorityIsNotRead(t *testing.T) {
	now := time.Now()
	fresh := func() string {
		t.Helper()
		dir := filepath.Join(t.TempDir(), "authority")
		if _, err := NewDirectory(dir, now); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: rootName, Organization: []string{"Intel Corporation"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	unmarked := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	dir := fresh()
	if err := os.WriteFile(filepath.Join(dir, rootFile+certSuffix), unmarked, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRoot(dir); err == nil {
		t.Fatal("a root that does not say it is simulated was taken")
	}
	if _, err := LoadDirectory(dir); err == nil {
		t.Fatal("a directory whose root does not say it is simulated was read")
	}

	dir = fresh()
	other, err := os.ReadFile(filepath.Join(fresh(), platformFile+keySuffix))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, platformFile+keySuffix), other, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDirectory(dir); err == nil {
		t.Fatal("a platform whose key is another's was read")
	}

	dir = fresh()
	if err := os.WriteFile(filepath.Join(dir, signerFile+certSuffix), []byte("no certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDirectory(dir); err == nil {
		t.Fatal("a directory with a file that is no certificate was read")
	}
	if _, err := LoadVendor(fresh()); err == nil {
		t.Fatal("a directory nobody serves named an address")
	}
	// The platform CA's certificate in the root's place signs itself as no
	// root does.
	dir = fresh()
	ca, err := os.ReadFile(filepath.Join(dir, platformCAFile+certSuffix))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, rootFile+certSuffix), ca, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRoot(dir); err == nil {
		t.Fatal("a certificate that another signed was taken as a root")
	}
}

// What a launcher hands a guest is whole, or the guest does not boot on it.
func TestGuestBootsOnWholeHardwareAlone(t *testing.T) {
	dir, err := NewDirectory(filepath.Join(t.TempDir(), "authority"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	elsewhere, err := NewDirectory(filepath.Join(t.TempDir(), "authority"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var register [48]byte
	whole := func() *Hardware {
		t.Helper()
		h, err := dir.NewHardware(register, register, register, "a machine")
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	if _, err := whole().Boot(); err != nil {
		t.Fatalf("whole hardware: %v", err)
	}
	foreign, err := elsewhere.NewHardware(register, register, register, "a machine")
	if err != nil {
		t.Fatal(err)
	}
	for name, bend := range map[string]func(*Hardware){
		"a register that is too short":    func(h *Hardware) { h.MRTD = h.MRTD[:94] },
		"a register that is no hex":       func(h *Hardware) { h.RTMR[1] = strings.Repeat("z", 96) },
		"no platform key":                 func(h *Hardware) { h.PlatformKey = "" },
		"another platform's key":          func(h *Hardware) { h.PlatformKey = foreign.PlatformKey },
		"a chain of two":                  func(h *Hardware) { h.Chain = h.Chain[:strings.LastIndex(h.Chain, "-----BEGIN")] },
		"a chain that is no certificates": func(h *Hardware) { h.Chain = "no chain" },
	} {
		h := whole()
		bend(h)
		encoded, err := h.Encode()
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseHardware(encoded)
		if err == nil {
			_, err = parsed.Boot()
		}
		if err == nil {
			t.Errorf("a guest booted on hardware with %s", name)
		}
	}
	if _, err := ParseHardware([]byte("{")); err == nil {
		t.Error("what is no hardware file was read")
	}
}

// A guest boots on no hardware whose certificates do not say they are
// simulated: no key of a real platform is ever put to this use, whoever
// hands it over.
func TestGuestBootsUnderNoUnmarkedCertificate(t *testing.T) {
	now := time.Now()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "a platform", Organization: []string{"Intel Corporation"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	unmarked := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := NewDirectory(filepath.Join(t.TempDir(), "authority"), now)
	if err != nil {
		t.Fatal(err)
	}
	var register [48]byte
	h, err := dir.NewHardware(register, register, register, "a machine")
	if err != nil {
		t.Fatal(err)
	}
	// The whole chain is the unmarked certificate, three times over, with
	// its own key: everything else about it holds.
	h.Chain = unmarked + unmarked + unmarked
	h.PlatformKey = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}))
	if _, err := h.Boot(); err == nil || !strings.Contains(err.Error(), "simulated") {
		t.Fatalf("a guest booted under certificates that do not say they are simulated: %v", err)
	}
	// One unmarked certificate among the authority's is enough.
	whole, err := dir.NewHardware(register, register, register, "a machine")
	if err != nil {
		t.Fatal(err)
	}
	last := strings.LastIndex(whole.Chain, "-----BEGIN")
	whole.Chain = whole.Chain[:last] + unmarked
	if _, err := whole.Boot(); err == nil {
		t.Fatal("a guest booted under a root that does not say it is simulated")
	}
}

// The address a directory's documents are served at is what its file holds,
// and a file that holds none is nobody serving.
func TestVendorFileNamesAnAddressOrNobodyServes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "authority")
	if _, err := NewDirectory(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, empty := range []string{"", "\n", " \r\n"} {
		if err := os.WriteFile(filepath.Join(dir, VendorFile), []byte(empty), 0o600); err != nil {
			t.Fatal(err)
		}
		if address, err := LoadVendor(dir); err == nil || !strings.Contains(err.Error(), "names no address") {
			t.Errorf("a vendor file holding %q names %q, %v", empty, address, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, VendorFile), []byte("127.0.0.1:4000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if address, err := LoadVendor(dir); err != nil || address != "127.0.0.1:4000" {
		t.Fatalf("the address as written: %q, %v", address, err)
	}
}

// A verifier reads no more than a document from whoever answers it.
func TestRemoteReadsNoMoreThanADocument(t *testing.T) {
	size := maxDocumentBytes
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, size))
	}))
	defer server.Close()
	remote := NewRemote(strings.TrimPrefix(server.URL, "http://"), nil)
	if _, body, err := remote.Get(RootCRLURL); err != nil || len(body) != maxDocumentBytes {
		t.Fatalf("an answer as long as a document may be: %d bytes, %v", len(body), err)
	}
	size = maxDocumentBytes + 1
	if _, body, err := remote.Get(RootCRLURL); err == nil || body != nil {
		t.Fatalf("an answer longer than a document was read: %d bytes, %v", len(body), err)
	}
}
