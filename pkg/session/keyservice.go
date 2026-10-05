package session

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// SourceKeyService marks a credential the guest takes from its key service
// when it is bound, where one with no source is handed over by a key the
// bind grants.
const SourceKeyService = "keyService"

// SourceBinder marks a credential the binder holds and may seal with the
// bind, so that the guest has it in place before its sandbox starts
// (SealWithBind). A key the bind grants may hand it over as well, as it
// hands over one with no source: a binder whose sealed message was not taken
// puts its credentials that way.
const SourceBinder = "binder"

// maxServiceURL bounds a pinned service's URL.
const maxServiceURL = 255

// MaxKeyServiceMembers bounds the replicas of its key service a bind names.
const MaxKeyServiceMembers = 16

// KeyService pins a key service: where it is reached and what it must be. A
// pool's launch document names the one its TDs open their sessions with, and
// a bind names the one its session trusts.
//
// The key service is an attested guest itself. Image and LaunchKey are what
// its evidence is held to: it runs that image, and it measured a launch
// document that key signed, which is its policy.
type KeyService struct {
	// URL is https://host:port.
	URL string `yaml:"url" json:"url"`
	// Image is the key service's measured image.
	Image Image `yaml:"image" json:"image"`
	// LaunchKey is the public key, PEM, that signs its launch document.
	LaunchKey string `yaml:"launchKey" json:"launchKey"`
	// AcceptTCBStatus names Intel TCB statuses, besides UpToDate, that the
	// key service's platform may have: see Policy.AcceptTCBStatus. Whoever
	// pins the key service accepts them of it, and a bind's pin equals its
	// guest's only if it names the same ones.
	AcceptTCBStatus []string `yaml:"acceptTCBStatus,omitempty" json:"acceptTCBStatus,omitempty"`
}

// BindKeyService is the key service a bind names for its session: the pin,
// which a guest holds to the one in its launch document, and the replicas of
// that key service its binder judged.
//
// A guest has no road to the vendor, so before its bind it judges its key
// service on the vendor's documents as its host hands them over. A host that
// holds the keys of a platform the vendor has since revoked passes that with
// a key service of its own and documents from before the revocation. The
// binder judges the replicas on documents it fetched itself, and the
// authority's signature on the bind carries its verdict to the guest.
type BindKeyService struct {
	// URL, Image, LaunchKey and AcceptTCBStatus are the pin, member for
	// member as KeyService has them: see Pin.
	URL             string   `json:"url"`
	Image           Image    `json:"image"`
	LaunchKey       string   `json:"launchKey"`
	AcceptTCBStatus []string `json:"acceptTCBStatus,omitempty"`
	// Members are the replicas the binder judged as for a release: on the
	// vendor's documents as it fetched them from the vendor within the last
	// hour. Each is a replica's instance key, as sha256:<hex> of its PKIX
	// encoding. From its bind on the guest takes nothing from a replica, and
	// sends it nothing, unless the bind names it. They are no part of the
	// pin.
	Members []string `json:"members"`
}

// Pin is the key service the bind names, as a launch document pins one: what
// a guest holds to the pin it booted under. Nil for a bind that names none.
func (k *BindKeyService) Pin() *KeyService {
	if k == nil {
		return nil
	}
	return &KeyService{URL: k.URL, Image: k.Image, LaunchKey: k.LaunchKey, AcceptTCBStatus: k.AcceptTCBStatus}
}

func (k *BindKeyService) validate() error {
	if err := k.Pin().validate(); err != nil {
		return err
	}
	if n := len(k.Members); n == 0 || n > MaxKeyServiceMembers {
		return fmt.Errorf("members must name 1..%d replicas of the key service, each one its binder judged", MaxKeyServiceMembers)
	}
	for i, member := range k.Members {
		if !instanceKeyRE.MatchString(member) {
			return errors.New("members: each must be sha256:<64 lowercase hex>")
		}
		if slices.Contains(k.Members[:i], member) {
			return fmt.Errorf("members: %s is named twice", member)
		}
	}
	return nil
}

// LoadKeyServicePin reads a pin from the JSON file 'c8s session key-service
// pin' writes.
func LoadKeyServicePin(path string) (*KeyService, error) {
	data, err := ReadBounded(path, MaxDocumentSize)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var pin KeyService
	if err := dec.Decode(&pin); err != nil {
		return nil, fmt.Errorf("key service pin %s: %w", path, err)
	}
	if err := pin.validate(); err != nil {
		return nil, fmt.Errorf("key service pin %s: %w", path, err)
	}
	return &pin, nil
}

// Validate checks every field of the pin.
func (k *KeyService) Validate() error { return k.validate() }

func (k *KeyService) validate() error {
	if len(k.URL) > maxServiceURL {
		return errors.New("url is too long")
	}
	u, err := url.Parse(k.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("url must be https://host:port")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || host == "" {
		return errors.New("url must be https://host:port")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return errors.New("url must name a port")
	}
	// One spelling: what a second reader makes of the URL is what this one
	// did.
	if k.URL != "https://"+net.JoinHostPort(host, port) {
		return errors.New("url must be https://host:port and nothing else")
	}
	if err := k.Image.validate(); err != nil {
		return err
	}
	if _, err := parsePublicKey(k.LaunchKey); err != nil {
		return fmt.Errorf("launchKey: %w", err)
	}
	if err := ValidateTCBStatuses(k.AcceptTCBStatus); err != nil {
		return fmt.Errorf("acceptTCBStatus: %w", err)
	}
	return nil
}

// Equal reports whether two pins name the same key service and accept the
// same of it.
func (k *KeyService) Equal(other *KeyService) bool {
	if k == nil || other == nil {
		return k == other
	}
	if k.URL != other.URL || k.LaunchKey != other.LaunchKey || k.Image.Platform != other.Image.Platform ||
		k.Image.Measurement != other.Image.Measurement || len(k.Image.RTMRs) != len(other.Image.RTMRs) ||
		!slices.Equal(k.AcceptTCBStatus, other.AcceptTCBStatus) {
		return false
	}
	for index, value := range k.Image.RTMRs {
		if other.Image.RTMRs[index] != value {
			return false
		}
	}
	return true
}

// Identity is the image as a pin that evidence is verified against: what
// runtimemeasure.LoadImageManifest returns for the manifest the values came
// from.
func (i Image) Identity() (runtimemeasure.ImageIdentity, error) {
	if err := i.validate(); err != nil {
		return nil, err
	}
	pins := imagePins{family: i.Family(), rtmrs: map[int][runtimemeasure.Size]byte{}}
	// validate has established that the registers decode.
	launch, _ := hex.DecodeString(i.Measurement)
	copy(pins.launch[:], launch)
	for index, value := range i.RTMRs {
		raw, _ := hex.DecodeString(value)
		pins.rtmrs[index] = [runtimemeasure.Size]byte(raw)
	}
	return pins, nil
}

// imagePins is an image pinned by the values a signed document carries.
type imagePins struct {
	family teetypes.Family
	launch [runtimemeasure.Size]byte
	rtmrs  map[int][runtimemeasure.Size]byte
}

func (p imagePins) Family() teetypes.Family { return p.family }

func (p imagePins) LaunchDigests() []runtimemeasure.LaunchVariant {
	return []runtimemeasure.LaunchVariant{{Digest: p.launch}}
}

func (p imagePins) RTMRs() map[int][runtimemeasure.Size]byte { return p.rtmrs }

// Verify holds signature-verified launch claims to the pinned image, and
// fails closed on claims that are absent.
func (p imagePins) Verify(r *teetypes.VerificationResult) error {
	if err := r.Check(); err != nil {
		return err
	}
	if r.Platform.Family() != p.family {
		return fmt.Errorf("%w: the evidence is %s, the pin is %s", runtimemeasure.ErrWrongFamily, r.Platform, p.family)
	}
	launch, err := r.Claims.LaunchMeasurement()
	if err != nil {
		return fmt.Errorf("launch measurement: %w", err)
	}
	if !bytes.Equal(launch, p.launch[:]) {
		return fmt.Errorf("launch measurement mismatch: the guest reports %x, the document pins %x", launch, p.launch)
	}
	if len(p.rtmrs) == 0 {
		return nil
	}
	want := make(map[int][]byte, len(p.rtmrs))
	for index, value := range p.rtmrs {
		want[index] = value[:]
	}
	if err := r.Claims.CheckRTMRs(want); err != nil {
		return fmt.Errorf("image pin mismatch: %w", err)
	}
	return nil
}

// VerifyService proves, from the evidence in a serving certificate, that the
// service holding the certificate's key runs the pinned image, was launched
// for the pinned key, has measured the launch document of this digest and
// nothing after it, and is one of the machines that document lists. The
// caller has checked that the pinned key signed the document, and passes
// the machines it lists.
//
// Like VerifyServingCert it is no freshness proof. The TLS handshake that
// presented the certificate proves the key is live.
func VerifyService(ctx context.Context, pin *KeyService, engine Engine, leaf *x509.Certificate, document string, machine *Machine, now time.Time) error {
	_, err := verifyService(ctx, pin, engine, leaf, document, machine, now)
	return err
}

// VerifyServiceToRelease is VerifyService for a verifier whose verdict lets
// others rely on the service: a binder that names a key service's replica in
// its bind, after which the bind's guest takes credentials from that replica.
// The verdict rests on the vendor's documents as this verifier fetched them
// from the vendor itself within the last hour, and on none that was handed
// over. It returns until when the verdict stands.
func VerifyServiceToRelease(ctx context.Context, pin *KeyService, engine Engine, leaf *x509.Certificate, document string, machine *Machine, now time.Time) (time.Time, error) {
	res, err := verifyService(ctx, pin, engine, leaf, document, machine, now)
	if err != nil {
		return time.Time{}, err
	}
	until := stands(now, leaf, res)
	if err := standsNot(now, until, leaf, res); err != nil {
		return time.Time{}, err
	}
	return until, nil
}

func verifyService(ctx context.Context, pin *KeyService, engine Engine, leaf *x509.Certificate, document string, machine *Machine, now time.Time) (*teetypes.VerificationResult, error) {
	res, rtmr0, err := serviceResult(ctx, pin, engine, leaf, document, now)
	if err != nil {
		return nil, err
	}
	switch {
	case !pin.Image.HasMachineRegister():
	case machine == nil:
		// Its host may have built it any machine: see Policy.AllowNoMachine.
		return nil, refuse("the key service's launch document lists no machine the key service may be")
	case !machine.Allows(rtmr0):
		return nil, refuse("the key service's machine (RTMR[0] %x) is none of the %d its launch document lists", rtmr0, len(machine.RTMR0))
	}
	return res, nil
}

// ServiceMachine verifies a service as VerifyService does, except for its
// machine, and returns what its RTMR[0] holds: nil on a TEE with no such
// register. It is for whoever writes the service's launch document, to read
// the value that document then lists. Nothing may be sent to a service on
// this verdict.
func ServiceMachine(ctx context.Context, pin *KeyService, engine Engine, leaf *x509.Certificate, document string, now time.Time) ([]byte, error) {
	_, rtmr0, err := serviceResult(ctx, pin, engine, leaf, document, now)
	return rtmr0, err
}

func serviceResult(ctx context.Context, pin *KeyService, engine Engine, leaf *x509.Certificate, document string, now time.Time) (*teetypes.VerificationResult, []byte, error) {
	identity, err := pin.Image.Identity()
	if err != nil {
		return nil, nil, err
	}
	policy := Policy{Image: identity, LaunchKey: []byte(pin.LaunchKey), AcceptTCBStatus: pin.AcceptTCBStatus}
	res, err := servingCertResult(ctx, policy, engine, leaf, now, nil, [][]string{{document}})
	if err != nil {
		return nil, nil, err
	}
	if !pin.Image.HasMachineRegister() {
		return res, nil, nil
	}
	rtmr0, err := res.Claims.RTMR(0)
	if err != nil {
		return nil, nil, &VerificationError{Err: fmt.Errorf("the key service's evidence carries no RTMR[0]: %w", err)}
	}
	return res, rtmr0, nil
}
