//go:build podcvm_hardware

// Package podcvm_test is the hardware suite for pod CVMs. It runs against a
// live guest on real TDX (or SEV-SNP) and uses the production verifier with
// the vendor's root of trust. Nothing here is simulated.
//
//	go test -tags podcvm_hardware -c -o podcvm-hw.test ./test/podcvm
//	C8S_POD_URL=https://<pod-ip>:8443 C8S_POD_BUNDLE=<dir> \
//	  C8S_POD_MANIFEST=<manifest.json> ./podcvm-hw.test -test.v
//
// C8S_POD_COLLATERAL selects "required" (default: Intel collateral fetched,
// TCB must be UpToDate) or "skip". Run it both ways on a new host: a host
// whose TCB is behind fails "required", and that is a finding about the host.
// C8S_POD_ACCEPT_TCB (comma-separated, e.g. OutOfDate) then names the statuses
// to accept, so the rest of the suite still runs with collateral checked.
package podcvm_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/podcvm"
)

type env struct {
	url      string
	bundle   *podcvm.Bundle
	dir      string
	manifest string
	policy   podcvm.Policy
	engine   podcvm.Engine
	signer   *operatorauth.Signer
}

func load(t *testing.T) *env {
	t.Helper()
	e := &env{url: os.Getenv("C8S_POD_URL"), dir: os.Getenv("C8S_POD_BUNDLE"), manifest: os.Getenv("C8S_POD_MANIFEST")}
	if e.url == "" || e.dir == "" || e.manifest == "" {
		t.Fatal("C8S_POD_URL, C8S_POD_BUNDLE and C8S_POD_MANIFEST are required")
	}
	bundle, err := podcvm.LoadBundle(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := runtimemeasure.LoadImageManifest(e.manifest)
	if err != nil {
		t.Fatal(err)
	}
	mode := podcvm.Collateral(os.Getenv("C8S_POD_COLLATERAL"))
	if mode == "" {
		mode = podcvm.CollateralRequired
	}
	// C8S_POD_ACCEPT_TCB lists TCB statuses the run accepts besides UpToDate.
	var accept []string
	if list := os.Getenv("C8S_POD_ACCEPT_TCB"); list != "" {
		accept = strings.Split(list, ",")
	}
	engine, err := podcvm.NewEngine(podcvm.EngineOptions{Collateral: mode, AcceptTCBStatus: accept})
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(e.dir, podcvm.BundleKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	e.bundle, e.engine, e.signer = bundle, engine, signer
	e.policy = podcvm.Policy{Image: identity, LaunchKey: bundle.LaunchKey, Launch: bundle.Launch}
	return e
}

func (e *env) client(t *testing.T, policy podcvm.Policy, auth operatorauth.Authorizer) *podcvm.Client {
	t.Helper()
	client, err := podcvm.NewClient(e.url, policy, e.engine, auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func deadline(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	return ctx
}

func refused(err error) bool {
	var verdict *podcvm.VerificationError
	return errors.As(err, &verdict)
}

// The milestone path, on silicon: fresh evidence from inside the guest, the
// pinned build and the guest-generated key verified, one credential released,
// one authenticated command that proves the credential arrived.
func TestHardwareAttestReleaseExec(t *testing.T) {
	e := load(t)
	client := e.client(t, e.policy, e.signer)

	started := time.Now()
	att, err := client.Attest(deadline(t))
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	t.Logf("attested in %s: platform=%s tenant=%s sandbox=%s phase=%s events=%v collateral_verified=%v",
		time.Since(started).Round(time.Millisecond), att.Result.Platform, att.Document.Tenant, att.Document.Sandbox,
		att.Phase, att.Events, att.Result.CollateralVerified)
	t.Logf("MRTD=%s RTMR3=%v instance_key=sha256:%s", att.Result.Claims.LaunchDigest,
		att.Result.Claims.PlatformData["rtmr_3"], certutil.CertFingerprint(att.InstanceKey))
	if finding := podcvm.TCBOf(att.Result); finding != nil {
		t.Logf("TCB: platform=%s tdx_module=%s quoting_enclave=%s advisories=%v", finding.Platform, finding.Module, finding.QuotingEnclave, finding.Advisories)
	}
	if att.Phase != podcvm.PhaseRunning {
		t.Fatalf("phase = %s", att.Phase)
	}

	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	credential := []byte("hw-" + hex.EncodeToString(secret))
	if len(e.bundle.Document.Credentials) == 0 {
		t.Fatal("the launch document under test declares no credential")
	}
	name := e.bundle.Document.Credentials[0].Name
	if _, err := client.PutCredential(deadline(t), name, credential); err != nil {
		t.Fatalf("release credential: %v", err)
	}
	started = time.Now()
	resp, err := client.Exec(deadline(t), podcvm.ExecRequest{Argv: []string{"sh", "-c", `id -u; cat "$C8S_CREDENTIALS_DIR/` + name + `"`}})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	t.Logf("exec round trip %s, in guest %dms", time.Since(started).Round(time.Millisecond), resp.DurationMillis)
	uid, got, _ := strings.Cut(string(resp.Stdout), "\n")
	if resp.ExitCode != 0 || got != string(credential) {
		t.Fatalf("command did not read the released credential: exit %d stdout %q stderr %q", resp.ExitCode, resp.Stdout, resp.Stderr)
	}
	if uid == "0" {
		t.Fatal("the command ran as root in the guest")
	}
}

// Real evidence from the live guest, bent one way per case, must be refused by
// the production verifier. The control proves the unbent evidence passes.
func TestHardwareRejectsInvalidEvidence(t *testing.T) {
	e := load(t)
	client := e.client(t, e.policy, e.signer)
	fetch := func(t *testing.T) *podcvm.Evidence {
		evidence, err := client.FetchEvidence(deadline(t))
		if err != nil {
			t.Fatal(err)
		}
		return evidence
	}
	if _, err := fetch(t).Verify(deadline(t), e.policy, e.engine); err != nil {
		t.Fatalf("control: genuine evidence was refused: %v", err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, err := podcvm.PublicKeyPEM(&otherKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.MarshalPKIXPublicKey(&otherKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	flipQuote := func(t *testing.T, ev *podcvm.Evidence, offset int) {
		var body map[string]json.RawMessage
		if err := json.Unmarshal(ev.Response.Evidence.Evidence, &body); err != nil {
			t.Fatal(err)
		}
		var quoteB64 string
		if err := json.Unmarshal(body["quote"], &quoteB64); err != nil {
			t.Skipf("evidence has no TDX quote field: %v", err)
		}
		quote, err := base64.StdEncoding.DecodeString(quoteB64)
		if err != nil {
			t.Fatal(err)
		}
		quote[offset] ^= 1
		body["quote"], _ = json.Marshal(base64.StdEncoding.EncodeToString(quote))
		ev.Response.Evidence.Evidence, _ = json.Marshal(body)
	}
	manifestWith := func(t *testing.T, field string) podcvm.Policy {
		raw, err := os.ReadFile(e.manifest)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		tdx, ok := m["tdx"].(map[string]any)
		if !ok {
			t.Skip("manifest has no tdx block")
		}
		value := tdx[field].(string)
		flipped := "0"
		if value[0] == '0' {
			flipped = "1"
		}
		tdx[field] = flipped + value[1:]
		out, _ := json.Marshal(m)
		path := filepath.Join(t.TempDir(), "manifest.json")
		if err := os.WriteFile(path, out, 0o644); err != nil {
			t.Fatal(err)
		}
		identity, err := runtimemeasure.LoadImageManifest(path)
		if err != nil {
			t.Fatal(err)
		}
		policy := e.policy
		policy.Image = identity
		// The launch document pins the real image, so pin the tenant instead:
		// the case under test is the hardware claim against the image pin.
		policy.Launch, policy.Tenant, policy.Sandbox = nil, e.bundle.Document.Tenant, e.bundle.Document.Sandbox
		return policy
	}
	// Offsets into a v4 TDX quote: 48-byte header, then the TD report body.
	const mrtd, rtmr1, rtmr3, reportData, signature = 48 + 136, 48 + 376, 48 + 472, 48 + 520, 48 + 584 + 4

	for name, tc := range map[string]func(t *testing.T) (*podcvm.Evidence, podcvm.Policy){
		"replayed for a different nonce": func(t *testing.T) (*podcvm.Evidence, podcvm.Policy) {
			ev := fetch(t)
			ev.Nonce = bytes.Repeat([]byte{0x5a}, podcvm.NonceSize)
			return ev, e.policy
		},
		"bound to another instance key": func(t *testing.T) (*podcvm.Evidence, podcvm.Policy) {
			ev := fetch(t)
			ev.InstanceKey = otherDER
			return ev, e.policy
		},
		"quote MRTD bit flipped": func(t *testing.T) (*podcvm.Evidence, podcvm.Policy) {
			ev := fetch(t)
			flipQuote(t, ev, mrtd)
			return ev, e.policy
		},
		"quote RTMR[1] bit flipped": func(t *testing.T) (*podcvm.Evidence, podcvm.Policy) {
			ev := fetch(t)
			flipQuote(t, ev, rtmr1)
			return ev, e.policy
		},
		"quote RTMR[3] bit flipped": func(t *testing.T) (*podcvm.Evidence, podcvm.Policy) {
			ev := fetch(t)
			flipQuote(t, ev, rtmr3)
			return ev, e.policy
		},
		"quote REPORTDATA bit flipped": func(t *testing.T) (*podcvm.Evidence, podcvm.Policy) {
			ev := fetch(t)
			flipQuote(t, ev, reportData)
			return ev, e.policy
		},
		"quote signature bit flipped": func(t *testing.T) (*podcvm.Evidence, podcvm.Policy) {
			ev := fetch(t)
			flipQuote(t, ev, signature)
			return ev, e.policy
		},
		"policy pins another MRTD": func(t *testing.T) (*podcvm.Evidence, podcvm.Policy) {
			return fetch(t), manifestWith(t, "mrtd")
		},
		"policy pins another kernel (RTMR[1])": func(t *testing.T) (*podcvm.Evidence, podcvm.Policy) {
			return fetch(t), manifestWith(t, "rtmr1")
		},
		"policy pins another rootfs (RTMR[2])": func(t *testing.T) (*podcvm.Evidence, podcvm.Policy) {
			return fetch(t), manifestWith(t, "rtmr2")
		},
		"policy pins another launch key": func(t *testing.T) (*podcvm.Evidence, podcvm.Policy) {
			policy := e.policy
			policy.LaunchKey = otherPub
			policy.Launch, policy.Tenant, policy.Sandbox = nil, e.bundle.Document.Tenant, e.bundle.Document.Sandbox
			return fetch(t), policy
		},
		"policy pins another tenant": func(t *testing.T) (*podcvm.Evidence, podcvm.Policy) {
			policy := e.policy
			policy.Launch, policy.Tenant, policy.Sandbox = nil, "someone-else", e.bundle.Document.Sandbox
			return fetch(t), policy
		},
		"launch document replaced by another the same key signed": func(t *testing.T) (*podcvm.Evidence, podcvm.Policy) {
			// What the host would do to pass one tenant's guest off as another's.
			dir := filepath.Join(t.TempDir(), "other")
			err := podcvm.NewBundle(podcvm.BundleOptions{
				Dir: dir, ManifestPath: e.manifest, KeyPath: filepath.Join(e.dir, podcvm.BundleKeyFile),
				Tenant: "someone-else", Sandbox: e.bundle.Document.Sandbox,
			})
			if err != nil {
				t.Fatal(err)
			}
			other, err := podcvm.LoadBundle(dir)
			if err != nil {
				t.Fatal(err)
			}
			ev := fetch(t)
			ev.Response.Launch, ev.Response.Signature = other.Launch, other.Signature
			events, err := podcvm.ExpectedEvents(other.Launch, other.Document, podcvm.PhaseRunning)
			if err != nil {
				t.Fatal(err)
			}
			ev.Response.Events = events
			policy := e.policy
			policy.Launch, policy.Tenant, policy.Sandbox = nil, "someone-else", e.bundle.Document.Sandbox
			return ev, policy
		},
	} {
		t.Run(name, func(t *testing.T) {
			ev, policy := tc(t)
			att, err := ev.Verify(deadline(t), policy, e.engine)
			if err == nil {
				t.Fatalf("ACCEPTED invalid evidence: %+v", att)
			}
			if !refused(err) {
				t.Fatalf("not a verification verdict: %v", err)
			}
			t.Logf("refused: %v", err)
		})
	}
}

// The handshake and the API refuse callers and policies that do not match.
func TestHardwareRejectsWrongCallerAndPolicy(t *testing.T) {
	e := load(t)
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	strangerPEM, err := certutil.MarshalECKeyPEM(stranger)
	if err != nil {
		t.Fatal(err)
	}
	strangerSigner, err := operatorauth.NewSignerFromKeyPEM(strangerPEM)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("a key the launch document does not name", func(t *testing.T) {
		client := e.client(t, e.policy, strangerSigner)
		_, err := client.Exec(deadline(t), podcvm.ExecRequest{Argv: []string{"id"}})
		var status *podcvm.StatusError
		if !errors.As(err, &status) || status.Status != http.StatusUnauthorized {
			t.Fatalf("want HTTP 401, got %v", err)
		}
	})
	t.Run("a token moved to another body", func(t *testing.T) {
		signed := []byte(`{"id":"` + strings.Repeat("a", 32) + `","argv":["true"]}`)
		sent := []byte(`{"id":"` + strings.Repeat("b", 32) + `","argv":["id"]}`)
		header, err := e.signer.Authorization(http.MethodPost, podcvm.PathExec, signed)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(deadline(t), http.MethodPost, e.url+podcvm.PathExec, bytes.NewReader(sent))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", header)
		raw := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // a probe: nothing about this peer is trusted
		defer raw.CloseIdleConnections()
		resp, err := raw.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("want HTTP 401, got %d", resp.StatusCode)
		}
	})
	t.Run("a client pinning another image releases nothing", func(t *testing.T) {
		raw, err := os.ReadFile(e.manifest)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		tdx, ok := m["tdx"].(map[string]any)
		if !ok {
			t.Skip("manifest has no tdx block")
		}
		tdx["rtmr2"] = strings.Repeat("0", 96)
		out, _ := json.Marshal(m)
		path := filepath.Join(t.TempDir(), "manifest.json")
		if err := os.WriteFile(path, out, 0o644); err != nil {
			t.Fatal(err)
		}
		identity, err := runtimemeasure.LoadImageManifest(path)
		if err != nil {
			t.Fatal(err)
		}
		policy := e.policy
		policy.Image = identity
		policy.Launch, policy.Tenant, policy.Sandbox = nil, e.bundle.Document.Tenant, e.bundle.Document.Sandbox
		client := e.client(t, policy, e.signer)
		marker := "must-not-arrive-" + hex.EncodeToString([]byte(time.Now().Format("150405.000")))
		name := e.bundle.Document.Credentials[0].Name
		if _, err := client.PutCredential(deadline(t), name, []byte(marker)); !refused(err) {
			t.Fatalf("want a verification refusal, got %v", err)
		}
		// Confirm from inside the guest that nothing was written.
		good := e.client(t, e.policy, e.signer)
		resp, err := good.Exec(deadline(t), podcvm.ExecRequest{Argv: []string{"sh", "-c", `grep -c ` + marker + ` "$C8S_CREDENTIALS_DIR/` + name + `" 2>/dev/null || true`}})
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(resp.Stdout)) == "1" {
			t.Fatal("a credential reached the guest through a client that failed verification")
		}
	})
}

// Tenant code must have no way to a quote or to the runtime register: either
// would let it speak as the guest. Each probe runs as the workload user and
// reports what it could reach.
func TestHardwareTenantCannotReachTheTEE(t *testing.T) {
	e := load(t)
	client := e.client(t, e.policy, e.signer)
	for name, probe := range map[string]string{
		"open the TDX guest device":    `for d in /dev/tdx_guest /dev/tdx-guest /dev/sev-guest; do [ -e "$d" ] && { [ -r "$d" ] || [ -w "$d" ]; } && echo "REACHED $d"; done; true`,
		"create a TSM report":          `d=/sys/kernel/config/tsm/report/c8s-probe-$$; mkdir "$d" 2>/dev/null && { echo "REACHED $d"; rmdir "$d"; }; true`,
		"extend a runtime register":    `for f in /sys/class/misc/tdx_guest/measurements/rtmr*; do [ -w "$f" ] && echo "REACHED $f"; done; true`,
		"gain privilege through sudo":  `command -v sudo >/dev/null && sudo -n true 2>/dev/null && echo "REACHED root"; true`,
		"find a setuid or setgid file": `find / -xdev -type f -perm /6000 2>/dev/null | head -5 | sed 's/^/REACHED /'; true`,
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := client.Exec(deadline(t), podcvm.ExecRequest{Argv: []string{"sh", "-c", "id -u; " + probe}})
			if err != nil {
				t.Fatal(err)
			}
			uid, rest, _ := strings.Cut(string(resp.Stdout), "\n")
			if resp.ExitCode != 0 || uid == "" || uid == "0" {
				t.Fatalf("probe did not run as the workload user: exit %d uid %q stderr %q", resp.ExitCode, uid, resp.Stderr)
			}
			if strings.Contains(rest, "REACHED") {
				t.Fatalf("tenant code %s", strings.TrimSpace(rest))
			}
		})
	}
}

// A repeated exec id must not run the command again, on real hardware either.
func TestHardwareExecIdempotent(t *testing.T) {
	e := load(t)
	client := e.client(t, e.policy, e.signer)
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	req := podcvm.ExecRequest{ID: hex.EncodeToString(id[:]), Argv: []string{"sh", "-c", "echo run >> $HOME/hw-idem-" + hex.EncodeToString(id[:4]) + "; wc -l < $HOME/hw-idem-" + hex.EncodeToString(id[:4])}}
	for i := 0; i < 3; i++ {
		resp, err := client.Exec(deadline(t), req)
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(resp.Stdout)) != "1" {
			t.Fatalf("call %d: the command ran %s times", i+1, strings.TrimSpace(string(resp.Stdout)))
		}
	}
}
