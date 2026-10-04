package sessionsim_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/disclosure"
	"github.com/confidential-dot-ai/c8s/pkg/session/sessionsim"
)

const image = "registry.example/agent@sha256:1111111111111111111111111111111111111111111111111111111111111111"

// echo is a sandbox with one port, which answers what it is sent, and which
// remembers what it was started with.
type echo struct {
	ln          net.Listener
	image       *session.Sandbox
	credentials string
}

func (e *echo) Start(ctx context.Context, image *session.Sandbox, credentialDir string) error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	e.ln, e.image, e.credentials = ln, image, credentialDir
	context.AfterFunc(ctx, func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	return nil
}

func (e *echo) Dial(ctx context.Context, port int) (net.Conn, error) {
	if e.ln == nil || port != 8080 {
		return nil, errors.New("nothing listens there")
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", e.ln.Addr().String())
}

func newKey(t *testing.T) (*ecdsa.PrivateKey, []byte, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := session.PublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return key, keyPEM, string(pub)
}

// The whole of a tenant's path, as a program outside this module walks it:
// verify the guest unbound, bind it, attest it, release a credential and open
// a stream to its sandbox.
func TestPoolIsBoundAndDriven(t *testing.T) {
	sandbox := &echo{}
	pool := sessionsim.NewGuest(t, sandbox)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	identity, err := runtimemeasure.LoadImageManifest(pool.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	launchKey, err := os.ReadFile(pool.LaunchKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	authority, _, authorityPub := newKey(t)
	_, accessPEM, accessPub := newKey(t)
	signer, err := operatorauth.NewSignerFromKeyPEM(accessPEM)
	if err != nil {
		t.Fatal(err)
	}

	unbound, err := session.NewClient(pool.URL, session.Policy{Image: identity, LaunchKey: launchKey, Authority: []byte(authorityPub), AllowReady: true}, sessionsim.Engine(), signer)
	if err != nil {
		t.Fatal(err)
	}
	defer unbound.Close()
	ready, err := unbound.Ready(ctx)
	if err != nil {
		t.Fatalf("Unbound: %v", err)
	}
	bind, err := session.NewBind(session.BindOptions{
		Authority: authority, InstanceKey: ready.InstanceKey,
		Tenant: "acme", Session: "sbx-1", NotAfter: time.Now().Add(time.Minute),
		Policy: session.BindPolicy{
			Sandbox:     &session.Sandbox{Image: image, Args: []string{"--serve"}},
			Access:      session.Access{Credentials: []string{accessPub}, Forward: []string{accessPub}},
			Credentials: []session.Credential{{Name: "task", MaxBytes: 64}},
			Forward:     &session.Forward{Ports: []int{8080}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unbound.Bind(ctx, bind); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if sandbox.image == nil || sandbox.image.Image != image || len(sandbox.image.Args) != 1 {
		t.Fatalf("the sandbox was started with %+v", sandbox.image)
	}

	binding := session.Binding{LaunchKey: launchKey, Launch: ready.Launch, Bind: bind}
	tenant, err := session.NewClient(pool.URL, binding.Policy(identity), sessionsim.Engine(), signer)
	if err != nil {
		t.Fatal(err)
	}
	defer tenant.Close()
	att, err := tenant.PutCredential(ctx, "task", []byte("do this"))
	if err != nil {
		t.Fatalf("PutCredential: %v", err)
	}
	if att.Tenant != "acme" || att.Session != "sbx-1" || att.Phase != session.PhaseRunning {
		t.Fatalf("attested %s/%s in phase %s", att.Tenant, att.Session, att.Phase)
	}
	if got, err := os.ReadFile(filepath.Join(sandbox.credentials, "task")); err != nil || string(got) != "do this" {
		t.Fatalf("the credential in the sandbox's directory: %q, %v", got, err)
	}

	stream, err := tenant.Dial(ctx, 8080)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(stream, "ping"); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(stream); err != nil || string(got) != "ping" {
		t.Fatalf("the sandbox answered %q, %v", got, err)
	}
}

// bindWith verifies pool's guest unbound and sends it a bind for sandbox.
func bindWith(t *testing.T, pool *sessionsim.Guest, sandbox *session.Sandbox) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	identity, err := runtimemeasure.LoadImageManifest(pool.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	launchKey, err := os.ReadFile(pool.LaunchKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	authority, _, authorityPub := newKey(t)
	_, accessPEM, accessPub := newKey(t)
	signer, err := operatorauth.NewSignerFromKeyPEM(accessPEM)
	if err != nil {
		t.Fatal(err)
	}
	client, err := session.NewClient(pool.URL, session.Policy{Image: identity, LaunchKey: launchKey, Authority: []byte(authorityPub), AllowReady: true}, sessionsim.Engine(), signer)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ready, err := client.Ready(ctx)
	if err != nil {
		t.Fatalf("Unbound: %v", err)
	}
	bind, err := session.NewBind(session.BindOptions{
		Authority: authority, InstanceKey: ready.InstanceKey,
		Tenant: "acme", Session: "sbx-1", NotAfter: time.Now().Add(time.Minute),
		Policy: session.BindPolicy{Sandbox: sandbox, Access: session.Access{Exec: []string{accessPub}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Bind(ctx, bind)
	return err
}

// A pool with no sandbox is a bare guest: it takes a bind that names no
// image, and refuses one that names one.
func TestPoolWithNoSandbox(t *testing.T) {
	if err := bindWith(t, sessionsim.NewGuest(t, nil), nil); err != nil {
		t.Fatalf("a bare guest refused a bind that names no image: %v", err)
	}
	if err := bindWith(t, sessionsim.NewGuest(t, nil), &session.Sandbox{Image: image}); err == nil {
		t.Fatal("a guest with no sandbox took a bind that names an image")
	}
}

// A pool with a sandbox is a guest for tenants: its bind names an image.
func TestPoolWithASandboxTakesNoBindWithoutAnImage(t *testing.T) {
	sandbox := &echo{}
	err := bindWith(t, sessionsim.NewGuest(t, sandbox), nil)
	var refused *session.StatusError
	if !errors.As(err, &refused) || refused.Code != string(disclosure.BindNoSandbox) {
		t.Fatalf("a bind that names no image: %v", err)
	}
	if sandbox.image != nil {
		t.Fatal("the refused bind started the sandbox")
	}
}

// A pinned pool's launch document lists the machine its guest runs on, and
// its twin's does too. A verifier that requires a pinned machine takes those
// and no guest of a pool that pins none.
func TestPinnedPoolListsItsMachine(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	unbound := func(guest *sessionsim.Guest) (*session.ReadyTD, error) {
		t.Helper()
		identity, err := runtimemeasure.LoadImageManifest(guest.ManifestPath)
		if err != nil {
			t.Fatal(err)
		}
		launchKey, err := os.ReadFile(guest.LaunchKeyPath)
		if err != nil {
			t.Fatal(err)
		}
		_, _, authorityPub := newKey(t)
		_, accessPEM, _ := newKey(t)
		signer, err := operatorauth.NewSignerFromKeyPEM(accessPEM)
		if err != nil {
			t.Fatal(err)
		}
		policy := session.Policy{Image: identity, LaunchKey: launchKey, Authority: []byte(authorityPub), AllowReady: true, RequireMachine: true}
		client, err := session.NewClient(guest.URL, policy, sessionsim.Engine(), signer)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(client.Close)
		return client.Ready(ctx)
	}
	pinned := sessionsim.NewPinnedGuest(t, nil)
	for name, guest := range map[string]*sessionsim.Guest{"a pinned pool": pinned, "its twin": pinned.Twin(t, nil)} {
		ready, err := unbound(guest)
		if err != nil || ready.Document.Machine == nil || len(ready.Document.Machine.RTMR0) != 1 {
			t.Fatalf("%s: %v", name, err)
		}
	}
	plain := sessionsim.NewGuest(t, nil)
	for name, guest := range map[string]*sessionsim.Guest{"a pool that pins none": plain, "its twin": plain.Twin(t, nil)} {
		if _, err := unbound(guest); err == nil || !strings.Contains(err.Error(), "pins no machine") {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// A twin is a guest of the same platform: a policy that pins the image and
// the launch key accepts both, and each has a key and a document of its own.
func TestTwinIsAnotherGuestOfTheSamePlatform(t *testing.T) {
	pool := sessionsim.NewGuest(t, nil)
	twin := pool.Twin(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	identity, err := runtimemeasure.LoadImageManifest(pool.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	launchKey, err := os.ReadFile(pool.LaunchKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if theirs, err := os.ReadFile(twin.LaunchKeyPath); err != nil || string(theirs) != string(launchKey) || twin.ManifestPath != pool.ManifestPath {
		t.Fatalf("the twin is of another platform (%v)", err)
	}
	_, _, authorityPub := newKey(t)
	_, accessPEM, _ := newKey(t)
	signer, err := operatorauth.NewSignerFromKeyPEM(accessPEM)
	if err != nil {
		t.Fatal(err)
	}
	policy := session.Policy{Image: identity, LaunchKey: launchKey, Authority: []byte(authorityPub), AllowReady: true}
	var seen []*session.ReadyTD
	for _, guest := range []*sessionsim.Guest{pool, twin} {
		client, err := session.NewClient(guest.URL, policy, sessionsim.Engine(), signer)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		ready, err := client.Ready(ctx)
		if err != nil {
			t.Fatalf("a guest of the pinned platform: %v", err)
		}
		seen = append(seen, ready)
	}
	first, _ := session.InstanceKeyDigest(seen[0].InstanceKey)
	second, _ := session.InstanceKeyDigest(seen[1].InstanceKey)
	if first == second {
		t.Fatal("the twin is the same guest")
	}
	// Another platform's guest is refused by the same policy.
	stranger := sessionsim.NewGuest(t, nil)
	client, err := session.NewClient(stranger.URL, policy, sessionsim.Engine(), signer)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Ready(ctx); err == nil {
		t.Fatal("control: a guest of another platform passed the same policy")
	}
}
