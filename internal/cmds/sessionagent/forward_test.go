package sessionagent_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// portsRunner is a runner whose sandbox has ports: the test's own listeners.
type portsRunner struct {
	*recordingRunner
	*sessiontest.Ports
}

func (r *portsRunner) Dial(ctx context.Context, port int) (net.Conn, error) {
	return r.Ports.Dial(ctx, port)
}

// forwarding is a guest bound by a tenant whose bind opens ports of the
// sandbox to its access key.
type forwarding struct {
	*pool
	sandbox *sessiontest.Ports
	// tenant is the tenant's client, with the access key.
	tenant *session.Client
	ready  *session.ReadyTD
	bind   *session.SignedBind
}

func newForwarding(t *testing.T, ports []int, mutate func(*session.BindOptions)) *forwarding {
	t.Helper()
	f := &forwarding{pool: newPool(t), sandbox: &sessiontest.Ports{}}
	f.cfg.Runner = &portsRunner{recordingRunner: f.runner, Ports: f.sandbox}
	f.start(t)
	client := f.client(t, f.access)
	var err error
	if f.ready, err = client.Ready(ctxT(t)); err != nil {
		t.Fatalf("Unbound: %v", err)
	}
	f.bind = f.bindFor(t, f.ready, func(o *session.BindOptions) {
		o.Policy.Forward = &session.Forward{Ports: ports}
		o.Policy.Access.Forward = []string{f.accessPub}
		if mutate != nil {
			mutate(o)
		}
	})
	if _, err := client.Bind(ctxT(t), f.bind); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	f.tenant = f.boundClient(t, f.ready, f.bind)
	return f
}

// as is a client for the bound guest that signs with another key.
func (f *forwarding) as(t *testing.T, signer *operatorauth.Signer) *session.Client {
	t.Helper()
	return f.client(t, signer)
}

func halfClose(t *testing.T, conn net.Conn) {
	t.Helper()
	half, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("a stream of type %T cannot end its input alone", conn)
	}
	if err := half.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
}

func readAll(t *testing.T, conn net.Conn) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read the stream to its end: %v (after %q)", err, data)
	}
	return string(data)
}

// A stream reaches a port of the sandbox that the bind opens, carries both
// directions, and lets either end finish its input while the other goes on.
// It runs in a TLS session of its own that ends at the attested key.
func TestForwardCarriesAStreamToASandboxPort(t *testing.T) {
	f := newForwarding(t, []int{80, 9000}, nil)
	f.sandbox.Open(t, 9000, sessiontest.Echo)
	f.sandbox.Open(t, 80, func(conn net.Conn) {
		// A sandbox that speaks first and then hangs up.
		_, _ = io.WriteString(conn, "hello\n")
		_ = conn.Close()
	})

	// Dial attests first: this client has attested nothing yet.
	conn, err := f.tenant.Dial(ctxT(t), 9000)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	for _, line := range []string{"one\n", "two\n"} {
		if _, err := io.WriteString(conn, line); err != nil {
			t.Fatal(err)
		}
		if got, err := reader.ReadString('\n'); err != nil || got != line {
			t.Fatalf("sent %q, the sandbox answered %q, %v", line, got, err)
		}
	}
	// The end of this side's input reaches the sandbox, and what the
	// sandbox still says reaches this side.
	if _, err := io.WriteString(conn, "last\n"); err != nil {
		t.Fatal(err)
	}
	halfClose(t, conn)
	if rest, err := io.ReadAll(reader); err != nil || string(rest) != "last\n" {
		t.Fatalf("after the end of input the stream carried %q, %v", rest, err)
	}

	att, err := f.tenant.Attest(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	state := conn.ConnectionState()
	key, err := x509.MarshalPKIXPublicKey(state.PeerCertificates[0].PublicKey)
	if err != nil || !bytes.Equal(key, att.InstanceKey) {
		t.Fatalf("the stream's TLS session does not end at the attested instance key (%v)", err)
	}

	greeting, err := f.tenant.Dial(ctxT(t), 80)
	if err != nil {
		t.Fatalf("Dial a second port: %v", err)
	}
	defer greeting.Close()
	if got := readAll(t, greeting); got != "hello\n" {
		t.Fatalf("a sandbox that speaks first said %q", got)
	}
	if asked := f.sandbox.Asked(); !slices.Equal(asked, []int{9000, 80}) {
		t.Fatalf("the agent connected to ports %v of the sandbox", asked)
	}
}

// upgrade sends one forward request the way an arbitrary peer would, with no
// trust gate in front of it, and returns the answer's status and error code.
// early is written right behind the request, before any answer.
func upgrade(t *testing.T, url string, body []byte, authorization string, headers map[string]string, early string) (int, string, *bufio.Reader, net.Conn) {
	t.Helper()
	conn, err := tls.Dial("tcp", strings.TrimPrefix(url, "https://"), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // a probe: nothing about this peer is trusted
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	req, err := http.NewRequest(http.MethodPost, url+session.PathForward, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	var wire bytes.Buffer
	if err := req.Write(&wire); err != nil {
		t.Fatal(err)
	}
	wire.WriteString(early)
	if _, err := conn.Write(wire.Bytes()); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		t.Fatalf("read the agent's answer: %v", err)
	}
	var refusal types.ErrorResponse
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = json.NewDecoder(resp.Body).Decode(&refusal)
		_ = resp.Body.Close()
	}
	return resp.StatusCode, refusal.Error, reader, conn
}

var upgradeHeaders = map[string]string{"Connection": "Upgrade", "Upgrade": session.ForwardProtocol}

// forwardToken is a token for one forward request to the guest at url.
func forwardToken(t *testing.T, url string, signer *operatorauth.Signer, body string) string {
	t.Helper()
	token, err := signer.AuthorizationFor(sessiontest.Audience(t, url), http.MethodPost, session.PathForward, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// A stream is opened for a key the bind grants streams, to a port the bind
// lists, by a request that asks for exactly that. Nothing else reaches the
// sandbox.
func TestForwardRefusals(t *testing.T) {
	execOnly, execOnlyPub := newSigner(t)
	stranger, _ := newSigner(t)
	f := newForwarding(t, []int{80, 9000}, func(o *session.BindOptions) {
		o.Policy.Access.Exec = append(o.Policy.Access.Exec, execOnlyPub)
	})
	f.sandbox.Open(t, 9000, sessiontest.Echo)

	// A port the bind does not list, although the sandbox listens there.
	f.sandbox.Open(t, 8080, sessiontest.Echo)
	_, err := f.tenant.Dial(ctxT(t), 8080)
	assertStatus(t, err, http.StatusForbidden)
	// The agent's own listener in the sandbox's namespace: no bind can list it.
	_, err = f.tenant.Dial(ctxT(t), session.SandboxProxyPort)
	assertStatus(t, err, http.StatusForbidden)

	// A listed port nothing listens on.
	_, err = f.tenant.Dial(ctxT(t), 80)
	var closed *session.StatusError
	if !errors.As(err, &closed) || closed.Status != http.StatusBadGateway || closed.Code != types.ErrorCodePortUnreachable {
		t.Fatalf("a listed port with no listener: %v", err)
	}

	// A key that may run commands is not thereby one that may open streams.
	runner := f.as(t, execOnly)
	if _, err := runner.Exec(ctxT(t), session.ExecRequest{Argv: []string{"true"}}); err != nil {
		t.Fatalf("control: the exec key cannot exec: %v", err)
	}
	_, err = runner.Dial(ctxT(t), 9000)
	assertStatus(t, err, http.StatusUnauthorized)
	_, err = f.as(t, stranger).Dial(ctxT(t), 9000)
	assertStatus(t, err, http.StatusUnauthorized)

	const open = `{"port":9000}`
	token := forwardToken(t, f.url, f.access, open)
	elsewhere, err := f.access.AuthorizationFor("sha256:"+strings.Repeat("0", 64), http.MethodPost, session.PathForward, []byte(open))
	if err != nil {
		t.Fatal(err)
	}
	unnamed, err := f.access.Authorization(http.MethodPost, session.PathForward, []byte(open))
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		body, token string
		headers     map[string]string
		want        int
	}{
		"no token":                    {open, "", upgradeHeaders, http.StatusUnauthorized},
		"a token for another guest":   {open, elsewhere, upgradeHeaders, http.StatusUnauthorized},
		"a token that names no guest": {open, unnamed, upgradeHeaders, http.StatusUnauthorized},
		"a token for another port":    {`{"port":80}`, token, upgradeHeaders, http.StatusUnauthorized},
		"no upgrade":                  {open, token, nil, http.StatusUpgradeRequired},
		"the protocol and no upgrade": {open, token, map[string]string{"Upgrade": session.ForwardProtocol}, http.StatusUpgradeRequired},
		"another protocol":            {open, token, map[string]string{"Connection": "Upgrade", "Upgrade": "websocket"}, http.StatusUpgradeRequired},
		"port 0":                      {`{"port":0}`, forwardToken(t, f.url, f.access, `{"port":0}`), upgradeHeaders, http.StatusBadRequest},
		"a port past the last":        {`{"port":65536}`, forwardToken(t, f.url, f.access, `{"port":65536}`), upgradeHeaders, http.StatusBadRequest},
		"an address":                  {`{"port":"127.0.0.1:9000"}`, forwardToken(t, f.url, f.access, `{"port":"127.0.0.1:9000"}`), upgradeHeaders, http.StatusBadRequest},
		"a host beside the port":      {`{"port":9000,"host":"10.0.0.1"}`, forwardToken(t, f.url, f.access, `{"port":9000,"host":"10.0.0.1"}`), upgradeHeaders, http.StatusBadRequest},
		"a second value":              {open + open, forwardToken(t, f.url, f.access, open+open), upgradeHeaders, http.StatusBadRequest},
		"an oversized request":        {`{"port":9000}` + strings.Repeat(" ", session.MaxForwardRequestBytes), "", upgradeHeaders, http.StatusRequestEntityTooLarge},
	} {
		if status, _, _, _ := upgrade(t, f.url, []byte(tc.body), tc.token, tc.headers, ""); status != tc.want {
			t.Errorf("%s: HTTP %d, want %d", name, status, tc.want)
		}
	}
	// Of all of the above only the closed port was ever connected to.
	if asked := f.sandbox.Asked(); !slices.Equal(asked, []int{80}) {
		t.Fatalf("refused requests reached the sandbox's ports %v", asked)
	}

	// The control: the same request, whole.
	status, _, reader, conn := upgrade(t, f.url, []byte(open), forwardToken(t, f.url, f.access, open), upgradeHeaders, "early\n")
	if status != http.StatusSwitchingProtocols {
		t.Fatalf("control: HTTP %d", status)
	}
	// What a caller wrote right behind its request is the start of the stream.
	if got, err := reader.ReadString('\n'); err != nil || got != "early\n" {
		t.Fatalf("bytes sent behind the request came back as %q, %v", got, err)
	}
	_ = conn.Close()
}

// An unbound guest has granted nobody anything, and a guest whose sandbox is
// not admitted has no port to connect to yet.
func TestForwardNeedsABoundGuestAndARunningSandbox(t *testing.T) {
	p := newPool(t)
	sandbox := &sessiontest.Ports{}
	p.cfg.Runner = &portsRunner{recordingRunner: p.runner, Ports: sandbox}
	p.start(t)
	const open = `{"port":9000}`
	for name, signer := range map[string]*operatorauth.Signer{"the pool's launch key": p.launchSigner(t), "the tenant's access key": p.access} {
		if status, _, _, _ := upgrade(t, p.url, []byte(open), forwardToken(t, p.url, signer, open), upgradeHeaders, ""); status != http.StatusUnauthorized {
			t.Errorf("%s asked an unbound guest for a stream: HTTP %d", name, status)
		}
	}

	// Bound, with its sandbox prepared and not started yet.
	h := newPool(t)
	ports := &sessiontest.Ports{}
	ports.Open(t, 9000, sessiontest.Echo)
	h.runner.gate = make(chan struct{})
	h.cfg.Runner = &portsRunner{recordingRunner: h.runner, Ports: ports}
	h.start(t)
	binder := h.client(t, h.access)
	ready, err := binder.Ready(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	bind := h.bindFor(t, ready, func(o *session.BindOptions) {
		o.Policy.Forward, o.Policy.Access.Forward = &session.Forward{Ports: []int{9000}}, []string{h.accessPub}
	})
	bound := make(chan error, 1)
	go func() {
		_, err := binder.Bind(ctxT(t), bind)
		bound <- err
	}()
	until(t, "the bind reaches the runner", func() bool { return h.runner.recorded() == "prepare "+sandboxImage })
	signer := h.access
	if status, _, _, _ := upgrade(t, h.url, []byte(open), forwardToken(t, h.url, signer, open), upgradeHeaders, ""); status != http.StatusConflict {
		t.Fatalf("a stream to a sandbox that is not admitted: HTTP %d", status)
	}
	if asked := append(sandbox.Asked(), ports.Asked()...); len(asked) != 0 {
		t.Fatalf("a refused stream reached ports %v", asked)
	}
	close(h.runner.gate)
	if err := <-bound; err != nil {
		t.Fatal(err)
	}
	conn, err := h.boundClient(t, ready, bind).Dial(ctxT(t), 9000)
	if err != nil {
		t.Fatalf("Dial once the sandbox is admitted: %v", err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "now\n"); err != nil {
		t.Fatal(err)
	}
	halfClose(t, conn)
	if got := readAll(t, conn); got != "now\n" {
		t.Fatalf("the admitted sandbox answered %q", got)
	}
}

// A guest that runs no sandbox image has no sandbox port. Its commands run
// in the guest's own network namespace, where a stream would reach the
// guest's services, so its runner connects to nothing.
func TestBareGuestHasNoPortToForward(t *testing.T) {
	h := newHarness(t, nil)
	if _, err := h.cfg.Runner.Dial(context.Background(), 8443); err == nil {
		t.Fatal("the runner of a guest with no sandbox image connected to a port")
	}
}

// Streams are counted for the guest and for each key. A stream does not count
// as a request in flight, so a key that holds all its streams still runs
// commands. An ended stream gives its place back.
func TestForwardStreamsAreBounded(t *testing.T) {
	second, secondPub := newSigner(t)
	third, thirdPub := newSigner(t)
	f := newForwarding(t, []int{9000}, func(o *session.BindOptions) {
		o.Policy.Access.Forward = append(o.Policy.Access.Forward, secondPub, thirdPub)
	})
	f.sandbox.Open(t, 9000, sessiontest.Echo)
	if sessionagent.MaxForwardsPerKey <= sessionagent.MaxInflightRequest {
		t.Fatalf("fixture: %d streams for a key would not show that a stream holds no request's place (%d)", sessionagent.MaxForwardsPerKey, sessionagent.MaxInflightRequest)
	}
	hold := func(client *session.Client, n int) []net.Conn {
		t.Helper()
		var held []net.Conn
		for i := 0; i < n; i++ {
			conn, err := client.Dial(ctxT(t), 9000)
			if err != nil {
				t.Fatalf("stream %d: %v", i+1, err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			held = append(held, conn)
		}
		return held
	}
	held := hold(f.tenant, sessionagent.MaxForwardsPerKey)
	_, err := f.tenant.Dial(ctxT(t), 9000)
	assertStatus(t, err, http.StatusTooManyRequests)
	if _, err := f.tenant.Exec(ctxT(t), session.ExecRequest{Argv: []string{"true"}}); err != nil {
		t.Fatalf("a key holding all its streams could not run a command: %v", err)
	}

	// Another key has a count of its own, up to what the guest carries in all.
	hold(f.as(t, second), sessionagent.MaxForwards-sessionagent.MaxForwardsPerKey)
	last := f.as(t, third)
	_, err = last.Dial(ctxT(t), 9000)
	assertStatus(t, err, http.StatusTooManyRequests)

	// Every held stream still carries.
	for _, i := range []int{0, len(held) - 1} {
		if _, err := io.WriteString(held[i], "still\n"); err != nil {
			t.Fatal(err)
		}
		_ = held[i].SetReadDeadline(time.Now().Add(10 * time.Second))
		if got, err := bufio.NewReader(held[i]).ReadString('\n'); err != nil || got != "still\n" {
			t.Fatalf("held stream %d answered %q, %v", i, got, err)
		}
	}

	// One ends, and its place is free once the agent has seen that.
	_ = held[0].Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := last.Dial(ctxT(t), 9000)
		if err == nil {
			_ = conn.Close()
			break
		}
		if !isStatus(err, http.StatusTooManyRequests) || time.Now().After(deadline) {
			t.Fatalf("a stream after one ended: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The host can answer one address with two guests. Once a client has attested
// its guest, a stream opens only on a connection that ends at that guest's
// key: a twin of the same image that would welcome the client's key gets
// neither the request nor a byte of the stream.
func TestForwardOpensOnlyToTheAttestedGuest(t *testing.T) {
	open := func(access string) func(o *session.BindOptions) {
		return func(o *session.BindOptions) {
			o.Policy.Sandbox, o.Policy.Forward = &session.Sandbox{Image: sandboxImage}, &session.Forward{Ports: []int{9000}}
			o.Policy.Access = session.Access{Exec: []string{access}, Credentials: []string{access}, Forward: []string{access}}
		}
	}
	withPorts := func(h *harness) *sessiontest.Ports {
		ports := &sessiontest.Ports{}
		ports.Open(t, 9000, sessiontest.Echo)
		h.cfg.Runner = &portsRunner{recordingRunner: &recordingRunner{ProcessRunner: h.cfg.Runner.(*sessionagent.ProcessRunner), td: h.td}, Ports: ports}
		return ports
	}
	h := newHarness(t, nil)
	h.binds = open(h.ownerPub)
	own := withPorts(h)
	h.start(t)

	impostor := newHarnessIn(t, func(o *session.BundleOptions) { o.ManifestPath = h.td.WriteManifest(t) }, open(h.ownerPub))
	impostor.td.MRTD, impostor.td.RTMR[1], impostor.td.RTMR[2] = h.td.MRTD, h.td.RTMR[1], h.td.RTMR[2]
	theirs := withPorts(impostor)
	impostor.start(t)

	// Without a pinned document the handshake proves the image and nothing
	// about who launched or bound the guest, so the twin passes it.
	policy := h.policy
	policy.Launch, policy.Bind, policy.Tenant, policy.Session = nil, nil, "acme", "sbx-1"
	var twin atomic.Bool
	host := newSplitter(t, func(n int) string {
		if n > 1 && twin.Load() {
			return strings.TrimPrefix(impostor.url, "https://")
		}
		return strings.TrimPrefix(h.url, "https://")
	})
	client, err := session.NewClient(host.url, policy, sessiontest.Engine{}, h.owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if _, err := client.Attest(ctxT(t)); err != nil {
		t.Fatalf("attest the real guest: %v", err)
	}
	conn, err := client.Dial(ctxT(t), 9000)
	if err != nil {
		t.Fatalf("control: a stream to the attested guest: %v", err)
	}
	_ = conn.Close()

	twin.Store(true)
	if _, err := client.Dial(ctxT(t), 9000); !isVerdict(err) {
		t.Fatalf("a stream whose connection the host led to another guest: %v", err)
	}
	if asked := theirs.Asked(); len(asked) != 0 {
		t.Fatalf("the other guest was asked for ports %v", asked)
	}
	if asked := own.Asked(); !slices.Equal(asked, []int{9000}) {
		t.Fatalf("the attested guest was asked for ports %v", asked)
	}
}

// ending waits for a sandbox connection to end and returns how.
func ending(t *testing.T, endings <-chan sessiontest.Ending) sessiontest.Ending {
	t.Helper()
	select {
	case e := <-endings:
		return e
	case <-time.After(10 * time.Second):
		t.Fatal("the sandbox's connection did not end")
		return sessiontest.Ending{}
	}
}

// cutStream is a stream through a hop the test can cut, with one line sent
// and its echo read: nothing is in flight in either direction.
func cutStream(t *testing.T, endings chan sessiontest.Ending) (*session.Stream, *sessiontest.Hop) {
	t.Helper()
	f := newForwarding(t, []int{9000}, nil)
	f.sandbox.Open(t, 9000, sessiontest.EchoRecording(endings))
	hop := sessiontest.NewHop(t, strings.TrimPrefix(f.url, "https://"))
	// The tenant's policy by now pins the guest's documents.
	client, err := session.NewClient(hop.URL, f.policy, sessiontest.Engine{}, f.access)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	stream, err := client.Dial(ctxT(t), 9000)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(stream, "half a question\n"); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len("half a question\n"))
	if _, err := io.ReadFull(stream, echo); err != nil || string(echo) != "half a question\n" {
		t.Fatalf("the sandbox echoed %q, %v", echo, err)
	}
	return stream, hop
}

// A stream has two ends that are not each other's: its sender ended it, or it
// was cut. Whoever carries the connection can end it between two TLS records,
// which crypto/tls reads as the end of the stream. Neither side takes that
// for the other's word: the sandbox's connection is reset, and the client
// reads an error.
func TestForwardTellsACutFromAnEnd(t *testing.T) {
	t.Run("the caller ends its input", func(t *testing.T) {
		endings := make(chan sessiontest.Ending, 1)
		stream, _ := cutStream(t, endings)
		if err := stream.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if e := ending(t, endings); e.Err != nil || e.Read != "half a question\n" {
			t.Fatalf("control: the sandbox read %q and then %v, want the end of its input", e.Read, e.Err)
		}
		// The sandbox closed in turn, and that is its end of the stream.
		if rest, err := io.ReadAll(stream); err != nil || len(rest) != 0 {
			t.Fatalf("control: the client read %q, %v, want the end of the stream", rest, err)
		}
	})

	t.Run("the connection is cut between two records", func(t *testing.T) {
		endings := make(chan sessiontest.Ending, 1)
		stream, hop := cutStream(t, endings)
		// Both of the hop's connections are closed, with nothing in flight:
		// each side's TLS session reads the end of its connection at a record
		// boundary.
		hop.Cut()
		if e := ending(t, endings); e.Err == nil {
			t.Fatalf("the sandbox read the end of its input, in order, after %q: its caller never ended it", e.Read)
		}
		n, err := stream.Read(make([]byte, 16))
		if n != 0 || !errors.Is(err, session.ErrStreamCut) {
			t.Fatalf("the client read %d bytes, %v, want ErrStreamCut", n, err)
		}
		if errors.Is(err, io.EOF) {
			t.Fatal("a cut stream reads as one that ended")
		}
	})

	t.Run("the caller aborts", func(t *testing.T) {
		endings := make(chan sessiontest.Ending, 1)
		stream, _ := cutStream(t, endings)
		if err := stream.Abort(); err != nil {
			t.Fatal(err)
		}
		if e := ending(t, endings); e.Err == nil {
			t.Fatal("the sandbox of an aborted stream read the end of its input, in order")
		}
	})

	t.Run("the sandbox breaks off", func(t *testing.T) {
		f := newForwarding(t, []int{9000}, nil)
		f.sandbox.Open(t, 9000, func(conn net.Conn) {
			_, _ = io.WriteString(conn, "half an answer")
			// Give the bytes time to leave before the reset drops what is unsent.
			_, _ = conn.Read(make([]byte, 1))
			_ = conn.(*net.TCPConn).SetLinger(0)
			_ = conn.Close()
		})
		stream, err := f.tenant.Dial(ctxT(t), 9000)
		if err != nil {
			t.Fatal(err)
		}
		defer stream.Close()
		_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
		got := make([]byte, len("half an answer"))
		if _, err := io.ReadFull(stream, got); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(stream, "x"); err != nil {
			t.Fatal(err)
		}
		if n, err := stream.Read(make([]byte, 16)); n != 0 || err == nil || errors.Is(err, io.EOF) {
			t.Fatalf("after the sandbox broke off the client read %d bytes, %v: want a failure", n, err)
		}
	})
}

// timedClientAt is a client for f's bound guest at url that notes the steps
// it takes, with opts.
func (f *forwarding) timedClientAt(t *testing.T, url string, opts ...session.ClientOption) (*session.Client, func() string) {
	t.Helper()
	var mu sync.Mutex
	var steps []string
	opts = append(opts, session.Timed(func(step string, _ time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		steps = append(steps, step)
	}))
	client, err := session.NewClient(url, f.policy, sessiontest.Engine{}, f.access, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client, func() string {
		mu.Lock()
		defer mu.Unlock()
		return strings.Join(steps, ", ")
	}
}

// echoed sends a line down a stream and wants it back.
func echoed(t *testing.T, conn net.Conn, line string) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, line); err != nil {
		t.Fatal(err)
	}
	if got, err := bufio.NewReader(conn).ReadString('\n'); err != nil || got != line {
		t.Fatalf("sent %q, the sandbox answered %q, %v", line, got, err)
	}
}

// A stream is a TLS session of its own. The first one of a client is the
// session its guest was attested on, so it costs the request that turns the
// connection into the stream and no more. The next one is a dial and a
// handshake, in which the verdict of the attestation still stands.
func TestStreamReportsItsSteps(t *testing.T) {
	f := newForwarding(t, []int{9000}, nil)
	f.sandbox.Open(t, 9000, sessiontest.Echo)
	way := sessiontest.NewHop(t, strings.TrimPrefix(f.url, "https://"))
	client, steps := f.timedClientAt(t, way.URL)
	conn, err := client.Dial(ctxT(t), 9000)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	echoed(t, conn, "one\n")
	want := "dial, serving_verdict, handshake, request /v1/attest, judgment, request /v1/forward"
	if got := steps(); got != want {
		t.Fatalf("steps: %s\n want: %s", got, want)
	}
	if n := way.Accepted(); n != 1 {
		t.Fatalf("an attestation and a stream opened %d connections, want 1", n)
	}
	second, err := client.Dial(ctxT(t), 9000)
	if err != nil {
		t.Fatalf("a second stream: %v", err)
	}
	defer second.Close()
	echoed(t, second, "two\n")
	if got := steps(); got != want+", dial, handshake, request /v1/forward" {
		t.Fatalf("steps after a second stream: %s", got)
	}
	if n := way.Accepted(); n != 2 {
		t.Fatalf("two streams opened %d connections in all, want 2", n)
	}
}

// A connection that ended while it waited for the client's next stream costs
// the stream a new connection and nothing else.
func TestStreamReplacesAConnectionThatEndedWhileItWaited(t *testing.T) {
	f := newForwarding(t, []int{9000}, nil)
	f.sandbox.Open(t, 9000, sessiontest.Echo)
	way := sessiontest.NewHop(t, strings.TrimPrefix(f.url, "https://"))
	client, steps := f.timedClientAt(t, way.URL)
	if _, err := client.Attest(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	if n := way.Cut(); n != 1 {
		t.Fatalf("the attestation opened %d connections", n)
	}
	conn, err := client.Dial(ctxT(t), 9000)
	if err != nil {
		t.Fatalf("a stream after the waiting connection was cut: %v", err)
	}
	defer conn.Close()
	echoed(t, conn, "one\n")
	if n := way.Accepted(); n != 2 {
		t.Fatalf("%d connections in all, want 2: %s", n, steps())
	}
	// The guest was asked for one stream: the cut request never reached it.
	if asked := f.sandbox.Asked(); !slices.Equal(asked, []int{9000}) {
		t.Fatalf("the agent connected to ports %v of the sandbox", asked)
	}
}

// A client that rests on a kept verdict reaches its guest before it asks it
// for anything: a handshake that must end at the verdict's key, on the
// connection its first stream then takes.
func TestReachHoldsTheGuestToTheKeptKey(t *testing.T) {
	f := newForwarding(t, []int{9000}, nil)
	f.sandbox.Open(t, 9000, sessiontest.Echo)
	if _, err := f.tenant.Attest(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	kept, ok := f.tenant.Verdict()
	if !ok {
		t.Fatal("the tenant's client has no verdict")
	}
	addr := strings.TrimPrefix(f.url, "https://")

	way := sessiontest.NewHop(t, addr)
	stranger, _ := f.timedClientAt(t, way.URL)
	if err := stranger.Reach(ctxT(t)); err == nil {
		t.Fatal("a client that pinned no key reached its guest")
	}
	if n := way.Accepted(); n != 0 {
		t.Fatalf("it opened %d connections", n)
	}

	way = sessiontest.NewHop(t, addr)
	client, steps := f.timedClientAt(t, way.URL, session.Kept(kept))
	if err := client.Reach(ctxT(t)); err != nil {
		t.Fatalf("Reach: %v", err)
	}
	if got := steps(); got != "dial, handshake" {
		t.Fatalf("reaching the guest, steps: %s", got)
	}
	conn, err := client.Dial(ctxT(t), 9000)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	echoed(t, conn, "one\n")
	if got := steps(); got != "dial, handshake, request /v1/forward" {
		t.Fatalf("a stream after reaching the guest, steps: %s", got)
	}
	if n := way.Accepted(); n != 1 {
		t.Fatalf("reaching the guest and a stream opened %d connections, want 1", n)
	}

	// A client that already has a connection waiting has reached its guest.
	way = sessiontest.NewHop(t, addr)
	twice, _ := f.timedClientAt(t, way.URL, session.Kept(kept))
	for i := 0; i < 2; i++ {
		if err := twice.Reach(ctxT(t)); err != nil {
			t.Fatalf("Reach %d: %v", i, err)
		}
	}
	if n := way.Accepted(); n != 1 {
		t.Fatalf("reaching twice opened %d connections, want 1", n)
	}

	// The bind names its guest's key under the tenant's signature, and a
	// verdict is taken only for that key. One that names another is no
	// verdict: the client attests its guest as if it had been given none.
	other, err := x509.MarshalPKIXPublicKey(&newECKey(t).PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	forged := *kept
	forged.InstanceKey = other
	misled, steps := f.timedClientAt(t, f.url, session.Kept(&forged))
	if misled.Pinned() {
		t.Fatal("a verdict for another key than the bind names was taken")
	}
	stream, err := misled.Dial(ctxT(t), 9000)
	if err != nil {
		t.Fatalf("a stream after a verdict that was not taken: %v", err)
	}
	defer stream.Close()
	echoed(t, stream, "three\n")
	if got := steps(); got != "dial, serving_verdict, handshake, request /v1/attest, judgment, request /v1/forward" {
		t.Fatalf("steps: %s", got)
	}

	// The verdict opens the guest it was reached on and no other: at another
	// guest's address the handshake refuses, and the client says why its
	// verdict should not be kept.
	elsewhere := newForwarding(t, []int{9000}, nil)
	lost, _ := f.timedClientAt(t, elsewhere.url, session.Kept(kept))
	if !lost.Pinned() || lost.AnotherKey() {
		t.Fatalf("before it connects: pinned %v, another key %v", lost.Pinned(), lost.AnotherKey())
	}
	if err := lost.Reach(ctxT(t)); !isVerdict(err) {
		t.Fatalf("another guest than the verdict's was reached: %v", err)
	}
	if !lost.AnotherKey() {
		t.Fatal("the client does not say that the guest presented another key")
	}
	if _, err := lost.Dial(ctxT(t), 9000); !isVerdict(err) {
		t.Fatalf("a stream to another guest than the verdict's: %v", err)
	}
	if asked := elsewhere.sandbox.Asked(); len(asked) != 0 {
		t.Fatalf("the other guest's sandbox was asked for ports %v", asked)
	}
}

// A stream the guest refuses on the connection that waited is not asked for
// again on another: the guest's answer arrived.
func TestRefusedStreamIsNotAskedForTwice(t *testing.T) {
	f := newForwarding(t, []int{9000}, nil)
	way := sessiontest.NewHop(t, strings.TrimPrefix(f.url, "https://"))
	client, steps := f.timedClientAt(t, way.URL)
	if _, err := client.Attest(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	// The bind opens the port and nothing listens on it.
	_, err := client.Dial(ctxT(t), 9000)
	assertStatus(t, err, http.StatusBadGateway)
	if n := way.Accepted(); n != 1 {
		t.Fatalf("a refused stream opened %d connections in all, want 1: %s", n, steps())
	}
	if asked := f.sandbox.Asked(); !slices.Equal(asked, []int{9000}) {
		t.Fatalf("the agent connected to ports %v of the sandbox", asked)
	}
}
