//go:build linux

package sessionagent_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// TestMain lets the test binary stand in for the agent's own binary, which
// the runner starts once more in the namespaces it makes for a sandbox.
func TestMain(m *testing.M) {
	if mode, ok := strings.CutPrefix(filepath.Base(os.Args[0]), fakeRuntimePrefix); ok {
		os.Exit(fakeRuntime(mode, os.Args[1:]))
	}
	if len(os.Args) == 3 && os.Args[1] == "session-agent" && os.Args[2] == "hold" {
		if err := sessionagent.Hold(os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	// The limit the agent sets on user namespaces is the whole machine's. A
	// test writes it to a file of its own.
	limit, err := os.CreateTemp("", "max_user_namespaces")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_ = limit.Close()
	sessionagent.SetUserNamespaceLimit(limit.Name())
	code := m.Run()
	_ = os.Remove(limit.Name())
	os.Exit(code)
}

// Where outsideServer answers. The near address is on a link of this
// machine's own, which makes it a private destination to the proxy. The far
// one is routed through it, as a public destination is through a gateway.
const (
	outsideNear = "198.51.100.2:8080"
	outsideFar  = "203.0.113.10:8080"
)

// outsideServer is an HTTP server that is not on this machine: in a network
// namespace of its own, reached over a veth pair. The proxy refuses every
// address of the machine it runs on, so a destination it may dial has to be
// somewhere else. It returns the far address.
func outsideServer(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("needs ip to build a network namespace for a destination outside this machine")
	}
	const ns, here, there = "c8s-test-out", "c8s-out0", "c8s-out1"
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	_ = exec.Command("ip", "netns", "del", ns).Run()
	run("netns", "add", ns)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
	run("link", "add", here, "type", "veth", "peer", "name", there, "netns", ns)
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", here).Run() })
	run("addr", "add", "198.51.100.1/30", "dev", here)
	run("link", "set", here, "up")
	run("netns", "exec", ns, "ip", "addr", "add", "198.51.100.2/30", "dev", there)
	run("netns", "exec", ns, "ip", "link", "set", there, "up")
	run("netns", "exec", ns, "ip", "link", "set", "lo", "up")
	run("netns", "exec", ns, "ip", "addr", "add", "203.0.113.10/32", "dev", "lo")
	run("route", "add", "203.0.113.10/32", "via", "198.51.100.2")

	// The test binary serves from inside that namespace: busybox there would
	// need its own copy, and this process has the HTTP server already.
	helper := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run", "^TestHelperOutsideServer$")
	helper.Env = append(os.Environ(), "C8S_TEST_OUTSIDE_SERVER=:8080")
	helper.Stderr = os.Stderr
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = helper.Process.Kill()
		_ = helper.Wait()
	})
	for i := 0; i < 100; i++ {
		if conn, err := net.Dial("tcp", outsideFar); err == nil {
			conn.Close()
			return outsideFar
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the outside server never answered")
	return ""
}

// TestHelperOutsideServer is outsideServer's process, not a test.
func TestHelperOutsideServer(t *testing.T) {
	addr := os.Getenv("C8S_TEST_OUTSIDE_SERVER")
	if addr == "" {
		t.Skip("run by outsideServer")
	}
	_ = http.ListenAndServe(addr, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("from outside\n"))
	}))
}

// The sandbox's network is a loopback interface and the agent's proxy.
// Nothing of the machine the agent runs on is in it, and the proxy is no way
// back: it dials anywhere but that machine.
func TestImageSandboxNetwork(t *testing.T) {
	c := newContainer(t, containerOptions{})
	outside := outsideServer(t)
	c.start(t)
	client := c.client(t, c.owner)

	if got := c.out(t, client, "ls /sys/class/net"); got != "lo" {
		t.Errorf("the sandbox's interfaces: %q, want lo alone", got)
	}
	if got := c.out(t, client, "cat /sys/class/net/lo/operstate; ip -o -4 addr show dev lo | wc -l"); !strings.HasSuffix(got, "\n1") {
		t.Errorf("the sandbox's loopback: %q", got)
	}
	// Its own loopback works: a listener of its own answers it.
	if got := c.out(t, client, "(echo pong | nc -l -p 9000 >/dev/null &) ; sleep 0.3; nc -w 3 127.0.0.1 9000 </dev/null"); got != "pong" {
		t.Errorf("a listener on the sandbox's loopback answered %q", got)
	}
	if got := c.out(t, client, "cat /etc/resolv.conf | grep -c '^nameserver' || true"); got != "0" {
		t.Errorf("the sandbox's resolv.conf names %s resolvers", got)
	}
	if got := c.out(t, client, `echo "$HTTP_PROXY $https_proxy $NO_PROXY"`); got != "http://127.0.0.1:3128 http://127.0.0.1:3128 localhost,127.0.0.1,::1" {
		t.Errorf("proxy environment %q", got)
	}

	// Out, through the proxy and no other way.
	if got := c.out(t, client, "wget -q -O - http://"+outside+"/"); got != "from outside" {
		t.Errorf("through the proxy: %q", got)
	}
	if resp := c.sh(t, client, "http_proxy= HTTP_PROXY= wget -q -T 3 -O - http://"+outside+"/"); resp.ExitCode == 0 {
		t.Errorf("the sandbox reached %s without the proxy: %q", outside, resp.Stdout)
	}
	// The same server at its address on this machine's own link, which is
	// also the next hop of a route: a private network, and no policy names it.
	resp := c.sh(t, client, "wget -q -T 3 -O - http://"+outsideNear+"/ 2>&1")
	if resp.ExitCode == 0 || !strings.Contains(string(resp.Stdout), "403") {
		t.Errorf("http://%s/ with no policy: exit %d, %q, want a 403", outsideNear, resp.ExitCode, resp.Stdout)
	}

	// The registry the image came from listens on this machine's loopback,
	// which is the guest's own in a real guest. Not directly, and not through
	// the proxy, by address or by name.
	registry := c.registry.Host
	_, port, _ := net.SplitHostPort(registry)
	for _, target := range []string{registry, "localhost:" + port, "0.0.0.0:" + port} {
		resp := c.sh(t, client, "no_proxy= NO_PROXY= wget -q -T 3 -O - http://"+target+"/v2/ 2>&1")
		if resp.ExitCode == 0 || !strings.Contains(string(resp.Stdout), "403") {
			t.Errorf("http://%s/ through the proxy: exit %d, %q, want a 403", target, resp.ExitCode, resp.Stdout)
		}
	}
	if resp := c.sh(t, client, "nc -w 3 "+strings.Replace(registry, ":", " ", 1)+" </dev/null"); resp.ExitCode == 0 {
		t.Errorf("the sandbox connected to %s on the machine's loopback", registry)
	}
}

// dialPort opens a stream to a port of the sandbox. A sandbox that answers
// one connection at a time listens again after each, so a port with no
// listener for a moment is asked again.
func dialPort(t *testing.T, client *session.Client, port int) net.Conn {
	t.Helper()
	for attempt := 0; ; attempt++ {
		conn, err := client.Dial(ctxT(t), port)
		if err == nil {
			t.Cleanup(func() { _ = conn.Close() })
			return conn
		}
		if !isStatus(err, http.StatusBadGateway) || attempt >= 100 {
			t.Fatalf("open a stream to the sandbox's port %d: %v", port, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A stream reaches a port of a real sandbox from outside it, and what
// arrives there comes from the sandbox's own loopback. The image's user is
// unprivileged and holds no capability over the network, and still listens
// on port 80: the namespace is the sandbox's alone. The agent's own
// listener there opens to no stream.
func TestImageSandboxForward(t *testing.T) {
	c := newContainer(t, containerOptions{
		image:   ocispec.ImageConfig{User: "1000:1000", Cmd: []string{"/bin/sh", "-c", "while true; do nc -l -p 80 -e /bin/cat; done"}},
		forward: &session.Forward{Ports: []int{80, 9000}},
	})
	c.start(t)
	client := c.client(t, c.owner)
	if got := c.out(t, client, "id -u; cat /proc/sys/net/ipv4/ip_unprivileged_port_start"); got != "1000\n0" {
		t.Fatalf("the sandbox's user and its first unprivileged port: %q, want 1000 and 0", got)
	}

	conn := dialPort(t, client, 80)
	if _, err := io.WriteString(conn, "ping\n"); err != nil {
		t.Fatal(err)
	}
	// While the stream is open, the sandbox's namespace holds both of its
	// ends: the listener's, and the socket the agent made there. Each has the
	// namespace's own loopback for a peer, and no address of the machine the
	// agent runs on. A listener on every address shows IPv4 peers as mapped.
	sockets := c.out(t, client, "/bin/busybox netstat -tn")
	var accepted, dialed string
	for _, line := range strings.Split(sockets, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[5] != "ESTABLISHED" {
			continue
		}
		local, peer := strings.TrimPrefix(fields[3], "::ffff:"), strings.TrimPrefix(fields[4], "::ffff:")
		switch {
		case local == "127.0.0.1:80":
			accepted = peer
		case peer == "127.0.0.1:80":
			dialed = local
		}
	}
	if !strings.HasPrefix(accepted, "127.0.0.1:") || accepted != dialed {
		t.Errorf("the sandbox's listener has the peer %q and the socket dialed to it is %q, want one address on the sandbox's loopback:\n%s", accepted, dialed, sockets)
	}
	halfClose(t, conn)
	if got := readAll(t, conn); got != "ping\n" {
		t.Fatalf("the sandbox answered %q", got)
	}

	// Larger than any buffer on the way, out and back, unchanged.
	payload := bytes.Repeat([]byte("0123456789abcdef"), 1<<16)
	big := dialPort(t, client, 80)
	sent := make(chan error, 1)
	go func() {
		_, err := big.Write(payload)
		if err == nil {
			err = big.(interface{ CloseWrite() error }).CloseWrite()
		}
		sent <- err
	}()
	_ = big.SetReadDeadline(time.Now().Add(30 * time.Second))
	got, err := io.ReadAll(big)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("1 MiB came back as %d bytes, %v", len(got), err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}

	// A port the document lists and nothing listens on.
	_, err = client.Dial(ctxT(t), 9000)
	var closed *session.StatusError
	if !errors.As(err, &closed) || closed.Status != http.StatusBadGateway || closed.Code != types.ErrorCodePortUnreachable {
		t.Errorf("a listed port with no listener: %v", err)
	}
	// The agent's proxy listens in this namespace and answers the sandbox.
	// No document lists its port, and no stream opens to it.
	if got := c.out(t, client, "echo | nc -w 3 127.0.0.1 3128 | head -1"); !strings.HasPrefix(got, "HTTP/1.1 400") {
		t.Fatalf("control: the proxy answered the sandbox %q", got)
	}
	_, err = client.Dial(ctxT(t), session.SandboxProxyPort)
	assertStatus(t, err, http.StatusForbidden)
}

// With an egress policy, the proxy carries what the policy names and nothing
// else. An address the policy names is reached although it is on a private
// network.
func TestImageSandboxEgressPolicy(t *testing.T) {
	c := newContainer(t, containerOptions{
		image:  ocispec.ImageConfig{},
		egress: &session.Egress{Allow: []string{outsideNear}},
	})
	outside := outsideServer(t)
	c.start(t)
	client := c.client(t, c.owner)
	if got := c.out(t, client, "wget -q -O - http://"+outsideNear+"/"); got != "from outside" {
		t.Errorf("an address the policy names: %q", got)
	}
	for _, other := range []string{"198.51.100.2:8081", outside} {
		resp := c.sh(t, client, "wget -q -T 3 -O - http://"+other+"/ 2>&1")
		if resp.ExitCode == 0 || !strings.Contains(string(resp.Stdout), "403") {
			t.Errorf("%s, which the policy does not name: exit %d, %q, want a 403", other, resp.ExitCode, resp.Stdout)
		}
	}
}
