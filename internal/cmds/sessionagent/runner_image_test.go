package sessionagent

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

const testCredentialDir = "/run/c8s/credentials"

func TestSandboxProcessCommandAndArgs(t *testing.T) {
	image := ocispec.ImageConfig{Entrypoint: []string{"/entry"}, Cmd: []string{"default"}}
	for _, c := range []struct {
		name string
		w    session.Sandbox
		want []string
	}{
		{"image defaults", session.Sandbox{}, []string{"/entry", "default"}},
		{"command drops the default arguments", session.Sandbox{Command: []string{"/other"}}, []string{"/other"}},
		{"args replace the default arguments", session.Sandbox{Args: []string{"a", "b"}}, []string{"/entry", "a", "b"}},
		{"command and args", session.Sandbox{Command: []string{"/other"}, Args: []string{"a"}}, []string{"/other", "a"}},
	} {
		p, err := sandboxProcess(image, &c.w, testCredentialDir)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !slices.Equal(p.Args, c.want) {
			t.Errorf("%s: argv %v, want %v", c.name, p.Args, c.want)
		}
	}
	if _, err := sandboxProcess(ocispec.ImageConfig{}, &session.Sandbox{}, testCredentialDir); err == nil {
		t.Error("a sandbox with no command at all was accepted")
	}
}

func TestSandboxProcessEnvironment(t *testing.T) {
	image := ocispec.ImageConfig{Entrypoint: []string{"/e"}, Env: []string{"A=1", "B=2", "malformed"}, WorkingDir: "/srv"}
	w := &session.Sandbox{Env: map[string]string{"B": "3", "C": "4", "C8S_CREDENTIALS_DIR": "/elsewhere"}}
	p, err := sandboxProcess(image, w, testCredentialDir)
	if err != nil {
		t.Fatal(err)
	}
	// Sorted as whole strings, as the bare-command runner sorts its own.
	const proxy, direct = "http://127.0.0.1:3128", "localhost,127.0.0.1,::1"
	want := []string{
		"A=1", "B=3", "C8S_CREDENTIALS_DIR=" + testCredentialDir, "C=4",
		"HTTPS_PROXY=" + proxy, "HTTP_PROXY=" + proxy, "NODE_USE_ENV_PROXY=1", "NO_PROXY=" + direct, "PATH=" + defaultSandboxPath,
		"http_proxy=" + proxy, "https_proxy=" + proxy, "no_proxy=" + direct,
	}
	if !slices.Equal(p.Env, want) {
		t.Fatalf("env %v, want %v", p.Env, want)
	}
	if p.Cwd != "/srv" {
		t.Fatalf("cwd %q", p.Cwd)
	}

	// The image's own proxy is for some other network and is replaced. The
	// document's is its author's choice and stands.
	image.Env = []string{"HTTPS_PROXY=http://corp.example:8080", "HTTP_PROXY=http://corp.example:8080"}
	w = &session.Sandbox{Env: map[string]string{"HTTP_PROXY": "http://127.0.0.1:9999"}}
	if p, err = sandboxProcess(image, w, testCredentialDir); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(p.Env, "HTTPS_PROXY="+proxy) || !slices.Contains(p.Env, "HTTP_PROXY=http://127.0.0.1:9999") {
		t.Fatalf("env %v", p.Env)
	}

	image.Env = []string{"PATH=/opt/bin"}
	w = &session.Sandbox{WorkingDir: "/work"}
	if p, err = sandboxProcess(image, w, testCredentialDir); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(p.Env, "PATH=/opt/bin") || p.Cwd != "/work" {
		t.Fatalf("env %v cwd %q", p.Env, p.Cwd)
	}
}

func TestRegistryUnreachable(t *testing.T) {
	dial := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ENETUNREACH}
	for name, tc := range map[string]struct {
		err  error
		want bool
	}{
		"no route yet":             {fmt.Errorf("resolve: %w", &url.Error{Op: "Head", URL: "https://r/v2/", Err: dial}), true},
		"no resolver yet":          {&url.Error{Op: "Head", URL: "https://r/v2/", Err: &net.OpError{Op: "dial", Err: &net.DNSError{Err: "no such host", Name: "r"}}}, true},
		"a bare resolver failure":  {&net.DNSError{Err: "server misbehaving", Name: "r"}, true},
		"not a TLS server":         {&url.Error{Op: "Head", URL: "https://r/v2/", Err: errors.New("http: server gave HTTP response to HTTPS client")}, false},
		"a certificate it refuses": {&url.Error{Op: "Head", URL: "https://r/v2/", Err: &tls.CertificateVerificationError{Err: errors.New("unknown authority")}}, false},
		"a connection that broke":  {&url.Error{Op: "Get", URL: "https://r/v2/", Err: &net.OpError{Op: "read", Err: syscall.ECONNRESET}}, false},
		"a wrong digest":           {errors.New("unexpected commit digest"), false},
	} {
		if got := registryUnreachable(tc.err); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}

func TestSandboxUser(t *testing.T) {
	for spec, want := range map[string]specs.User{
		"":          {},
		"1000":      {UID: 1000},
		"1000:2000": {UID: 1000, GID: 2000},
		"65535:0":   {UID: 65535},
	} {
		got, err := sandboxUser(spec)
		if err != nil || got.UID != want.UID || got.GID != want.GID {
			t.Errorf("%q: %+v, %v", spec, got, err)
		}
	}
	for _, spec := range []string{"nobody", "65536", "1000:staff", "1000:65536", "-1", "1000:"} {
		if _, err := sandboxUser(spec); err == nil {
			t.Errorf("%q was accepted", spec)
		}
	}
}

func TestSandboxProcessHoldsNoPrivilegeOverTheGuest(t *testing.T) {
	p, err := sandboxProcess(ocispec.ImageConfig{Cmd: []string{"/bin/sh"}}, &session.Sandbox{}, testCredentialDir)
	if err != nil {
		t.Fatal(err)
	}
	if !p.NoNewPrivileges {
		t.Error("noNewPrivileges is off")
	}
	c := p.Capabilities
	if len(c.Inheritable) != 0 || len(c.Ambient) != 0 {
		t.Errorf("inheritable %v, ambient %v", c.Inheritable, c.Ambient)
	}
	for _, set := range [][]string{c.Bounding, c.Effective, c.Permitted} {
		if !slices.Equal(set, sandboxCapabilities) {
			t.Errorf("capability set %v", set)
		}
		// Any of these would let the sandbox reconfigure or inspect the guest.
		for _, banned := range []string{"CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_MKNOD", "CAP_SYS_PTRACE", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_BPF", "CAP_DAC_READ_SEARCH"} {
			if slices.Contains(set, banned) {
				t.Errorf("%s is granted", banned)
			}
		}
	}
	if p.OOMScoreAdj == nil || *p.OOMScoreAdj <= 0 {
		t.Errorf("OOM score adjustment %v", p.OOMScoreAdj)
	}
}

func TestSandboxSpecIsolation(t *testing.T) {
	p := &specs.Process{Args: []string{"/bin/sh"}}
	made := sandboxNamespaces{User: "/proc/1/fd/7", Network: "/proc/1/fd/8"}
	s := sandboxSpec(p, "/var/lib/c8s-session/rootfs", "sbx-1", "/system.slice/agent/sandbox", 4096,
		sandboxMounts{CredentialDir: testCredentialDir, ResolvConf: "/run/resolv.conf"}, made)

	// The user namespace exists, with its ids mapped by the agent that made
	// it: a mapping here would be one the runtime writes itself.
	if len(s.Linux.UIDMappings)+len(s.Linux.GIDMappings) != 0 {
		t.Errorf("id mappings %v %v", s.Linux.UIDMappings, s.Linux.GIDMappings)
	}
	var namespaces []string
	for _, ns := range s.Linux.Namespaces {
		namespaces = append(namespaces, string(ns.Type)+"="+ns.Path)
	}
	// The user and the network namespace are the two the agent made, and
	// every other is new: none of the guest's own is the sandbox's.
	slices.Sort(namespaces)
	if got := strings.Join(namespaces, ","); got != "cgroup=,ipc=,mount=,network=/proc/1/fd/8,pid=,user=/proc/1/fd/7,uts=" {
		t.Errorf("namespaces %s", got)
	}
	// Nothing runs for the runtime on the way: no hook, of any kind. And the
	// runtime sets nothing in a network namespace that is not its own making.
	if s.Hooks != nil || len(s.Linux.Sysctl) != 0 {
		t.Errorf("hooks %+v, sysctls %v", s.Hooks, s.Linux.Sysctl)
	}
	if r := s.Linux.Resources; r == nil || len(r.Devices) != 0 || r.Pids == nil || *r.Pids.Limit != 4096 {
		t.Errorf("resources %+v", r)
	}
	for _, path := range []string{"/sys/kernel/config", "/sys/devices/virtual/misc/tdx_guest", "/sys/devices/virtual/misc/sev-guest", "/proc/kcore"} {
		if !slices.Contains(s.Linux.MaskedPaths, path) {
			t.Errorf("%s is not masked", path)
		}
	}
	if s.Root.Path != "/var/lib/c8s-session/rootfs" || s.Root.Readonly || s.Hostname != "sbx-1" || s.Linux.CgroupsPath != "/system.slice/agent/sandbox" {
		t.Errorf("root %+v hostname %q cgroup %q", s.Root, s.Hostname, s.Linux.CgroupsPath)
	}

	mounts := map[string]specs.Mount{}
	for _, m := range s.Mounts {
		mounts[m.Destination] = m
	}
	cred := mounts[testCredentialDir]
	if cred.Source != testCredentialDir || cred.Type != "bind" {
		t.Errorf("credential mount %+v", cred)
	}
	for _, opt := range []string{"ro", "nosuid", "nodev", "noexec"} {
		if !slices.Contains(cred.Options, opt) {
			t.Errorf("credential mount lacks %s", opt)
		}
	}
	if m := mounts["/etc/resolv.conf"]; m.Source != "/run/resolv.conf" || !slices.Contains(m.Options, "ro") {
		t.Errorf("resolver mount %+v", m)
	}

	bare := sandboxSpec(p, "/r", "h", "/c", 0, sandboxMounts{CredentialDir: testCredentialDir}, made)
	if bare.Linux.Resources != nil {
		t.Errorf("resources without a limit: %+v", bare.Linux.Resources)
	}
	for _, m := range bare.Mounts {
		if m.Destination == "/etc/resolv.conf" {
			t.Error("resolver mounted without a source")
		}
	}
}

func TestExecProcessRunsInTheSandboxContext(t *testing.T) {
	main, err := sandboxProcess(ocispec.ImageConfig{Cmd: []string{"/bin/app"}, Env: []string{"A=1"}, User: "1000:1000", WorkingDir: "/srv"},
		&session.Sandbox{}, testCredentialDir)
	if err != nil {
		t.Fatal(err)
	}
	p := execProcess(main, &session.ExecRequest{Argv: []string{"ls", "-l"}, Env: map[string]string{"A": "2", "B": "3"}, Cwd: "/tmp"})
	if !slices.Equal(p.Args, []string{"ls", "-l"}) || p.Cwd != "/tmp" {
		t.Errorf("argv %v cwd %q", p.Args, p.Cwd)
	}
	if !slices.Contains(p.Env, "A=2") || !slices.Contains(p.Env, "B=3") || !slices.Contains(p.Env, "C8S_CREDENTIALS_DIR="+testCredentialDir) {
		t.Errorf("env %v", p.Env)
	}
	if p.User.UID != 1000 || p.User.GID != 1000 || !p.NoNewPrivileges || !slices.Equal(p.Capabilities.Bounding, sandboxCapabilities) {
		t.Errorf("exec left the sandbox's context: %+v", p)
	}
	if !slices.Equal(main.Args, []string{"/bin/app"}) || !slices.Contains(main.Env, "A=1") || main.Cwd != "/srv" {
		t.Errorf("exec changed the main process: %+v", main)
	}

	plain := execProcess(main, &session.ExecRequest{Argv: []string{"true"}})
	if plain.Cwd != "/srv" || !slices.Equal(plain.Env, main.Env) {
		t.Errorf("defaults: cwd %q env %v", plain.Cwd, plain.Env)
	}
}
