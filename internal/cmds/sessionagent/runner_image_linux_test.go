//go:build linux

package sessionagent_test

import (
	"bytes"
	"context"
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
	"github.com/confidential-dot-ai/c8s/internal/imagestore"
	"github.com/confidential-dot-ai/c8s/internal/imagestore/imagestoretest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// These tests run a real container: crun, user namespaces, cgroups and mounts.
// They need root, crun on PATH and a static busybox to build an image from
// (C8S_TEST_BUSYBOX, default /usr/bin/busybox), and skip without them.

const testPidsLimit = 64

func containerFixtures(t *testing.T) (crun string, busybox []byte) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: the agent runs the sandbox container as the guest's root")
	}
	crun, err := exec.LookPath("crun")
	if err != nil {
		t.Skip("needs crun on PATH")
	}
	path := os.Getenv("C8S_TEST_BUSYBOX")
	if path == "" {
		path = "/usr/bin/busybox"
	}
	bin, err := elf.Open(path)
	if err != nil {
		t.Skipf("needs a static busybox (set C8S_TEST_BUSYBOX): %v", err)
	}
	defer bin.Close()
	if bin.Section(".interp") != nil {
		t.Skipf("%s is dynamically linked: the test image holds nothing else", path)
	}
	if busybox, err = os.ReadFile(path); err != nil {
		t.Fatal(err)
	}
	return crun, busybox
}

// sandboxInit is the program a container starts with, built once for the
// tests the way a guest image's build compiles it: static, since a
// container's root holds no library of the guest's. C8S_TEST_SANDBOX_INIT
// names one built already.
var sandboxInit = sync.OnceValues(func() (string, error) {
	if path := os.Getenv("C8S_TEST_SANDBOX_INIT"); path != "" {
		return path, nil
	}
	root, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/confidential-dot-ai/c8s").Output()
	if err != nil {
		return "", fmt.Errorf("find the module: %w", err)
	}
	dir, err := os.MkdirTemp("", "c8s-sandbox-init-")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "c8s-sandbox-init")
	build := exec.Command("go", "build", "-o", path, "./cmd/c8s-sandbox-init")
	build.Dir = strings.TrimSpace(string(root))
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build c8s-sandbox-init: %w\n%s", err, out)
	}
	// The container's user reaches it through a descriptor, and must be
	// allowed to run it.
	if err := os.Chmod(dir, 0o755); err != nil {
		return "", err
	}
	return path, nil
})

// container is a harness whose agent runs a sandbox image under crun.
type container struct {
	*harness
	runner   *sessionagent.ImageRunner
	registry *imagestoretest.Registry
	manifest ocispec.Descriptor
	stateDir string
	cgroup   string
}

type containerOptions struct {
	image   ocispec.ImageConfig
	sandbox session.Sandbox
	// egress is the sandbox's allowlist, nil for none.
	egress *session.Egress
	// forward opens ports of the sandbox to streams, nil for none.
	forward *session.Forward
	// tamper changes the registry after the image is stored.
	tamper func(c *container)
	// runtime is run in place of crun, when set.
	runtime string
	// cold has the runtime start every command when it comes, and none
	// ahead.
	cold bool
}

func mkdirTemp(t *testing.T, parent string, mode os.FileMode) string {
	t.Helper()
	dir, err := os.MkdirTemp(parent, "c8s-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
	return dir
}

func newContainer(t *testing.T, o containerOptions) *container {
	t.Helper()
	crun, busybox := containerFixtures(t)
	c := &container{registry: imagestoretest.NewRegistry(t)}
	// A test that gives its image a command has the session run it. Any
	// other names no process, as most sessions do: the image still holds a
	// command, which then does not run.
	if len(o.image.Entrypoint)+len(o.image.Cmd) == 0 {
		o.image.Cmd = []string{"/bin/sleep", "100000"}
	} else if o.sandbox.Process == "" {
		o.sandbox.Process = session.ProcessImage
	}
	c.manifest = c.registry.Image([][]byte{imagestoretest.BusyboxLayer(busybox)}, imagestoretest.ImageOptions{Config: &o.image})
	o.sandbox.Image = c.registry.Ref(c.manifest.Digest)
	c.harness = newHarness(t, func(b *session.BindOptions) {
		b.Policy.Sandbox, b.Policy.Egress, b.Policy.Forward = &o.sandbox, o.egress, o.forward
		if o.forward != nil {
			b.Policy.Access.Forward = []string{c.ownerPub}
		}
	})
	if o.runtime != "" {
		crun = o.runtime
	}
	c.runner, c.stateDir, c.cgroup = imageRunner(t, c.harness, crun, nil, func(cfg *sessionagent.ImageRunnerConfig) { cfg.ColdCommands = o.cold })
	if o.tamper != nil {
		o.tamper(c)
	}
	return c
}

// imageRunner gives h's agent a runner of sandbox images, as a guest image
// with crun does: credentials on a RAM-backed path the sandbox's user can
// reach, the image on disk, and images the host's image store, if any.
func imageRunner(t *testing.T, h *harness, crun string, images *imagestore.Store, configure ...func(*sessionagent.ImageRunnerConfig)) (runner *sessionagent.ImageRunner, stateDir, cgroup string) {
	t.Helper()
	h.credDir = filepath.Join(mkdirTemp(t, "/dev/shm", 0o755), "c8s", "credentials")
	h.cfg.CredentialDir = h.credDir
	stateDir = mkdirTemp(t, "/var/tmp", 0o700)
	cgroup = filepath.Join("/sys/fs/cgroup", filepath.Base(stateDir))
	if err := os.Mkdir(cgroup, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(cgroup) })
	if err := os.WriteFile(filepath.Join(cgroup, "cgroup.subtree_control"), []byte("+pids"), 0); err != nil {
		t.Fatal(err)
	}

	bare, err := sessionagent.NewProcessRunner(sessionagent.RunnerConfig{UID: -1, GID: -1, Home: h.home, CredentialDir: h.credDir})
	if err != nil {
		t.Fatal(err)
	}
	init, err := sandboxInit()
	if err != nil {
		t.Skipf("needs the sandbox's init: %v", err)
	}
	cfg := sessionagent.ImageRunnerConfig{
		StateDir: stateDir, RunDir: t.TempDir(), CredentialDir: h.credDir, CgroupParent: cgroup,
		PidsLimit: testPidsLimit, Crun: crun, SandboxInit: init, PlainHTTP: func(string) bool { return true },
		Pull:   imagestore.PullLimits{Layers: 4, BlobBytes: 64 << 20, TotalBytes: 128 << 20},
		Unpack: imagestore.UnpackLimits{Entries: 1000, Bytes: 64 << 20},
		Images: images,
	}
	for _, change := range configure {
		change(&cfg)
	}
	runner, err = sessionagent.NewImageRunner(cfg, bare)
	if err != nil {
		t.Fatal(err)
	}
	h.cfg.Runner = runner
	t.Cleanup(func() {
		if err := runner.Close(); err != nil {
			t.Errorf("close runner: %v", err)
		}
	})
	return runner, stateDir, cgroup
}

// sh runs a shell command in the sandbox through the agent's API.
func (c *container) sh(t *testing.T, client *session.Client, script string) *session.ExecResponse {
	t.Helper()
	resp, err := client.Exec(ctxT(t), session.ExecRequest{Argv: []string{"/bin/sh", "-c", script}})
	if err != nil {
		t.Fatalf("exec %q: %v", script, err)
	}
	return resp
}

func (c *container) out(t *testing.T, client *session.Client, script string) string {
	t.Helper()
	resp := c.sh(t, client, script)
	if resp.ExitCode != 0 {
		t.Fatalf("%q: exit %d, stderr %q", script, resp.ExitCode, resp.Stderr)
	}
	return strings.TrimSpace(string(resp.Stdout))
}

func ownerOf(t *testing.T, path string) (uid, gid uint32) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	return st.Uid, st.Gid
}

// The guest's path against a simulated TD and a real runtime: the image a
// bind names is pulled by digest, measured, started in a container, handed a
// credential and driven through the authenticated API.
func TestImageSandboxAttestReleaseExec(t *testing.T) {
	c := newContainer(t, containerOptions{
		image: ocispec.ImageConfig{Cmd: []string{"/bin/sh", "-c", "echo up > /tmp/started; exec /bin/sleep 100000"}, Env: []string{"FROM_IMAGE=1", "BOTH=image"}, WorkingDir: "/srv"},
	})
	c.start(t)
	// Every step of the admission is timed, and a registry that answers the
	// first time costs no wait.
	if got := stepNames(sessionagent.AdmissionOf(c.agent)); got != "resolve,fetch,unpack,own,clear,measure,start" {
		t.Errorf("admission steps: %s", got)
	}
	client := c.client(t, c.owner)

	att, err := client.Attest(ctxT(t))
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	image := c.manifest.Digest.String()
	if att.Phase != session.PhaseRunning || len(att.Events) != 3 || att.Events[2] != image {
		t.Fatalf("attestation: phase %s, events %v, image %s", att.Phase, att.Events, image)
	}
	want := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(c.bundle.LaunchKey), []string{session.DocumentDigest(c.bundle.Launch), session.DocumentDigest(c.bind.Raw), image})
	if got := register(t, c.td); !bytes.Equal(got, want[:]) {
		t.Fatalf("register %x, want %x", got, want)
	}

	secret := []byte("s3cr3t-token")
	if _, err := client.PutCredential(ctxT(t), "test-token", secret); err != nil {
		t.Fatalf("PutCredential: %v", err)
	}
	if uid, gid := ownerOf(t, filepath.Join(c.credDir, "test-token")); uid != imagestore.IDBase || gid != imagestore.IDBase {
		t.Errorf("credential is owned by %d:%d, want the container's root %d", uid, gid, imagestore.IDBase)
	}
	if got := c.out(t, client, `cat "$C8S_CREDENTIALS_DIR/test-token"`); got != string(secret) {
		t.Errorf("the sandbox read %q as its credential", got)
	}
	if resp := c.sh(t, client, `echo x > "$C8S_CREDENTIALS_DIR/mine"`); resp.ExitCode == 0 {
		t.Error("the sandbox can write to its credential directory")
	}

	t.Run("context", func(t *testing.T) {
		for _, check := range [][2]string{
			// Start returns once the container runs, which can be before its
			// first statement has.
			{"i=0; while [ ! -f /tmp/started ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i+1)); done; cat /tmp/started", "up"},
			{"cat /proc/1/comm", "sleep"},
			// The sandbox's own process is filtered, not only the commands.
			{"grep '^Seccomp:' /proc/1/status | grep -c 2", "1"},
			{"id -u; id -g", "0\n0"},
			{"pwd", "/srv"},
			{`echo "$FROM_IMAGE $BOTH"`, "1 image"},
			{"stat -c %u:%g /home/app/data", "1000:1000"},
			{"cat /home/app/data", "mine"},
		} {
			if got := c.out(t, client, check[0]); got != check[1] {
				t.Errorf("%q printed %q, want %q", check[0], got, check[1])
			}
		}
		mapping := strings.Join(strings.Fields(c.out(t, client, "cat /proc/self/uid_map")), " ")
		if mapping != fmt.Sprintf("0 %d %d", imagestore.IDBase, imagestore.IDCount) {
			t.Errorf("uid map %q", mapping)
		}
		// Groups are mapped the same, and may be set: an image that drops
		// to a user of its own sets that user's groups.
		groups := strings.Join(strings.Fields(c.out(t, client, "cat /proc/self/gid_map /proc/self/setgroups")), " ")
		if groups != fmt.Sprintf("0 %d %d allow", imagestore.IDBase, imagestore.IDCount) {
			t.Errorf("gid map and setgroups %q", groups)
		}
		resp, err := client.Exec(ctxT(t), session.ExecRequest{Argv: []string{"/bin/sh", "-c", `pwd; echo "$BOTH $MINE"`}, Cwd: "/tmp", Env: map[string]string{"BOTH": "request", "MINE": "3"}})
		if err != nil || strings.TrimSpace(string(resp.Stdout)) != "/tmp\nrequest 3" {
			t.Errorf("request cwd and env: %q, %v", resp.Stdout, err)
		}
		if uid, _ := ownerOf(t, filepath.Join(c.stateDir, "rootfs/home/app/data")); uid != imagestore.IDBase+1000 {
			t.Errorf("the image's uid 1000 is uid %d in the guest", uid)
		}
	})

	t.Run("isolation", func(t *testing.T) {
		// The layer carried two device entries. Neither exists, in the guest's
		// view of the tree or in the sandbox's.
		for _, name := range []string{"srv/tdx_guest", "dev/tdx_guest"} {
			if _, err := os.Lstat(filepath.Join(c.stateDir, "rootfs", name)); !os.IsNotExist(err) {
				t.Errorf("%s was unpacked: %v", name, err)
			}
		}
		for script, why := range map[string]string{
			"ls /srv/tdx_guest":        "a device entry of the image is visible",
			"mknod /tmp/node c 10 257": "the sandbox made a device node",
			// Nothing but the seccomp profile stands in the way of this one here:
			// a user namespace needs no capability, and this machine sets no limit.
			"unshare -U true":                      "the sandbox made a user namespace of its own",
			"echo 0 > /sys/fs/cgroup/cgroup.procs": "the sandbox wrote to its cgroup",
			"echo 1 > /proc/sys/kernel/sysrq":      "the sandbox wrote to /proc/sys",
		} {
			if resp := c.sh(t, client, script); resp.ExitCode == 0 {
				t.Errorf("%s (%q exited 0: %s)", why, script, resp.Stdout)
			}
		}
		if got := c.out(t, client, "ls -A /sys/kernel/config | wc -l"); got != "0" {
			t.Errorf("the report interface's directory shows %s entries", got)
		}
		status := c.out(t, client, "grep -E '^(CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs|Seccomp):' /proc/self/status")
		// CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL, SETGID, SETUID, SETPCAP,
		// SYS_CHROOT and SETFCAP, and nothing else.
		const caps = "00000000800401fb"
		for _, line := range []string{"CapPrm:\t" + caps, "CapEff:\t" + caps, "CapBnd:\t" + caps, "CapInh:\t0000000000000000", "CapAmb:\t0000000000000000", "NoNewPrivs:\t1", "Seccomp:\t2"} {
			if !strings.Contains(status, line) {
				t.Errorf("process status lacks %q:\n%s", line, status)
			}
		}
		var options string
		for _, line := range strings.Split(c.out(t, client, "cat /proc/self/mountinfo"), "\n") {
			if f := strings.Fields(line); len(f) > 5 && f[4] == "/" {
				options = f[5]
			}
		}
		if !strings.Contains(options, "nodev") || !strings.Contains(options, "nosuid") {
			t.Errorf("root filesystem mount options %q", options)
		}
		// The sandbox has a process namespace of its own, and nothing of the
		// guest's is in it: not this process, which is the guest's agent
		// here, and no more than the few the sandbox runs. The runtime is in
		// it for the moment it takes to become the next process that waits
		// for a command, as it is when it starts a command itself.
		outside, err := os.Readlink("/proc/self/ns/pid")
		if err != nil {
			t.Fatal(err)
		}
		if inside := c.out(t, client, "readlink /proc/self/ns/pid"); !strings.HasPrefix(inside, "pid:[") || inside == outside {
			t.Errorf("the sandbox's process namespace is %q, and the guest's is %q", inside, outside)
		}
		// The bracket keeps the pattern from matching the shell that carries it.
		if got := c.out(t, client, "ps -o pid,comm,args | grep -c -e '[s]essionagent' -e '[.]test' || true"); got != "0" {
			t.Errorf("the sandbox sees %s of the guest's processes", got)
		}
		if got, err := strconv.Atoi(c.out(t, client, "ls -d /proc/[0-9]* | wc -l")); err != nil || got < 2 || got > 12 {
			t.Errorf("the sandbox sees %d processes (%v): its own are a handful", got, err)
		}
		limit, err := os.ReadFile(filepath.Join(c.cgroup, "sandbox", "pids.max"))
		if err != nil || strings.TrimSpace(string(limit)) != fmt.Sprint(testPidsLimit) {
			t.Errorf("pids.max = %q, %v", limit, err)
		}
	})

	t.Run("commands", func(t *testing.T) {
		resp, err := client.Exec(ctxT(t), session.ExecRequest{Argv: []string{"/bin/sh", "-c", "cat; echo err >&2; exit 7"}, Stdin: []byte("in")})
		if err != nil || resp.ExitCode != 7 || string(resp.Stdout) != "in" || string(resp.Stderr) != "err\n" {
			t.Errorf("exec = %+v, %v", resp, err)
		}
		for name, tc := range map[string]struct {
			req  session.ExecRequest
			exit int
		}{
			"no such command":  {session.ExecRequest{Argv: []string{"/bin/absent"}}, 127},
			"not executable":   {session.ExecRequest{Argv: []string{"/etc/passwd"}}, 126},
			"no such cwd":      {session.ExecRequest{Argv: []string{"/bin/true"}, Cwd: "/absent"}, 127},
			"killed by signal": {session.ExecRequest{Argv: []string{"/bin/sh", "-c", "kill -TERM $$"}}, 143},
			"exits 255":        {session.ExecRequest{Argv: []string{"/bin/sh", "-c", "exit 255"}}, 255},
		} {
			resp, err := client.Exec(ctxT(t), tc.req)
			if err != nil || resp.ExitCode != tc.exit {
				t.Errorf("%s: %+v, %v, want exit %d", name, resp, err, tc.exit)
			}
			if tc.exit == 126 || tc.exit == 127 {
				if len(resp.Stderr) == 0 {
					t.Errorf("%s: no reason on stderr", name)
				}
			}
		}
	})

	t.Run("a command that outlives its limit is killed with everything it started", func(t *testing.T) {
		const id = "0123456789abcdef0123456789abcdef"
		began := time.Now()
		resp, err := client.Exec(ctxT(t), session.ExecRequest{ID: id, Argv: []string{"/bin/sh", "-c", "sleep 300 & sleep 300"}, TimeoutSeconds: 1})
		if err != nil || !resp.TimedOut || resp.ExitCode != 137 {
			t.Fatalf("exec = %+v, %v", resp, err)
		}
		if took := time.Since(began); took > 10*time.Second {
			t.Errorf("a one second limit took %s", took)
		}
		if got := c.out(t, client, "ps | grep -c '[s]leep 300' || true"); got != "0" {
			t.Errorf("%s sleepers outlived the command", got)
		}
		if _, err := os.Stat(filepath.Join(c.cgroup, "sandbox", "exec-"+id)); !os.IsNotExist(err) {
			t.Errorf("the command's cgroup is still there: %v", err)
		}
	})

	t.Run("the guest ends with its sandbox", func(t *testing.T) {
		done := make(chan error, 1)
		go func() { done <- c.runner.Wait(context.Background()) }()
		select {
		case err := <-done:
			t.Fatalf("Wait returned while the sandbox runs: %v", err)
		case <-time.After(200 * time.Millisecond):
		}
		if err := os.WriteFile(filepath.Join(c.cgroup, "sandbox", "cgroup.kill"), []byte("1"), 0); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "status 137") {
				t.Errorf("Wait = %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("Wait did not return after the sandbox was killed")
		}
		if _, err := client.Exec(ctxT(t), session.ExecRequest{Argv: []string{"/bin/true"}}); err == nil {
			t.Error("a command ran in a sandbox that has ended")
		}
	})
}

// A sandbox whose own process ends is known to have ended at once, and its
// runner closes at once over it, with a command's process waiting in it or
// without one: a guest's end waits on nothing of the runtime's.
func TestImageSandboxEndIsKnownAtOnce(t *testing.T) {
	for _, cold := range []bool{false, true} {
		t.Run(map[bool]string{false: "a command's process waits", true: "none waits"}[cold], func(t *testing.T) {
			c := newContainer(t, containerOptions{cold: cold, image: ocispec.ImageConfig{
				Cmd: []string{"/bin/sh", "-c", "until [ -e /tmp/end ]; do sleep 0.01; done; exit 3"},
			}})
			c.start(t)
			client := c.client(t, c.owner)
			c.out(t, client, "true")
			if !cold {
				c.awaitWarm(t)
			}
			c.out(t, client, ": > /tmp/end")
			began := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := c.runner.Wait(ctx); err == nil || !strings.Contains(err.Error(), "status 3") {
				t.Fatalf("Wait = %v", err)
			}
			if took := time.Since(began); took > 500*time.Millisecond {
				t.Errorf("the sandbox's end was known %s after the command that had its process end", took)
			}
			// What its guest then waits for before it ends.
			began = time.Now()
			if err := c.runner.Close(); err != nil {
				t.Errorf("close runner: %v", err)
			}
			if took := time.Since(began); took > 500*time.Millisecond {
				t.Errorf("the runner took %s to close over a sandbox that had ended", took)
			}
		})
	}
}

// awaitWarm waits until a command's process waits in the sandbox for the
// next command.
func (c *container) awaitWarm(t *testing.T) {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(2 * time.Millisecond) {
		if waiting, _ := c.runner.WarmCommands(); waiting {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no process was started ahead for the next command")
		}
	}
}

func (c *container) warmUsed() int64 {
	_, used := c.runner.WarmCommands()
	return used
}

// A command runs as a process the runtime started before the command came:
// in the container, in a cgroup of its own, as the image's user, under the
// container's capabilities and system call filter. What a caller sees of a
// command is what it sees of one the runtime starts when asked: its
// directory and environment, its input and output, its status, a reason when
// it could not start, and its end at its limit with everything it started.
func TestCommandsRunAsProcessesStartedAhead(t *testing.T) {
	c := newContainer(t, containerOptions{
		image: ocispec.ImageConfig{Env: []string{"FROM_IMAGE=1", "BOTH=image"}, WorkingDir: "/srv"},
	})
	c.start(t)
	client := c.client(t, c.owner)
	if _, err := client.Attest(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	// run is one command that must run as a process started ahead.
	run := func(what string, req session.ExecRequest) *session.ExecResponse {
		t.Helper()
		c.awaitWarm(t)
		before := c.warmUsed()
		resp, err := client.Exec(ctxT(t), req)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if c.warmUsed() != before+1 {
			t.Fatalf("%s: the command was started by the runtime, with a process waiting for it", what)
		}
		return resp
	}
	sh := func(script string) session.ExecRequest {
		return session.ExecRequest{Argv: []string{"/bin/sh", "-c", script}}
	}

	resp := run("directory and environment", session.ExecRequest{
		Argv: []string{"/bin/sh", "-c", `pwd; echo "$FROM_IMAGE $BOTH $MINE"; echo "$C8S_CREDENTIALS_DIR"`}, Cwd: "/tmp", Env: map[string]string{"BOTH": "request", "MINE": "3"},
	})
	if got := strings.TrimSpace(string(resp.Stdout)); resp.ExitCode != 0 || got != "/tmp\n1 request 3\n"+c.credDir {
		t.Errorf("request directory and environment: exit %d, %q, stderr %q", resp.ExitCode, got, resp.Stderr)
	}
	resp = run("the image's directory and environment", sh(`pwd; echo "$BOTH"`))
	if got := strings.TrimSpace(string(resp.Stdout)); got != "/srv\nimage" {
		t.Errorf("default directory and environment: %q", got)
	}
	// A command named without a directory is found in the PATH of its
	// environment, as the runtime finds one.
	if resp := run("a command found by its name", session.ExecRequest{Argv: []string{"socket-inet"}}); resp.ExitCode != 0 {
		t.Errorf("a command named without a directory: %+v", resp)
	}
	resp = run("input, output and status", session.ExecRequest{Argv: []string{"/bin/sh", "-c", "cat; echo err >&2; exit 7"}, Stdin: []byte("in")})
	if resp.ExitCode != 7 || string(resp.Stdout) != "in" || string(resp.Stderr) != "err\n" {
		t.Errorf("input, output and status: %+v", resp)
	}
	big := bytes.Repeat([]byte("0123456789abcdef"), 16<<10)
	resp = run("input larger than a pipe holds, unread", session.ExecRequest{Argv: []string{"/bin/true"}, Stdin: big})
	if resp.ExitCode != 0 {
		t.Errorf("a command that reads none of its input: %+v", resp)
	}
	resp = run("input larger than a pipe holds, read", session.ExecRequest{Argv: []string{"/bin/sh", "-c", "wc -c"}, Stdin: big})
	if got := strings.TrimSpace(string(resp.Stdout)); got != fmt.Sprint(len(big)) {
		t.Errorf("a command read %s bytes of %d", got, len(big))
	}

	status := strings.TrimSpace(string(run("its own limits", sh("grep -E '^(CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs|Seccomp):' /proc/self/status; cat /proc/self/uid_map")).Stdout))
	const caps = "00000000800401fb"
	for _, line := range []string{"CapPrm:\t" + caps, "CapEff:\t" + caps, "CapBnd:\t" + caps, "CapInh:\t0000000000000000", "CapAmb:\t0000000000000000", "NoNewPrivs:\t1", "Seccomp:\t2"} {
		if !strings.Contains(status, line) {
			t.Errorf("a command's process status lacks %q:\n%s", line, status)
		}
	}
	if !strings.Contains(strings.Join(strings.Fields(status), " "), fmt.Sprintf("0 %d %d", imagestore.IDBase, imagestore.IDCount)) {
		t.Errorf("a command's user namespace is not the sandbox's:\n%s", status)
	}
	// The command inherits neither descriptor the runtime preserved for
	// the init: its standard three, and the one that lists them.
	if got := strings.TrimSpace(string(run("descriptors", session.ExecRequest{Argv: []string{"/bin/ls", "/proc/self/fd"}}).Stdout)); strings.Join(strings.Fields(got), " ") != "0 1 2 3" {
		t.Errorf("a command's descriptors: %q", got)
	}
	for probe, want := range map[string]int{"/bin/socket-inet": 0, "/bin/socket-vsock": int(syscall.EPERM)} {
		if resp := run(probe, session.ExecRequest{Argv: []string{probe}}); resp.ExitCode != want {
			t.Errorf("%s exited %d, want %d: the system call filter", probe, resp.ExitCode, want)
		}
	}

	for name, tc := range map[string]struct {
		req  session.ExecRequest
		exit int
	}{
		"no such command":         {session.ExecRequest{Argv: []string{"/bin/absent"}}, 127},
		"no such command by name": {session.ExecRequest{Argv: []string{"c8s-absent"}}, 127},
		"not executable":          {session.ExecRequest{Argv: []string{"/etc/passwd"}}, 126},
		"no such cwd":             {session.ExecRequest{Argv: []string{"/bin/true"}, Cwd: "/absent"}, 127},
		"killed by signal":        {sh("kill -TERM $$"), 143},
		"exits 255":               {sh("exit 255"), 255},
		"exits 127 by itself":     {sh("exit 127"), 127},
		"exits 126 by itself":     {sh("exit 126"), 126},
	} {
		resp := run(name, tc.req)
		if resp.ExitCode != tc.exit {
			t.Errorf("%s: %+v, want exit %d", name, resp, tc.exit)
		}
		told := strings.HasPrefix(name, "no such") || name == "not executable"
		if told != (len(resp.Stderr) > 0) {
			t.Errorf("%s: a reason on stderr: %q", name, resp.Stderr)
		}
	}

	const id = "0123456789abcdef0123456789abcdef"
	began := time.Now()
	resp = run("a command past its limit", session.ExecRequest{ID: id, Argv: []string{"/bin/sh", "-c", "sleep 300 & sleep 300"}, TimeoutSeconds: 1})
	if !resp.TimedOut || resp.ExitCode != 137 {
		t.Fatalf("a command past its limit: %+v", resp)
	}
	if took := time.Since(began); took > 12*time.Second {
		t.Errorf("a one second limit took %s", took)
	}
	if got := c.out(t, client, "ps | grep -c '[s]leep 300' || true"); got != "0" {
		t.Errorf("%s sleepers outlived the command", got)
	}
	// Of the cgroups below the sandbox's, only the waiting process's is left.
	c.awaitWarm(t)
	left, err := filepath.Glob(filepath.Join(c.cgroup, "sandbox", "exec-*"))
	if err != nil || len(left) != 1 || !strings.Contains(filepath.Base(left[0]), "ahead") {
		t.Errorf("command cgroups left behind: %v, %v", left, err)
	}

	// More commands at once than processes wait: each is run, by whichever
	// way starts it.
	var group sync.WaitGroup
	results := make([]string, 6)
	for i := range results {
		group.Go(func() {
			resp, err := client.Exec(ctxT(t), sh(fmt.Sprintf("echo %d", i)))
			if err == nil && resp.ExitCode == 0 {
				results[i] = strings.TrimSpace(string(resp.Stdout))
			}
		})
	}
	group.Wait()
	for i, got := range results {
		if got != fmt.Sprint(i) {
			t.Errorf("command %d of six at once printed %q", i, got)
		}
	}
}

// While it waits for a command, the process started ahead holds a socket to
// the agent, and the tenant's code runs beside it under the same user. That
// code cannot attach to it or open what it holds: the process marks itself
// undumpable, and the sandbox has no capability to trace. As the sandbox's
// root it can still list the numbers of the process's descriptors, which
// tell it nothing. It can end the process, as it can end anything of its
// user's, and the next command is then started another way and is none the
// wiser.
func TestWaitingProcessIsOutOfTheTenantsReach(t *testing.T) {
	c := newContainer(t, containerOptions{})
	c.start(t)
	client := c.client(t, c.owner)
	if _, err := client.Attest(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	// A command looks for the process that waits beside it, which is the one
	// whose command line is the descriptor it was started from, and tries
	// to open what that process holds. The command may have been the
	// waiting process itself a moment ago, so it first gives the next one
	// time to be started.
	probe := `sleep 0.5
for p in /proc/[0-9]*; do
	[ "$(tr '\0' ' ' < $p/cmdline 2>/dev/null)" = "/proc/self/fd/3 " ] || continue
	echo "found ${p#/proc/}"
	cat $p/environ > /dev/null 2>&1; echo "environment $?"
	cat $p/maps > /dev/null 2>&1; echo "memory-map $?"
	head -c 1 $p/exe > /dev/null 2>&1; echo "program $?"
	readlink $p/fd/4 > /dev/null 2>&1; echo "socket's-name $?"
	cat $p/fd/4 > /dev/null 2>&1 < /dev/null; echo "socket $?"
	cat $p/fd/0 > /dev/null 2>&1 < /dev/null; echo "input $?"
done`
	resp, err := client.Exec(ctxT(t), session.ExecRequest{Argv: []string{"/bin/sh", "-c", probe}})
	if err != nil || resp.ExitCode != 0 {
		t.Fatalf("the probe: %+v, %v", resp, err)
	}
	report := string(resp.Stdout)
	if !strings.Contains(report, "found ") {
		t.Fatalf("no waiting process was found in the sandbox: %q", report)
	}
	for _, line := range strings.Split(strings.TrimSpace(report), "\n") {
		what, status, _ := strings.Cut(line, " ")
		if what != "found" && status == "0" {
			t.Errorf("a command opened the %s of the process that waits beside it: %q", what, report)
		}
	}
	// The same command can open its own, so the probe tells a refusal
	// from a file that is not there.
	if got := c.out(t, client, "ls /proc/self/fd > /dev/null && cat /proc/self/maps > /dev/null && echo own"); got != "own" {
		t.Fatalf("a command cannot open its own files: %q", got)
	}

	// Ended by the tenant's own code: the next commands still run, and
	// say what they were asked to say.
	c.awaitWarm(t)
	if _, err := client.Exec(ctxT(t), session.ExecRequest{Argv: []string{"/bin/sh", "-c", `for p in /proc/[0-9]*; do if [ "$(tr '\0' ' ' < $p/cmdline 2>/dev/null)" = "/proc/self/fd/3 " ]; then kill -9 ${p#/proc/}; fi; done; true`}}); err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		resp, err := client.Exec(ctxT(t), session.ExecRequest{Argv: []string{"/bin/sh", "-c", fmt.Sprintf("echo after-%d", i)}})
		if err != nil || resp.ExitCode != 0 || strings.TrimSpace(string(resp.Stdout)) != fmt.Sprintf("after-%d", i) {
			t.Fatalf("command %d after the waiting process was killed: %+v, %v", i, resp, err)
		}
	}
	c.awaitWarm(t)
}

// A runner that starts no process ahead runs every command by the runtime,
// as before.
func TestCommandsStartedByTheRuntimeWhenAsked(t *testing.T) {
	c := newContainer(t, containerOptions{cold: true})
	c.start(t)
	client := c.client(t, c.owner)
	if got := c.out(t, client, "echo cold"); got != "cold" {
		t.Fatalf("a command: %q", got)
	}
	if waiting, used := c.runner.WarmCommands(); waiting || used != 0 {
		t.Fatalf("a runner that starts none ahead has one waiting (%v) or used %d", waiting, used)
	}
	if left, _ := filepath.Glob(filepath.Join(c.cgroup, "sandbox", "exec-*")); len(left) != 0 {
		t.Fatalf("command cgroups left behind: %v", left)
	}
}

// An image that names a user runs as that user, and its credentials are that
// user's: container root holds no capability over files outside its own ids.
func TestImageSandboxRunsAsTheImageUser(t *testing.T) {
	c := newContainer(t, containerOptions{image: ocispec.ImageConfig{User: "1000:1000", WorkingDir: "/home/app"}})
	c.start(t)
	client := c.client(t, c.owner)
	if _, err := client.PutCredential(ctxT(t), "test-token", []byte("for-app")); err != nil {
		t.Fatal(err)
	}
	if uid, gid := ownerOf(t, filepath.Join(c.credDir, "test-token")); uid != imagestore.IDBase+1000 || gid != imagestore.IDBase+1000 {
		t.Errorf("credential is owned by %d:%d", uid, gid)
	}
	if got := c.out(t, client, `id -u; id -g; cat "$C8S_CREDENTIALS_DIR/test-token"; echo; cat data`); got != "1000\n1000\nfor-app\nmine" {
		t.Errorf("as the image's user: %q", got)
	}
	status := c.out(t, client, "grep -E '^(CapPrm|CapEff):' /proc/self/status")
	if strings.Count(status, "0000000000000000") != 2 {
		t.Errorf("a non-root sandbox holds capabilities:\n%s", status)
	}
}

// A sandbox leaves its guest through the agent's proxy and by no other
// road. vsock would be one: its other end is whatever the host listens with,
// the quoting service among it, and no network namespace keeps a socket
// family out. The seccomp profile does: a vsock socket is refused, where the
// same program is given a socket of a family every sandbox has.
func TestImageSandboxCannotOpenVsock(t *testing.T) {
	c := newContainer(t, containerOptions{})
	c.start(t)
	client := c.client(t, c.owner)
	for probe, want := range map[string]int{"/bin/socket-inet": 0, "/bin/socket-vsock": int(syscall.EPERM)} {
		resp, err := client.Exec(ctxT(t), session.ExecRequest{Argv: []string{probe}})
		if err != nil {
			t.Fatalf("%s: %v", probe, err)
		}
		// EPERM is the profile's answer. A kernel without the family would
		// say EAFNOSUPPORT, and prove nothing about the profile.
		if resp.ExitCode != want {
			t.Errorf("%s exited %d, want %d", probe, resp.ExitCode, want)
		}
	}
}

// Whatever the registry or the image gets wrong, nothing of the image runs.
// What Prepare refuses is never measured.
func TestImageSandboxRefusals(t *testing.T) {
	// Same length, one byte changed: only the digest can tell.
	flipLayer := func(c *container) {
		for digest, blob := range c.registry.Blobs {
			if blob.MediaType == ocispec.MediaTypeImageLayerGzip {
				blob.Data = bytes.Clone(blob.Data)
				blob.Data[len(blob.Data)/2] ^= 1
				c.registry.Blobs[digest] = blob
			}
		}
	}
	for name, tc := range map[string]struct {
		o    containerOptions
		want string
		// measured: the refusal comes from the runtime, after the image was
		// verified and extended into the register.
		measured bool
	}{
		"a layer the registry changed":      {containerOptions{tamper: flipLayer}, "unexpected commit digest", false},
		"a user that is not numeric":        {containerOptions{image: ocispec.ImageConfig{User: "app"}}, "numeric", false},
		"a command the image does not have": {containerOptions{image: ocispec.ImageConfig{Cmd: []string{"/bin/absent"}}}, "not found", true},
	} {
		t.Run(name, func(t *testing.T) {
			c := newContainer(t, tc.o)
			err := c.admitErr(t)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the bind ended the guest with %v, want %q", err, tc.want)
			}
			// The bind is measured either way. The image is measured only once
			// it is verified.
			bound := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(c.bundle.LaunchKey), []string{session.DocumentDigest(c.bundle.Launch), session.DocumentDigest(c.bind.Raw)})
			if moved := !bytes.Equal(bound[:], register(t, c.td)); moved != tc.measured {
				t.Errorf("the image was measured: %v, want %v", moved, tc.measured)
			}
			if _, err := os.Stat(filepath.Join(c.cgroup, "sandbox")); !os.IsNotExist(err) {
				t.Errorf("a container was left behind: %v", err)
			}
		})
	}
}

// A sandbox that ends at once ends the guest, whichever side of Start's
// return it lands on.
func TestImageSandboxThatExitsAtOnce(t *testing.T) {
	c := newContainer(t, containerOptions{image: ocispec.ImageConfig{Cmd: []string{"/bin/sh", "-c", "exit 3"}}})
	if err := c.admitErr(t); err != nil {
		if !strings.Contains(err.Error(), "status 3") {
			t.Fatalf("the bind ended the guest with %v", err)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.runner.Wait(ctx); err == nil || !strings.Contains(err.Error(), "status 3") {
		t.Fatalf("Wait = %v", err)
	}
}
