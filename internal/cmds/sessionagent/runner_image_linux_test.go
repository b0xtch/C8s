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
	"strings"
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
	if len(o.image.Entrypoint)+len(o.image.Cmd) == 0 {
		o.image.Cmd = []string{"/bin/sleep", "100000"}
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
	c.runner, c.stateDir, c.cgroup = imageRunner(t, c.harness, crun, nil)
	if o.tamper != nil {
		o.tamper(c)
	}
	return c
}

// imageRunner gives h's agent a runner of sandbox images, as a guest image
// with crun does: credentials on a RAM-backed path the sandbox's user can
// reach, the image on disk, and images the host's image store, if any.
func imageRunner(t *testing.T, h *harness, crun string, images *imagestore.Store) (runner *sessionagent.ImageRunner, stateDir, cgroup string) {
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
	runner, err = sessionagent.NewImageRunner(sessionagent.ImageRunnerConfig{
		StateDir: stateDir, RunDir: t.TempDir(), CredentialDir: h.credDir, CgroupParent: cgroup,
		PidsLimit: testPidsLimit, Crun: crun, PlainHTTP: func(string) bool { return true },
		Pull:   imagestore.PullLimits{Layers: 4, BlobBytes: 64 << 20, TotalBytes: 128 << 20},
		Unpack: imagestore.UnpackLimits{Entries: 1000, Bytes: 64 << 20},
		Images: images,
	}, bare)
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
		image:   ocispec.ImageConfig{Cmd: []string{"/bin/sh", "-c", "echo up > /tmp/started; exec /bin/sleep 100000"}, Env: []string{"FROM_IMAGE=1", "BOTH=image"}, WorkingDir: "/srv"},
		sandbox: session.Sandbox{Env: map[string]string{"FROM_DOC": "2", "BOTH": "doc"}},
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
			{`echo "$FROM_IMAGE $FROM_DOC $BOTH"`, "1 2 doc"},
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
		// The bracket keeps the pattern from matching the shell that carries it.
		if got := c.out(t, client, "ps | grep -c '[c]run' || true"); got != "0" {
			t.Errorf("the sandbox sees %s of the guest's processes", got)
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
		"a command the image does not have": {containerOptions{sandbox: session.Sandbox{Command: []string{"/bin/absent"}}}, "not found", true},
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
