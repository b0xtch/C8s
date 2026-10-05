package sessionagent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/confidential-dot-ai/c8s/internal/imagestore"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// The sandbox runs as root of a user namespace. That namespace is what keeps
// it from the TDX guest device and from everything else the guest's root
// owns: the guest kernel has no bpf, so there is no device cgroup to lean on.
//
// The capabilities are the ones that make root useful over the sandbox's own
// files and processes. Docker's default set also has network and device
// capabilities. The sandbox has none: its network namespace holds a loopback
// interface and the agent's proxy, and it is given nothing to change that
// with. CAP_SYS_ADMIN stays out, so it cannot make a second network namespace
// to administer. It could from inside a second user namespace, which the
// kernel refuses to make once the agent holds the sandbox's
// (closeUserNamespaces).
var sandboxCapabilities = []string{
	"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL",
	"CAP_SETFCAP", "CAP_SETGID", "CAP_SETPCAP", "CAP_SETUID", "CAP_SYS_CHROOT",
}

var (
	// The last three are the guest's attestation interfaces. File permissions
	// already keep the sandbox out of them; masking keeps them out of sight.
	sandboxMaskedPaths = []string{
		"/proc/acpi", "/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/sched_debug",
		"/proc/scsi", "/proc/timer_list", "/proc/timer_stats", "/sys/firmware",
		"/sys/kernel/config", "/sys/devices/virtual/misc/tdx_guest", "/sys/devices/virtual/misc/sev-guest",
	}
	sandboxReadonlyPaths = []string{"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"}
)

const (
	defaultSandboxPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	// sandboxOOMScoreAdj puts the sandbox ahead of every guest service when
	// memory runs out, as execOOMScoreAdj does for a bare command.
	sandboxOOMScoreAdj = 500
)

// sandboxProcess is what everything in the sandbox runs as: the image's
// user, environment and working directory, with the sandbox's capabilities.
// Its arguments are the session's own process: the image's command when the
// bind names that, and none otherwise, for a sandbox whose init stays.
func sandboxProcess(image ocispec.ImageConfig, w *session.Sandbox, credentialDir string) (*specs.Process, error) {
	var argv []string
	if w.Process == session.ProcessImage {
		if argv = slices.Concat(image.Entrypoint, image.Cmd); len(argv) == 0 {
			return nil, errors.New("the bind names the image's command as the session's process, and the image names none")
		}
	}
	user, err := sandboxUser(image.User)
	if err != nil {
		return nil, err
	}
	env := map[string]string{"PATH": defaultSandboxPath}
	for _, kv := range image.Env {
		if k, v, ok := strings.Cut(kv, "="); ok && k != "" {
			env[k] = v
		}
	}
	// After the image's: a proxy an image names for some other network is
	// unreachable here.
	for k, v := range egressProxyEnv() {
		env[k] = v
	}
	env["C8S_CREDENTIALS_DIR"] = credentialDir
	cwd := "/"
	if image.WorkingDir != "" {
		cwd = image.WorkingDir
	}
	score := sandboxOOMScoreAdj
	return &specs.Process{
		User: user,
		Args: argv,
		Env:  environList(env),
		Cwd:  cwd,
		Capabilities: &specs.LinuxCapabilities{
			Bounding: sandboxCapabilities, Effective: sandboxCapabilities, Permitted: sandboxCapabilities,
		},
		NoNewPrivileges: true,
		OOMScoreAdj:     &score,
	}, nil
}

// execProcess is one command in the sandbox's context: its user, limits and
// environment, with the request's own variables and working directory on top.
func execProcess(main *specs.Process, req *session.ExecRequest) *specs.Process {
	p := *main
	p.Args = req.Argv
	if req.Cwd != "" {
		p.Cwd = req.Cwd
	}
	if len(req.Env) > 0 {
		env := make(map[string]string, len(main.Env)+len(req.Env))
		for _, kv := range main.Env {
			k, v, _ := strings.Cut(kv, "=")
			env[k] = v
		}
		for k, v := range req.Env {
			env[k] = v
		}
		p.Env = environList(env)
	}
	return &p
}

// sandboxUser reads an image's USER. Only numeric ids are understood: a name
// would have to be looked up in the image's own passwd file.
func sandboxUser(spec string) (specs.User, error) {
	if spec == "" {
		return specs.User{}, nil
	}
	uidPart, gidPart, hasGID := strings.Cut(spec, ":")
	uid, err := strconv.ParseUint(uidPart, 10, 32)
	if err != nil || uid >= imagestore.IDCount {
		return specs.User{}, fmt.Errorf("image user %q must be a numeric id below %d", spec, imagestore.IDCount)
	}
	gid := uint64(0)
	if hasGID {
		if gid, err = strconv.ParseUint(gidPart, 10, 32); err != nil || gid >= imagestore.IDCount {
			return specs.User{}, fmt.Errorf("image user %q must be a numeric id below %d", spec, imagestore.IDCount)
		}
	}
	return specs.User{UID: uint32(uid), GID: uint32(gid)}, nil
}

func environList(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

// registryUnreachable reports whether a pull failed before any registry
// answered: no route yet, no resolver yet, nothing listening. Only that is
// worth waiting out. A registry that answered, even with a TLS failure, will
// answer the same way again.
func registryUnreachable(err error) bool {
	var dns *net.DNSError
	var op *net.OpError
	return errors.As(err, &dns) || (errors.As(err, &op) && op.Op == "dial")
}

const (
	// pullRetryFor is how long a pull waits for a registry it cannot reach.
	// The agent serves before the guest's network is up.
	pullRetryFor = 2 * time.Minute
	// A network that is nearly up is up within a moment: the first wait is
	// short, and each one after it twice as long, up to pullMaxWait.
	pullFirstWait = 100 * time.Millisecond
	pullMaxWait   = 8 * time.Second
)

// pullWaiting pulls ref and waits out a registry it cannot reach. What that
// cost, and how long the pull that worked took over each of its steps, is
// recorded for the admission ctx belongs to.
func pullWaiting(ctx context.Context, puller *imagestore.Puller, ref string, log *slog.Logger) (*imagestore.Image, error) {
	began := time.Now()
	deadline := began.Add(pullRetryFor)
	for failed, wait := 0, pullFirstWait; ; failed, wait = failed+1, min(2*wait, pullMaxWait) {
		attempt := time.Now()
		img, err := puller.Pull(ctx, ref)
		if err == nil {
			if failed > 0 {
				recordStep(ctx, stepRegistryWait, attempt.Sub(began))
			}
			if img.FromRegistry == 0 {
				recordStep(ctx, stepStore, img.Resolved+img.Fetched)
			} else {
				recordStep(ctx, stepResolve, img.Resolved)
				recordStep(ctx, stepFetch, img.Fetched)
			}
			return img, nil
		}
		if !registryUnreachable(err) || time.Now().Add(wait).After(deadline) {
			return nil, fmt.Errorf("pull image: %w", err)
		}
		log.Warn("registry not reachable, retrying", "error", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
}

// egressProxyEnv points the usual clients at the agent's proxy, which is the
// sandbox's one way out of its network namespace.
func egressProxyEnv() map[string]string {
	proxy := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(EgressProxyPort))
	const direct = "localhost,127.0.0.1,::1"
	return map[string]string{
		"HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "http_proxy": proxy, "https_proxy": proxy,
		"NO_PROXY": direct, "no_proxy": direct,
		// Node reads the variables above only when told to.
		"NODE_USE_ENV_PROXY": "1",
	}
}

// sandboxResolvConf is the container's resolv.conf. There is no resolver in
// its network namespace, and with no nameserver line a lookup fails at once
// against its own loopback, where waiting on the image's would time out.
const sandboxResolvConf = `# This sandbox has no resolver. Connections leave through the proxy named in
# HTTPS_PROXY and HTTP_PROXY, which resolves names itself.
`

// sandboxMounts is what the runtime config binds in from the guest.
type sandboxMounts struct {
	// CredentialDir is bound read-only at the same path.
	CredentialDir string
	// ResolvConf, when set, is bound over /etc/resolv.conf.
	ResolvConf string
}

// sandboxNamespaces names the two namespaces the agent made for the sandbox
// before it knew one, as paths the runtime opens.
type sandboxNamespaces struct {
	// User maps the container's ids 0 to 65535 to the guest's 100000 and up.
	User string
	// Network is owned by User, and holds a loopback interface that is up
	// and the agent's proxy listening on it.
	Network string
}

// sandboxSpec is the complete runtime config of the sandbox container.
func sandboxSpec(process *specs.Process, rootfs, hostname, cgroupsPath string, pidsLimit int64, m sandboxMounts, ns sandboxNamespaces) *specs.Spec {
	mounts := []specs.Mount{
		{Destination: "/proc", Type: "proc", Source: "proc"},
		{Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
		{Destination: "/dev/pts", Type: "devpts", Source: "devpts", Options: []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"}},
		{Destination: "/dev/shm", Type: "tmpfs", Source: "shm", Options: []string{"nosuid", "noexec", "nodev", "mode=1777"}},
		{Destination: "/dev/mqueue", Type: "mqueue", Source: "mqueue", Options: []string{"nosuid", "noexec", "nodev"}},
		{Destination: "/sys", Type: "sysfs", Source: "sysfs", Options: []string{"nosuid", "noexec", "nodev", "ro"}},
		{Destination: "/sys/fs/cgroup", Type: "cgroup", Source: "cgroup", Options: []string{"nosuid", "noexec", "nodev", "relatime", "ro"}},
		{Destination: m.CredentialDir, Type: "bind", Source: m.CredentialDir, Options: []string{"rbind", "ro", "nosuid", "nodev", "noexec"}},
	}
	if m.ResolvConf != "" {
		mounts = append(mounts, specs.Mount{Destination: "/etc/resolv.conf", Type: "bind", Source: m.ResolvConf, Options: []string{"bind", "ro"}})
	}
	// No device rules, here or ever: crun would need bpf to apply them.
	var resources *specs.LinuxResources
	if pidsLimit > 0 {
		resources = &specs.LinuxResources{Pids: &specs.LinuxPids{Limit: &pidsLimit}}
	}
	return &specs.Spec{
		Version:  specs.Version,
		Process:  process,
		Root:     &specs.Root{Path: rootfs},
		Hostname: hostname,
		Mounts:   mounts,
		Linux: &specs.Linux{
			// The user and the network namespace exist already, and the
			// runtime joins them: it maps no ids, runs no hook and sets
			// nothing in the network. Nothing of the guest's network is in
			// that namespace, neither its interfaces nor its loopback
			// services nor its abstract unix sockets. The rest the runtime
			// makes, inside that user namespace.
			Namespaces: []specs.LinuxNamespace{
				{Type: specs.UserNamespace, Path: ns.User}, {Type: specs.NetworkNamespace, Path: ns.Network},
				{Type: specs.PIDNamespace}, {Type: specs.MountNamespace}, {Type: specs.IPCNamespace},
				{Type: specs.UTSNamespace}, {Type: specs.CgroupNamespace},
			},
			CgroupsPath:   cgroupsPath,
			Resources:     resources,
			MaskedPaths:   sandboxMaskedPaths,
			ReadonlyPaths: sandboxReadonlyPaths,
		},
	}
}
