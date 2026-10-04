//go:build linux

package sessionagent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/imagestore"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// sandboxNet is where a sandbox's container runs: a user namespace with the
// container's id range, and a network namespace it owns that holds a loopback
// interface and the agent's egress proxy, and nothing else.
//
// The agent makes both itself, when it starts and before any sandbox is
// named, so that starting a sandbox makes neither. A process is started in
// new namespaces, they are held open by descriptor, and the process is ended:
// a namespace lasts as long as something holds it. The container runtime is
// then told to join them. They are what the runtime would have made: a
// network namespace created together with its user namespace is owned by it,
// so the container's root may mount a sysfs that shows this network alone.
//
// A socket stays in the namespace it was made in, so the proxy accepts in the
// sandbox's namespace and dials from the guest's.
type sandboxNet struct {
	user, network *os.File
	listener      net.Listener

	mu     sync.Mutex
	server *http.Server
}

// holdCommand is what the agent's executable is run as to stand in new
// namespaces until the agent holds them: `c8s session-agent hold`.
const holdCommand = "hold"

// ownExecutable is the running program, to whoever may run it: the kernel
// follows it to the file itself, through no directory.
const ownExecutable = "/proc/self/exe"

// userNamespaceLimit is how many user namespaces the guest may hold.
var userNamespaceLimit = "/proc/sys/user/max_user_namespaces"

// closeUserNamespaces has the kernel make no user namespace from here on, in
// the guest or nested in one that exists. The sandbox's is made before this
// is called, and it is the only one a session guest has a use for: in a second
// one, nested in its own, the sandbox would be root with every capability.
// The agent sets the limit, once it holds the sandbox's. As a limit of one in
// the image's sysctl files it was in force while the guest booted, when other
// services of its root make a user namespace for a moment, and the agent was
// then refused its own.
func closeUserNamespaces() error {
	if err := os.WriteFile(userNamespaceLimit, []byte("0"), 0); err != nil {
		return fmt.Errorf("close the guest to further user namespaces: %w", err)
	}
	return nil
}

// newSandboxNet makes the namespaces and prepares the network one. The
// agent's own executable is run once more for the moment it takes.
func newSandboxNet() (_ *sandboxNet, err error) {
	mapping := []syscall.SysProcIDMap{{ContainerID: 0, HostID: imagestore.IDBase, Size: imagestore.IDCount}}
	holder := exec.Command(ownExecutable, "session-agent", holdCommand)
	holder.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: mapping,
		GidMappings: mapping,
		// As a runtime leaves a namespace it makes: an image that drops to a
		// user of its own sets that user's groups.
		GidMappingsEnableSetgroups: true,
	}
	stdin, err := holder.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err := holder.Start(); err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("start a process in new namespaces: %w", err)
	}
	// It waits for its input to end, and has served once the descriptors
	// below are open. It is the guest's root still, which the new user
	// namespace maps to nothing, and holds no capability outside that
	// namespace: it reaches what any user of the guest reaches.
	defer func() {
		_ = stdin.Close()
		_ = holder.Process.Kill()
		_ = holder.Wait()
	}()
	n := &sandboxNet{}
	defer func() {
		if err != nil {
			_ = n.Close()
		}
	}()
	if n.user, err = os.Open(fmt.Sprintf("/proc/%d/ns/user", holder.Process.Pid)); err != nil {
		return nil, fmt.Errorf("hold the sandbox's user namespace: %w", err)
	}
	if n.network, err = os.Open(fmt.Sprintf("/proc/%d/ns/net", holder.Process.Pid)); err != nil {
		return nil, fmt.Errorf("hold the sandbox's network namespace: %w", err)
	}
	if err = closeUserNamespaces(); err != nil {
		return nil, err
	}
	err = inNetworkNamespace(n.network, func() error {
		interfaces, err := net.Interfaces()
		if err != nil {
			return fmt.Errorf("list the sandbox's interfaces: %w", err)
		}
		if err := onlyLoopback(interfaces); err != nil {
			return err
		}
		if err := loopbackUp(); err != nil {
			return fmt.Errorf("bring up the sandbox's loopback: %w", err)
		}
		// The namespace is the sandbox's alone, so a low port in it is
		// nobody else's: any user of the image may listen on one, with no
		// capability over the network. The file is this thread's namespace's.
		if err := os.WriteFile(unprivilegedPortStart, []byte("0"), 0); err != nil {
			return fmt.Errorf("open the sandbox's low ports to its users: %w", err)
		}
		n.listener, err = net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(EgressProxyPort)))
		if err != nil {
			return fmt.Errorf("listen in the sandbox's network namespace: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return n, nil
}

const unprivilegedPortStart = "/proc/sys/net/ipv4/ip_unprivileged_port_start"

// Hold is `c8s session-agent hold`: it does nothing until its input ends. The
// agent runs it in new namespaces and takes hold of them through it.
func Hold(stdin io.Reader) error {
	_, err := io.Copy(io.Discard, stdin)
	return err
}

// holds reports whether the process whose /proc directory is proc runs in the
// namespaces made here. The runtime is told to join them, and a sandbox it
// started anywhere else is not the sandbox this guest attests: its network
// would not be the one the proxy stands in, or its user ids not the mapped
// ones.
func (n *sandboxNet) holds(proc string) error {
	for _, namespace := range []struct {
		name string
		held *os.File
	}{{"user", n.user}, {"net", n.network}} {
		want, err := namespace.held.Stat()
		if err != nil {
			return err
		}
		got, err := os.Stat(filepath.Join(proc, "ns", namespace.name))
		if err != nil {
			return err
		}
		if !os.SameFile(want, got) {
			return fmt.Errorf("the sandbox does not run in the %s namespace made for it", namespace.name)
		}
	}
	return nil
}

// paths are the namespaces as the runtime opens them: the agent's own
// descriptors, which name these namespaces for as long as the agent runs.
func (n *sandboxNet) paths() sandboxNamespaces {
	at := func(f *os.File) string { return fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), f.Fd()) }
	return sandboxNamespaces{User: at(n.user), Network: at(n.network)}
}

// serve starts the proxy under the sandbox's egress policy, once: a guest
// has one sandbox. Its socket has been listening since the namespace was
// made, with nothing in the namespace to connect to it.
func (n *sandboxNet) serve(policy *session.Egress) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.server = &http.Server{Handler: &EgressProxy{Policy: policy}, ReadHeaderTimeout: 10 * time.Second}
	go func(server *http.Server) { _ = server.Serve(n.listener) }(n.server)
}

// dial connects to port on the sandbox's loopback. The socket is made by a
// thread inside the sandbox's network namespace and stays there, so the
// sandbox sees a connection from its own loopback and nothing of the guest's
// network is on the way.
func (n *sandboxNet) dial(ctx context.Context, port int) (net.Conn, error) {
	var conn net.Conn
	err := inNetworkNamespace(n.network, func() error {
		// A literal address: nothing is resolved, and the one connect runs on
		// this thread.
		var err error
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		return err
	})
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// Close stops the proxy and lets go of the namespaces.
func (n *sandboxNet) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	var err error
	if n.server != nil {
		err = n.server.Close()
	} else if n.listener != nil {
		err = n.listener.Close()
	}
	for _, namespace := range []*os.File{n.user, n.network} {
		if namespace != nil {
			err = errors.Join(err, namespace.Close())
		}
	}
	return err
}

// inNetworkNamespace runs fn on a thread that has entered the network
// namespace target, and returns once the thread is back in its own. What fn
// makes in there with system calls of its own thread, a socket for one, stays
// in that namespace.
func inNetworkNamespace(target *os.File, fn func() error) error {
	done := make(chan error, 1)
	go func() {
		// The thread goes back to the scheduler only from its own namespace.
		// One that could not return stays locked, and ends with this
		// goroutine instead of running some other goroutine in the wrong
		// namespace.
		runtime.LockOSThread()
		own, err := os.Open(fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()))
		if err != nil {
			runtime.UnlockOSThread()
			done <- err
			return
		}
		defer own.Close()
		if err := enterNetworkNamespace(target); err != nil {
			runtime.UnlockOSThread()
			done <- fmt.Errorf("enter network namespace %s: %w", target.Name(), err)
			return
		}
		fnErr := fn()
		if err := unix.Setns(int(own.Fd()), unix.CLONE_NEWNET); err != nil {
			done <- errors.Join(fnErr, fmt.Errorf("return to the guest's network namespace: %w", err))
			return
		}
		runtime.UnlockOSThread()
		done <- fnErr
	}()
	return <-done
}

// enterNetworkNamespace moves the calling thread into target. The descriptor
// is used while the file is held against a close: a number read off a file
// that another goroutine closes could be another file's by the time it is used.
func enterNetworkNamespace(target *os.File) error {
	raw, err := target.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	if err := raw.Control(func(fd uintptr) { setErr = unix.Setns(int(fd), unix.CLONE_NEWNET) }); err != nil {
		return err
	}
	return setErr
}

// onlyLoopback refuses a network namespace that holds anything besides its
// loopback. The proxy is the sandbox's one way out, and its rules cover
// nothing that leaves by another interface. A kernel with a tunnel driver
// puts a fallback device in every new namespace unless it is told not to
// (net.core.fb_tunnels_only_for_init_net).
func onlyLoopback(interfaces []net.Interface) error {
	var others []string
	for _, i := range interfaces {
		if i.Flags&net.FlagLoopback == 0 {
			others = append(others, i.Name)
		}
	}
	if len(others) > 0 {
		return fmt.Errorf("the sandbox's network namespace holds %s besides its loopback", strings.Join(others, ", "))
	}
	return nil
}

// loopbackUp sets IFF_UP on lo in the calling thread's network namespace.
func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}
