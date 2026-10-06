// Command fcburst is the Firecracker side of test/session/burst.sh, which
// holds a burst of session starts to it. It starts many sessions at the same
// instant in one of three ways, and has each guest run its first command.
//
//	fcburst -dir <fc dir> -sessions 100 [-mode load|load-ci|pool] [-vmm-cpus 12-21,36-45] [-timeout 2m]
//
// <fc dir> is as the steps of test/session/firecracker_sample.py left it.
//
// With -mode load, the default, each start loads one snapshot into a VMM of
// its own: Firecracker's fastest start of a guest that does not run yet. The
// snapshot is of the lean guest (lean.state and lean.mem, with lean.json),
// the least that takes a session's first command. A start's time runs from
// the start of its VMM's process to its guest's answer.
//
// With -mode load-ci the snapshot is of the guest of Firecracker's own
// tests, with an agent on a second drive (snap.state, snap.mem and
// first.json): a fuller guest, kept as a second line.
//
// With -mode pool, each start takes a guest that was booted ahead, as a
// platform with confidentiality off can keep them and as sessions keep TDs:
// the lean guest (lean.img and lean-vm.json), booted, with its file system
// read whole and one command run in it, idle for -rest, and a connection to
// its agent made. A start's time runs from its message's send to the
// command's answer.
//
// A start in the lean guest is one message to its agent, with a credential
// made for it and the first command: the agent writes the credential where
// a session's goes and runs the command.
//
// Each VMM runs in a directory of its own under <fc dir>/burst, where its
// sockets are, and is stopped once every guest has answered or failed. With
// -vmm-cpus the VMMs keep to those CPUs and this program stays where it was
// started, as a session's guests and the program that starts them keep to
// CPUs apart.
//
// It prints one JSON record for each guest that answered and one for the
// burst, with times in microseconds: kinds "fc-load-session" and "fc-load",
// "fc-ci-load-session" and "fc-ci-load", or "fc-pool-session" and "fc-pool".
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/confidential-dot-ai/c8s/test/session/hostcpu"
)

// agentPort is where the guest's agent listens on vsock, as the snapshot's
// guest started it.
const agentPort = 5000

// credential names the credential a start from a pool brings, as a
// session's bind brings one.
const credential = "api-token"

// first is the first command. For the snapshot of the tests' guest, as its
// snapshot step wrote it: Stdout is what it must write, in base64 as the
// agent answers, or nil for a command that says what it will. For the lean
// guest, as the lean step wrote it: a start brings a credential of Bytes
// bytes, and a command that ReadsBack must write it.
type first struct {
	Argv      []string `json:"argv"`
	Stdout    *string  `json:"stdout"`
	ReadsBack bool     `json:"reads_back"`
	Bytes     int      `json:"credential_bytes"`
}

// started is one guest that answered: kind "fc-load-session", or
// "fc-pool-session" for one that was booted ahead.
type started struct {
	Kind  string `json:"kind"`
	Round int    `json:"round"`
	Index int    `json:"index"`
	// Offset is how long after the burst began this start did: its VMM's
	// process was started, or its message sent to a guest booted ahead. The
	// times after it run from there. For a snapshot: the API socket there,
	// the snapshot loaded and its guest resumed, and the agent's accept of
	// the connection, after Connections tries. For both: the command's
	// answer.
	Offset      int64  `json:"offset_us"`
	APIUp       int64  `json:"api_up_us,omitempty"`
	Loaded      int64  `json:"loaded_us,omitempty"`
	Connected   int64  `json:"vsock_connected_us,omitempty"`
	Connections int    `json:"vsock_connections,omitempty"`
	FirstCmd    int64  `json:"first_cmd_us"`
	Output      string `json:"first_output,omitempty"`
}

// volley is the burst: kind "fc-load", or "fc-pool". Its times run from the
// instant every start was let go.
type volley struct {
	Kind     string `json:"kind"`
	Round    int    `json:"round"`
	At       int64  `json:"at_unix_us"`
	Sessions int    `json:"sessions"`
	Started  int    `json:"started"`
	First    int64  `json:"first_us,omitempty"`
	Wall     int64  `json:"wall_us,omitempty"`
	// Span is from that instant until every start had answered or failed.
	// HostCPU is all the CPU the host gave over it, whoever took it, by its
	// kernel's count, and OwnCPU the part this program took.
	Span    int64    `json:"span_us,omitempty"`
	HostCPU int64    `json:"host_cpu_us,omitempty"`
	OwnCPU  int64    `json:"own_cpu_us,omitempty"`
	Command []string `json:"first_command"`
	// PoolBoot is how long the pool's guests took to boot, all of them, so
	// many at a time, and Idle how long they then sat before the burst.
	// Neither is part of a start.
	PoolBoot int64 `json:"pool_boot_ms,omitempty"`
	Idle     int64 `json:"idle_ms,omitempty"`
	// Errors are what the others failed with: the first five that differ.
	Errors []string `json:"errors,omitempty"`
}

// options are what the command line says.
type options struct {
	dir, mode, cpus string
	sessions, round int
	boots           int
	timeout, rest   time.Duration
	before, after   string
}

func main() {
	var o options
	flag.StringVar(&o.dir, "dir", "", "the directory of the VMM and what it starts from")
	flag.StringVar(&o.mode, "mode", "load", "load: each start loads the lean guest's snapshot; load-ci: the snapshot of the tests' guest; pool: each start takes a guest booted ahead")
	flag.IntVar(&o.sessions, "sessions", 100, "how many sessions start at once")
	flag.StringVar(&o.cpus, "vmm-cpus", "", "the CPUs the VMMs keep to, as taskset takes them (default: this program's)")
	flag.DurationVar(&o.timeout, "timeout", 2*time.Minute, "how long one guest has to answer, and with -mode pool to boot")
	flag.IntVar(&o.round, "round", 0, "the number each record says its burst has")
	flag.IntVar(&o.boots, "boots", 8, "with -mode pool, how many guests boot at a time")
	flag.DurationVar(&o.rest, "rest", 5*time.Second, "with -mode pool, how long the booted guests sit idle before the burst")
	flag.StringVar(&o.before, "before-burst", "", "a program run with the burst's number before the burst is let go, which waits for it")
	flag.StringVar(&o.after, "after-answers", "", "a program run with the burst's number once every start has answered or failed, while the VMMs still run")
	flag.Parse()
	if err := run(&o); err != nil {
		fmt.Fprintln(os.Stderr, "fcburst:", err)
		os.Exit(1)
	}
}

func run(o *options) error {
	if o.dir == "" || o.sessions < 1 || o.boots < 1 {
		return errors.New("-dir is required, and -sessions and -boots are at least 1")
	}
	how, known := modes[o.mode]
	if !known {
		return errors.New("-mode is load, load-ci or pool")
	}
	pooled := o.mode == "pool"
	dir, err := filepath.Abs(o.dir)
	if err != nil {
		return err
	}
	said := &volley{Kind: how.kind, Round: o.round, Sessions: o.sessions}
	each, from := how.kind+"-session", how.first
	data, err := os.ReadFile(filepath.Join(dir, from))
	if err != nil {
		return fmt.Errorf("the first command: %w", err)
	}
	var command first
	if err := json.Unmarshal(data, &command); err != nil || len(command.Argv) == 0 {
		return fmt.Errorf("%s names no command: %v", from, err)
	}
	said.Command = command.Argv
	pin, err := affinity(o.cpus)
	if err != nil {
		return fmt.Errorf("-vmm-cpus: %w", err)
	}
	base := filepath.Join(dir, "burst")
	if err := os.RemoveAll(base); err != nil {
		return err
	}
	defer os.RemoveAll(base)
	// Everything a VMM needs that is no part of a start is made before the
	// burst: its directory and the file its console goes to.
	vmms := make([]*vmm, o.sessions)
	for i := range vmms {
		work := filepath.Join(base, strconv.Itoa(i))
		if err := os.MkdirAll(work, 0o755); err != nil {
			return err
		}
		console, err := os.Create(filepath.Join(work, "console.log"))
		if err != nil {
			return err
		}
		defer console.Close()
		vmms[i] = &vmm{index: i, dir: dir, work: work, console: console, pin: pin}
	}
	defer func() {
		for _, v := range vmms {
			v.stop()
		}
	}()
	if pooled {
		began := time.Now()
		if err := boot(vmms, o.boots, o.timeout); err != nil {
			return err
		}
		said.PoolBoot = time.Since(began).Milliseconds()
		time.Sleep(o.rest)
		said.Idle = o.rest.Milliseconds()
	}

	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	outcomes := make([]error, o.sessions)
	answers := make([]*started, o.sessions)
	var all sync.WaitGroup
	release := make(chan struct{})
	for i, v := range vmms {
		all.Add(1)
		go func() {
			defer all.Done()
			<-release
			if pooled {
				answers[i], outcomes[i] = v.take(ctx, &command)
			} else {
				answers[i], outcomes[i] = v.start(ctx, &command, how)
			}
		}()
	}
	if err := hook(o.before, o.round); err != nil {
		return fmt.Errorf("-before-burst: %w", err)
	}
	given, counted := hostcpu.Now()
	began := time.Now()
	for _, v := range vmms {
		v.burst = began
	}
	said.At = began.UnixMicro()
	close(release)
	all.Wait()
	said.Span = time.Since(began).Microseconds()
	if now, ok := hostcpu.Now(); ok && counted {
		given = now.Since(given)
		said.HostCPU, said.OwnCPU = given.Host, given.Own
	}
	if err := hook(o.after, o.round); err != nil {
		return fmt.Errorf("-after-answers: %w", err)
	}

	out := json.NewEncoder(os.Stdout)
	for i, answer := range answers {
		if err := outcomes[i]; err != nil {
			if len(said.Errors) < 5 && !slices.Contains(said.Errors, err.Error()) {
				said.Errors = append(said.Errors, err.Error())
			}
			continue
		}
		said.Started++
		answer.Kind, answer.Round = each, o.round
		at := answer.Offset + answer.FirstCmd
		if said.First == 0 || at < said.First {
			said.First = at
		}
		said.Wall = max(said.Wall, at)
		if err := out.Encode(answer); err != nil {
			return err
		}
	}
	return out.Encode(said)
}

// hook runs program, if one is named, with the burst's number, and waits for
// it. What it prints goes where this program's own complaints go.
func hook(program string, round int) error {
	if program == "" {
		return nil
	}
	cmd := exec.Command(program, strconv.Itoa(round))
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	return cmd.Run()
}

// mode is one way to start a session: the kind its burst's record has, the
// file that names its first command, and for a snapshot its two files.
type mode struct {
	kind, first, state, mem string
}

var modes = map[string]mode{
	"load":    {"fc-load", "lean.json", "lean.state", "lean.mem"},
	"load-ci": {"fc-ci-load", "first.json", "snap.state", "snap.mem"},
	"pool":    {"fc-pool", "lean.json", "", ""},
}

// boot boots every guest of a pool, so many at a time, and leaves each as a
// pool keeps it: a command run in it, and a connection to its agent made.
// One that does not come up fails the pool: a burst is of all its sessions.
func boot(vmms []*vmm, atOnce int, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	turn := make(chan struct{}, atOnce)
	failed := make([]error, len(vmms))
	var all sync.WaitGroup
	for i, v := range vmms {
		all.Add(1)
		go func() {
			defer all.Done()
			turn <- struct{}{}
			defer func() { <-turn }()
			failed[i] = v.boot(ctx)
		}()
	}
	all.Wait()
	for i, err := range failed {
		if err != nil {
			return fmt.Errorf("guest %d of the pool: %w", i, err)
		}
	}
	return nil
}

// vmm is one VMM of the burst.
type vmm struct {
	index     int
	dir, work string
	console   *os.File
	pin       func() (restore func(), err error)
	burst     time.Time
	process   *exec.Cmd
	// ahead is the connection made to the agent of a guest booted ahead.
	ahead *link
}

// run starts the VMM's process, kept to the VMMs' CPUs.
func (v *vmm) run(args ...string) (time.Time, error) {
	cmd := exec.Command(filepath.Join(v.dir, "firecracker"), args...)
	cmd.Dir, cmd.Stdout, cmd.Stderr = v.work, v.console, v.console
	// The VMM is a child of the thread that starts it, and keeps to that
	// thread's CPUs.
	restore, err := v.pin()
	if err != nil {
		return time.Time{}, err
	}
	began := time.Now()
	err = cmd.Start()
	restore()
	if err != nil {
		return time.Time{}, err
	}
	v.process = cmd
	return began, nil
}

// boot boots the lean guest in the VMM and, once its agent serves, has it
// read its whole file system, as a pooled session guest has its sandbox
// image unpacked and in memory before a bind, and run one command. It then
// makes the connection a start is sent on.
func (v *vmm) boot(ctx context.Context) error {
	if _, err := v.run("--no-api", "--config-file", filepath.Join(v.dir, "lean-vm.json")); err != nil {
		return err
	}
	for {
		to, err := v.connect(ctx)
		if err == nil {
			_, err = to.do(&request{Read: "/", Argv: []string{"true"}})
		}
		if err == nil {
			break
		}
		var failed *commandError
		if errors.As(err, &failed) {
			return err
		}
		if ctx.Err() != nil {
			return fmt.Errorf("the guest's agent took no connection: %w", err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	var err error
	v.ahead, err = v.connect(ctx)
	return err
}

// take starts a session in a guest booted ahead: one message on the
// connection made to its agent.
func (v *vmm) take(ctx context.Context, command *first) (*started, error) {
	// The connection was made under the deadline of its guest's boot.
	deadline, _ := ctx.Deadline()
	_ = v.ahead.conn.SetDeadline(deadline)
	began := time.Now()
	output, err := v.ahead.session(command)
	if err != nil {
		return nil, err
	}
	return &started{Index: v.index, Offset: began.Sub(v.burst).Microseconds(), FirstCmd: time.Since(began).Microseconds(), Output: output}, nil
}

// session sends a session's first command on the connection, with a
// credential made for this start when the guest takes one, and holds the
// answer to what the command must write. It returns what a command that
// says what it will wrote.
func (l *link) session(command *first) (string, error) {
	var credentials map[string][]byte
	var secret []byte
	if command.Bytes > 0 {
		// Text, as a session's credential is.
		raw := make([]byte, (command.Bytes+1)/2)
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		secret = []byte(hex.EncodeToString(raw)[:command.Bytes])
		credentials = map[string][]byte{credential: secret}
	}
	answer, err := l.ask(command.Argv, credentials)
	if err != nil {
		return "", err
	}
	switch {
	case command.ReadsBack:
		if !bytes.Equal(answer.Stdout, secret) {
			return "", &commandError{"the first command did not read back the credential its start brought"}
		}
	case command.Stdout != nil:
		if base64.StdEncoding.EncodeToString(answer.Stdout) != *command.Stdout {
			return "", &commandError{"the first command did not read back the file its snapshot's drive holds"}
		}
	default:
		return strings.TrimSpace(string(answer.Stdout[:min(len(answer.Stdout), 64)])), nil
	}
	return "", nil
}

// start runs the VMM, loads the snapshot into it, and has its guest's agent
// run the first command.
func (v *vmm) start(ctx context.Context, command *first, how mode) (*started, error) {
	rec := &started{Index: v.index}
	began, err := v.run("--api-sock", "fc.sock")
	if err != nil {
		return nil, err
	}
	rec.Offset = began.Sub(v.burst).Microseconds()
	since := func() int64 { return time.Since(began).Microseconds() }

	api := filepath.Join(v.work, "fc.sock")
	for {
		if _, err := os.Stat(api); err == nil {
			break
		}
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("the VMM's API socket: %w", err)
		}
		time.Sleep(100 * time.Microsecond)
	}
	rec.APIUp = since()
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", api)
		},
	}}
	defer client.CloseIdleConnections()
	body, err := json.Marshal(map[string]any{
		"snapshot_path": filepath.Join(v.dir, how.state),
		"mem_backend":   map[string]string{"backend_type": "File", "backend_path": filepath.Join(v.dir, how.mem)},
		"resume_vm":     true,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://localhost/snapshot/load", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("the snapshot's load: %w", err)
	}
	said, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the snapshot's load: %s: %s", resp.Status, bytes.TrimSpace(said))
	}
	rec.Loaded = since()

	// A guest that was just resumed may not take a connection at once: one
	// that is refused is made again.
	for {
		rec.Connections++
		to, err := v.connect(ctx)
		if err == nil {
			rec.Connected = to.at.Sub(began).Microseconds()
			if rec.Output, err = to.session(command); err == nil {
				rec.FirstCmd = since()
				return rec, nil
			}
		}
		var failed *commandError
		if errors.As(err, &failed) {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("the guest's agent took no connection: %w", err)
		}
		time.Sleep(200 * time.Microsecond)
	}
}

// answer is what the guest's agent says of one command.
type answer struct {
	ExitCode int    `json:"exit_code"`
	Stdout   []byte `json:"stdout"`
	Stderr   []byte `json:"stderr"`
	Error    string `json:"error,omitempty"`
}

// commandError is a command the agent ran, or would not: no connection made
// again changes it.
type commandError struct{ said string }

func (e *commandError) Error() string { return e.said }

// link is a connection the guest's agent has taken, through the VMM's vsock
// socket, and when this side knew that it had.
type link struct {
	conn  net.Conn
	lines *bufio.Reader
	at    time.Time
}

// connect makes a connection to the guest's agent: the VMM's vsock socket
// takes the guest's port on a first line, and says when the guest took it.
func (v *vmm) connect(ctx context.Context) (*link, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(v.work, "v.sock"))
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %d\n", agentPort); err != nil {
		conn.Close()
		return nil, err
	}
	lines := bufio.NewReaderSize(conn, 1<<16)
	line, err := lines.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "OK ") {
		conn.Close()
		return nil, fmt.Errorf("the VMM answered the connection with %q: %v", strings.TrimSpace(line), err)
	}
	return &link{conn: conn, lines: lines, at: time.Now()}, nil
}

// request is what the guest's agent is asked: a command, what credentials
// come with it, and a directory to read whole before either.
type request struct {
	Argv        []string          `json:"argv"`
	Credentials map[string][]byte `json:"credentials,omitempty"`
	Read        string            `json:"read,omitempty"`
}

// ask sends a command and what credentials come with it, and returns the
// agent's answer.
func (l *link) ask(argv []string, credentials map[string][]byte) (*answer, error) {
	return l.do(&request{Argv: argv, Credentials: credentials})
}

// do sends the one request the connection takes and returns the agent's
// answer.
func (l *link) do(req *request) (*answer, error) {
	defer l.conn.Close()
	argv := req.Argv
	request, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := l.conn.Write(append(request, '\n')); err != nil {
		return nil, err
	}
	data, err := l.lines.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var said answer
	if err := json.Unmarshal(data, &said); err != nil {
		return nil, &commandError{fmt.Sprintf("the guest's agent answered %q", bytes.TrimSpace(data))}
	}
	if said.Error != "" || said.ExitCode != 0 {
		return nil, &commandError{fmt.Sprintf("%v: exit %d, %s%s", argv, said.ExitCode, said.Error, bytes.TrimSpace(said.Stderr))}
	}
	return &said, nil
}

// ask sends one command to the guest's agent on a connection of its own,
// and says when the agent had taken that connection.
func (v *vmm) ask(ctx context.Context, argv []string) (*answer, time.Time, error) {
	to, err := v.connect(ctx)
	if err != nil {
		return nil, time.Time{}, err
	}
	said, err := to.ask(argv, nil)
	if err != nil {
		return nil, time.Time{}, err
	}
	return said, to.at, nil
}

// stop ends the VMM, with its guest.
func (v *vmm) stop() {
	if v.ahead != nil {
		_ = v.ahead.conn.Close()
	}
	if v.process == nil || v.process.Process == nil {
		return
	}
	_ = v.process.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		_ = v.process.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = v.process.Process.Kill()
		<-done
	}
}
