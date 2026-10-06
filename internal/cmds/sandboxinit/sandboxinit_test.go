//go:build unix

package sandboxinit_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sandboxinit"
)

// When this test binary is run with the variable set, it is the program
// under test: what a container's runtime would start.
const asInit = "C8S_SANDBOXINIT_TEST_AS_INIT"

// beforeInit, where a platform's tests set it, runs in the program under
// test before it is the init.
var beforeInit func()

func TestMain(m *testing.M) {
	// A spawner starts this binary by its preserved descriptor, with no
	// variable of the test's: that is the init too.
	if os.Getenv(asInit) == "1" || os.Args[0] == fmt.Sprintf("/proc/self/fd/%d", sandboxinit.ProgramFD) {
		if beforeInit != nil {
			beforeInit()
		}
		os.Exit(sandboxinit.Main())
	}
	os.Exit(m.Run())
}

// start runs this binary as the init, with its own file and one end of a
// socket pair where a runtime would preserve them, and returns the agent's
// end.
func start(t *testing.T) (*exec.Cmd, *os.File) {
	t.Helper()
	return startWith(t)
}

// startWith is start with more variables in the init's environment.
func startWith(t *testing.T, env ...string) (*exec.Cmd, *os.File) {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The child gets its end as a preserved descriptor and no other copy.
	unix.CloseOnExec(pair[0])
	unix.CloseOnExec(pair[1])
	agent, theirs := os.NewFile(uintptr(pair[0]), "agent"), os.NewFile(uintptr(pair[1]), "init")
	t.Cleanup(func() { agent.Close() })
	self, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append([]string{asInit + "=1"}, env...)
	cmd.ExtraFiles = []*os.File{self, theirs}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	theirs.Close()
	return cmd, agent
}

func send(t *testing.T, agent *os.File, p sandboxinit.Process) {
	t.Helper()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := unix.Shutdown(int(agent.Fd()), unix.SHUT_WR); err != nil {
		t.Fatal(err)
	}
}

// The init becomes the process the agent names: in the directory, with the
// environment and under the arguments of the message, found in the message's
// PATH, and with neither preserved descriptor left open.
func TestInitBecomesTheProcess(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	cmd, agent := start(t)
	send(t, agent, sandboxinit.Process{
		Argv: []string{"sh", "-c", `echo "$GREETING $0 $(pwd) $(ls /proc/self/fd 2>/dev/null | tr '\n' ' ')" > "$OUT"`, "arg0"},
		Env:  []string{"PATH=/usr/bin:/bin", "GREETING=hello", "OUT=" + out},
		Cwd:  dir,
	})
	if err := cmd.Wait(); err != nil {
		t.Fatalf("the process ended with %v", err)
	}
	// It said that it took the message, and nothing after: a reason is a
	// failure's.
	if taken, reason := sandboxinit.ReadAnswer(agent); !taken || reason != "" {
		t.Fatalf("the init answered taken %v, reason %q", taken, reason)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(got))
	if len(fields) < 3 || fields[0] != "hello" || fields[1] != "arg0" {
		t.Fatalf("the process wrote %q", got)
	}
	if resolved, _ := filepath.EvalSymlinks(dir); fields[2] != dir && fields[2] != resolved {
		t.Fatalf("the process ran in %s, want %s", fields[2], dir)
	}
	// Where the kernel lists a process's descriptors, the two the runtime
	// preserved are not among the shell's.
	for _, fd := range fields[3:] {
		if fd == "4" {
			t.Fatalf("the process inherited the control descriptor: %q", got)
		}
	}
}

// What it cannot become, it says on one line, and exits as a shell does for
// a command that did not run. It says that it took the message only once it
// has found the command: a failure after that is the exec's.
func TestInitSaysWhyItCouldNotBecomeTheProcess(t *testing.T) {
	for name, tc := range map[string]struct {
		process sandboxinit.Process
		raw     string
		want    string
		taken   bool
	}{
		"no such command":      {process: sandboxinit.Process{Argv: []string{"c8s-no-such-command"}, Env: []string{"PATH=/usr/bin:/bin"}}, want: "c8s-no-such-command: command not found in /usr/bin:/bin"},
		"no such file":         {process: sandboxinit.Process{Argv: []string{"/nonexistent/program"}}, want: "/nonexistent/program: command not found", taken: true},
		"no program":           {process: sandboxinit.Process{Argv: []string{"/"}}, want: "run /:", taken: true},
		"no such directory":    {process: sandboxinit.Process{Argv: []string{"true"}, Cwd: "/nonexistent"}, want: "working directory"},
		"no command":           {process: sandboxinit.Process{}, want: "names no command"},
		"something else":       {raw: "not json", want: "the process to become"},
		"nothing but the end":  {raw: "", want: "the process to become"},
		"more than a megabyte": {raw: `{"argv":["true"],"env":["A=` + strings.Repeat("a", sandboxinit.MaxMessage) + `"]}`, want: "more than"},
	} {
		cmd, agent := start(t)
		if tc.raw != "" || name == "nothing but the end" {
			if _, err := agent.WriteString(tc.raw); err != nil {
				t.Fatal(err)
			}
			if err := unix.Shutdown(int(agent.Fd()), unix.SHUT_WR); err != nil {
				t.Fatal(err)
			}
		} else {
			send(t, agent, tc.process)
		}
		taken, said := sandboxinit.ReadAnswer(agent)
		err := cmd.Wait()
		var status *exec.ExitError
		if !strings.Contains(said, tc.want) || strings.Contains(said, "\n") {
			t.Errorf("%s: it said %q, want one line with %q", name, said, tc.want)
		}
		if taken != tc.taken {
			t.Errorf("%s: it said it took the message: %v, want %v", name, taken, tc.taken)
		}
		if ok := errorsAs(err, &status); !ok || status.ExitCode() != sandboxinit.FailureStatus {
			t.Errorf("%s: it ended with %v, want status %d", name, err, sandboxinit.FailureStatus)
		}
	}
}

func errorsAs(err error, target **exec.ExitError) bool {
	exit, ok := err.(*exec.ExitError)
	if ok {
		*target = exit
	}
	return ok
}

// A command named without a directory is searched for in the PATH its
// environment sets, like execvp, and one with a directory is that path.
func TestLookup(t *testing.T) {
	dir := t.TempDir()
	for name, mode := range map[string]os.FileMode{"tool": 0o755, "data": 0o644} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"), mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "folder"), 0o755); err != nil {
		t.Fatal(err)
	}
	env := []string{"HOME=/", "PATH=/nonexistent:" + dir}
	if got, err := sandboxinit.Lookup("tool", env); err != nil || got != filepath.Join(dir, "tool") {
		t.Fatalf("tool: %q, %v", got, err)
	}
	for _, name := range []string{"data", "folder", "absent"} {
		if got, err := sandboxinit.Lookup(name, env); err == nil {
			t.Errorf("%s was found at %s", name, got)
		}
	}
	if got, err := sandboxinit.Lookup("./relative/tool", env); err != nil || got != "./relative/tool" {
		t.Fatalf("a path: %q, %v", got, err)
	}
	// With no PATH of its own, the usual directories.
	if got, err := sandboxinit.Lookup("sh", nil); err != nil || !strings.HasSuffix(got, "/sh") {
		t.Fatalf("sh with no PATH: %q, %v", got, err)
	}
}

// An init that ends before it is told anything says nothing and took
// nothing: whoever started it for a command starts the command another way.
// What the agent reads of an answer is bounded.
func TestInitThatEndsUntoldTookNothing(t *testing.T) {
	cmd, agent := start(t)
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if taken, reason := sandboxinit.ReadAnswer(agent); taken || reason != "" {
		t.Fatalf("an init that was killed untold answered taken %v, reason %q", taken, reason)
	}
	for said, want := range map[string]struct {
		taken  bool
		reason string
	}{
		"":                                {false, ""},
		"ok\n":                            {true, ""},
		"ok\nrun /x: permission denied\n": {true, "run /x: permission denied"},
		"x: command not found in /bin\n":  {false, "x: command not found in /bin"},
		"okay then\n":                     {false, "okay then"},
		"ok":                              {false, "ok"},
	} {
		if taken, reason := sandboxinit.ReadAnswer(strings.NewReader(said)); taken != want.taken || reason != want.reason {
			t.Errorf("%q read as taken %v, reason %q", said, taken, reason)
		}
	}
	long := strings.Repeat("x", 10*sandboxinit.MaxAnswer)
	if _, reason := sandboxinit.ReadAnswer(strings.NewReader(long)); len(reason) != sandboxinit.MaxAnswer {
		t.Errorf("an answer of %d bytes was read as %d", len(long), len(reason))
	}
}

// ended reports when the other end of a pipe has closed everywhere.
func ended(pipe *os.File) <-chan time.Time {
	at := make(chan time.Time, 1)
	go func() {
		var none [1]byte
		_, _ = pipe.Read(none[:])
		at <- time.Now()
	}()
	return at
}

// The agent passes the init one end of a pipe with its message. The init
// keeps it and does nothing with it, and it closes at the exec: the agent's
// end reads the pipe's end while the process the init became still runs, and
// that process does not have the descriptor. One more than the init keeps is
// closed as it arrives.
func TestInitHoldsAPassedDescriptorUntilItsExec(t *testing.T) {
	cmd, agent := start(t)
	became, theirs, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer became.Close()
	spare, more, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer spare.Close()
	data, err := json.Marshal(sandboxinit.Process{Argv: []string{"sleep", "3"}, Env: []string{"PATH=/usr/bin:/bin"}, Cwd: "/"})
	if err != nil {
		t.Fatal(err)
	}
	// The first half of the message carries both descriptors.
	half := len(data) / 2
	if err := unix.Sendmsg(int(agent.Fd()), data[:half], unix.UnixRights(int(theirs.Fd()), int(more.Fd())), nil, 0); err != nil {
		t.Fatal(err)
	}
	theirs.Close()
	more.Close()
	execed, dropped := ended(became), ended(spare)
	select {
	case <-dropped:
	case <-time.After(10 * time.Second):
		t.Fatal("the init kept a second descriptor")
	}
	// The init waits for the rest of its message, and holds the first.
	select {
	case <-execed:
		t.Fatal("the pipe closed before the init had its message")
	case <-time.After(100 * time.Millisecond):
	}
	began := time.Now()
	if _, err := agent.Write(data[half:]); err != nil {
		t.Fatal(err)
	}
	if err := unix.Shutdown(int(agent.Fd()), unix.SHUT_WR); err != nil {
		t.Fatal(err)
	}
	select {
	case at := <-execed:
		// The process sleeps for seconds: had it inherited the descriptor,
		// the pipe would have closed at its end and not at its start.
		if took := at.Sub(began); took > 2*time.Second {
			t.Fatalf("the pipe closed %s after the message: at the process's end, not at the exec", took)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the pipe never closed")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
}

// An init that cannot become the process is gone, and the pipe it was passed
// closes with it: the agent's end does not wait for a process that will not
// come.
func TestPassedDescriptorClosesWithAnInitThatFailed(t *testing.T) {
	cmd, agent := start(t)
	became, theirs, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer became.Close()
	data, err := json.Marshal(sandboxinit.Process{Argv: []string{"/nonexistent/command"}, Env: []string{"PATH=/usr/bin:/bin"}, Cwd: "/"})
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Sendmsg(int(agent.Fd()), data, unix.UnixRights(int(theirs.Fd())), nil, 0); err != nil {
		t.Fatal(err)
	}
	theirs.Close()
	if err := unix.Shutdown(int(agent.Fd()), unix.SHUT_WR); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ended(became):
	case <-time.After(10 * time.Second):
		t.Fatal("the pipe outlived an init that failed")
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("an init that could not become its process exited with status 0")
	}
	// It had found the command's path and took the message: the exec is
	// what failed, and it says so.
	if _, reason := sandboxinit.ReadAnswer(agent); !strings.Contains(reason, "command not found") {
		t.Fatalf("the init's reason: %q", reason)
	}
}

// An init told to stay says that it took the message and stays: it is the
// sandbox's first process for as long as the sandbox lasts. It keeps neither
// its socket to the agent nor the descriptor passed with the message, so the
// agent reads the end of both while the init still runs.
func TestInitStaysWhenToldTo(t *testing.T) {
	cmd, agent := start(t)
	stays, theirs, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stays.Close()
	data, err := json.Marshal(sandboxinit.Process{Stay: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Sendmsg(int(agent.Fd()), data, unix.UnixRights(int(theirs.Fd())), nil, 0); err != nil {
		t.Fatal(err)
	}
	theirs.Close()
	if err := unix.Shutdown(int(agent.Fd()), unix.SHUT_WR); err != nil {
		t.Fatal(err)
	}
	said := make(chan [2]any, 1)
	go func() {
		taken, reason := sandboxinit.ReadAnswer(agent)
		said <- [2]any{taken, reason}
	}()
	select {
	case answer := <-said:
		if answer[0] != true || answer[1] != "" {
			t.Fatalf("the init answered taken %v, reason %q", answer[0], answer[1])
		}
	case <-time.After(10 * time.Second):
		t.Fatal("an init that stays kept its socket to the agent open")
	}
	select {
	case <-ended(stays):
	case <-time.After(10 * time.Second):
		t.Fatal("an init that stays kept the descriptor passed with its message")
	}
	gone := make(chan error, 1)
	go func() { gone <- cmd.Wait() }()
	select {
	case err := <-gone:
		t.Fatalf("an init told to stay ended: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-gone
}

// A message that says to stay names no command: an init does not guess
// which of the two was meant.
func TestInitRefusesToStayAndBecomeACommand(t *testing.T) {
	cmd, agent := start(t)
	send(t, agent, sandboxinit.Process{Stay: true, Argv: []string{"true"}, Env: []string{"PATH=/usr/bin:/bin"}})
	err := cmd.Wait()
	var status *exec.ExitError
	if !errorsAs(err, &status) || status.ExitCode() != sandboxinit.FailureStatus {
		t.Fatalf("the init ended with %v, want status %d", err, sandboxinit.FailureStatus)
	}
	if taken, reason := sandboxinit.ReadAnswer(agent); taken || !strings.Contains(reason, "told no command") {
		t.Fatalf("the init answered taken %v, reason %q", taken, reason)
	}
}
