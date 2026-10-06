package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// guest stands for a VMM's vsock socket with an agent behind it: it takes
// the guest's port on a first line, as the VMM does, and answers one command
// a connection, as the agent does.
func guest(t *testing.T, answerTo func(argv []string) string) *vmm {
	t.Helper()
	return guestWith(t, func(argv []string, _ map[string][]byte) string { return answerTo(argv) })
}

// guestWith is such a guest whose answer may depend on the credentials a
// request brought.
func guestWith(t *testing.T, answerTo func(argv []string, credentials map[string][]byte) string) *vmm {
	t.Helper()
	// A socket's path is short: under the system's own directory.
	work, err := os.MkdirTemp("", "fcburst")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(work) })
	listener, err := net.Listen("unix", filepath.Join(work, "v.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				lines := bufio.NewReader(conn)
				if line, err := lines.ReadString('\n'); err != nil || line != fmt.Sprintf("CONNECT %d\n", agentPort) {
					fmt.Fprintf(conn, "NO\n")
					return
				}
				fmt.Fprintf(conn, "OK 1073741824\n")
				line, err := lines.ReadBytes('\n')
				if err != nil {
					return
				}
				var request struct {
					Argv        []string          `json:"argv"`
					Credentials map[string][]byte `json:"credentials"`
					Word        bool              `json:"word"`
				}
				if json.Unmarshal(line, &request) != nil {
					return
				}
				if request.Word {
					fmt.Fprintf(conn, "{\"taken\":true}\n")
				}
				fmt.Fprintf(conn, "%s\n", answerTo(request.Argv, request.Credentials))
			}()
		}
	}()
	return &vmm{work: work}
}

// A command reaches the guest's agent through the VMM's socket, and its
// answer comes back whole. A command that failed is no connection to make
// again: it is told apart from a guest that does not answer yet.
func TestAskRunsOneCommandThroughTheVMMsSocket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	v := guest(t, func(argv []string) string {
		switch strings.Join(argv, " ") {
		case "node -v":
			return `{"exit_code":0,"stdout":"djI0LjkuMAo=","stderr":null}`
		case "false":
			return `{"exit_code":1,"stdout":null,"stderr":"bm8K"}`
		case "absent":
			return `{"exit_code":0,"stdout":null,"stderr":null,"error":"exec: \"absent\": executable file not found in $PATH"}`
		}
		return "not an answer"
	})
	said, connected, err := v.ask(ctx, []string{"node", "-v"})
	if err != nil || string(said.Stdout) != "v24.9.0\n" || connected.IsZero() {
		t.Fatalf("the answer: %+v at %v, %v", said, connected, err)
	}
	for _, argv := range [][]string{{"false"}, {"absent"}, {"anything", "else"}} {
		var failed *commandError
		if _, _, err := v.ask(ctx, argv); !errors.As(err, &failed) {
			t.Errorf("%v: %v, want a command's failure", argv, err)
		}
	}
	// A guest whose socket is not there yet is one to try again.
	gone := &vmm{work: t.TempDir()}
	var failed *commandError
	if _, _, err := gone.ask(ctx, []string{"true"}); err == nil || errors.As(err, &failed) {
		t.Fatalf("a guest with no socket: %v", err)
	}
}

// With no CPUs named a VMM stays where this program runs, and a list that
// names none is refused before any VMM starts.
func TestAffinityNamesCPUsOrChangesNothing(t *testing.T) {
	pin, err := affinity("")
	if err != nil {
		t.Fatal(err)
	}
	restore, err := pin()
	if err != nil {
		t.Fatal(err)
	}
	restore()
	for _, list := range []string{"x", "3-1", "-2", "1,,2", "1-"} {
		if _, err := affinity(list); err == nil {
			t.Errorf("%q was taken for a list of CPUs", list)
		}
	}
}

// A start from a pool is one message on the connection made ahead to the
// guest's agent: a credential made for that start, of the size asked for,
// and the first command, whose answer must be the credential when the
// command reads it back. Its time runs from the message, and no part of it
// is the connection.
func TestTakeSendsACredentialAndTheFirstCommandOnTheConnectionMadeAhead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var mu sync.Mutex
	var brought [][]byte
	agent := func(argv []string, credentials map[string][]byte) string {
		mu.Lock()
		brought = append(brought, credentials[credential])
		mu.Unlock()
		switch argv[0] {
		case "sh":
			data, _ := json.Marshal(map[string]any{"exit_code": 0, "stdout": credentials[credential]})
			return string(data)
		case "stale":
			return `{"exit_code":0,"stdout":"b2xk"}`
		}
		return `{"exit_code":0,"stdout":"djI0LjkuMAo="}`
	}
	pooled := func() *vmm {
		v := guestWith(t, agent)
		var err error
		if v.ahead, err = v.connect(ctx); err != nil {
			t.Fatal(err)
		}
		v.burst = time.Now().Add(-time.Second)
		return v
	}
	reads := &first{Argv: []string{"sh", "-c", `cat "$C8S_CREDENTIALS_DIR/api-token"`}, ReadsBack: true, Bytes: 22}
	rec, err := pooled().take(ctx, reads, nil)
	if err != nil || rec.Output != "" || rec.Offset < time.Second.Microseconds() || rec.FirstCmd <= 0 || rec.Connected != 0 || rec.Taken != 0 {
		t.Fatalf("a start whose command reads its credential back: %+v, %v", rec, err)
	}
	if again, err := pooled().take(ctx, reads, nil); err != nil || again == nil {
		t.Fatal(err)
	}
	seen := func() [][]byte {
		mu.Lock()
		defer mu.Unlock()
		return append([][]byte(nil), brought...)
	}
	if got := seen(); len(got) != 2 || len(got[0]) != 22 || string(got[0]) == string(got[1]) {
		t.Fatalf("two starts brought the credentials %q", got)
	}
	// A command that answers with something else has not read it back.
	if rec, err := pooled().take(ctx, &first{Argv: []string{"stale"}, ReadsBack: true, Bytes: 22}, nil); err == nil {
		t.Fatalf("a command that wrote another credential than its start brought: %+v", rec)
	}
	// A command that was named says what it will, and a start that brings
	// no credential sends none.
	rec, err = pooled().take(ctx, &first{Argv: []string{"node", "-v"}}, nil)
	if got := seen(); err != nil || rec.Output != "v24.9.0" || got[len(got)-1] != nil {
		t.Fatalf("a named command with no credential: %+v, %v, brought %q", rec, err, got[len(got)-1])
	}
}

// A hook is run with the burst's number and waited for, and one that fails
// fails the burst. No hook named is none run.
func TestHookRunsItsProgramWithTheBurstsNumber(t *testing.T) {
	if err := hook("", 3); err != nil {
		t.Fatalf("no hook: %v", err)
	}
	said := filepath.Join(t.TempDir(), "said")
	program := filepath.Join(t.TempDir(), "hook")
	if err := os.WriteFile(program, []byte("#!/bin/sh\necho \"$1\" > "+said+"\n[ \"$1\" != 9 ]\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := hook(program, 3); err != nil {
		t.Fatalf("a hook that ends in order: %v", err)
	}
	if got, err := os.ReadFile(said); err != nil || strings.TrimSpace(string(got)) != "3" {
		t.Fatalf("the hook was told %q (%v), and its burst is 3", got, err)
	}
	if err := hook(program, 9); err == nil {
		t.Fatal("a hook that failed did not fail the burst")
	}
}

// With so many starts at once, a start past them waits in line: it sends its
// guest nothing until one before it has its agent's word, and it does not
// wait on that one's command. A start with no line asks for no word.
func TestStartPastTheBoundWaitsForAWordAndNotForACommand(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The first guest's command ends only when the test lets it.
	hold := make(chan struct{})
	reached := make(chan string, 3)
	pooled := func(name string, wait <-chan struct{}) *vmm {
		v := guest(t, func([]string) string {
			reached <- name
			if wait != nil {
				<-wait
			}
			return `{"exit_code":0,"stdout":"djI0LjkuMAo="}`
		})
		var err error
		if v.ahead, err = v.connect(ctx); err != nil {
			t.Fatal(err)
		}
		v.burst = time.Now()
		return v
	}
	command := &first{Argv: []string{"node", "-v"}}
	turns := newLine(1)
	type outcome struct {
		rec *started
		err error
	}
	start := func(v *vmm) <-chan outcome {
		out := make(chan outcome, 1)
		done, err := turns.take(ctx)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			defer done()
			rec, err := v.take(ctx, command, done)
			out <- outcome{rec, err}
		}()
		return out
	}
	// The one turn is taken, and the test's own next take must wait for the
	// first agent's word: it comes while that agent's command still runs.
	one := start(pooled("first", hold))
	if got := <-reached; got != "first" {
		t.Fatalf("the guest reached first was %s", got)
	}
	two := start(pooled("second", nil))
	second := <-two
	if second.err != nil || second.rec.Taken <= 0 || second.rec.Taken > second.rec.FirstCmd {
		t.Fatalf("the start that waited its turn: %+v, %v", second.rec, second.err)
	}
	select {
	case got := <-one:
		t.Fatalf("the first start ended with its command held: %+v, %v", got.rec, got.err)
	default:
	}
	close(hold)
	if got := <-one; got.err != nil || got.rec.Taken <= 0 {
		t.Fatalf("the first start: %+v, %v", got.rec, got.err)
	}
	// A turn that nobody ends is given back when its start is over, and a
	// start that waits past its deadline is told.
	full := newLine(1)
	held, err := full.take(ctx)
	if err != nil {
		t.Fatal(err)
	}
	short, stop := context.WithTimeout(ctx, 20*time.Millisecond)
	defer stop()
	if _, err := full.take(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a start whose turn did not come: %v", err)
	}
	held()
	held()
	if again, err := full.take(ctx); err != nil {
		t.Fatalf("a turn given back twice: %v", err)
	} else {
		again()
	}
	// No line: every start has its turn, and none asks its agent for a word.
	if done, err := newLine(0).take(ctx); err != nil || done == nil {
		t.Fatalf("a start with no line: %v", err)
	}
	if rec, err := pooled("third", nil).take(ctx, command, nil); err != nil || rec.Taken != 0 {
		t.Fatalf("a start with no line: %+v, %v", rec, err)
	}
}
