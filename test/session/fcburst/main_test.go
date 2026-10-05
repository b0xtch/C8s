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
				}
				if json.Unmarshal(line, &request) != nil {
					return
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
	rec, err := pooled().take(ctx, reads)
	if err != nil || rec.Output != "" || rec.Offset < time.Second.Microseconds() || rec.FirstCmd <= 0 || rec.Connected != 0 {
		t.Fatalf("a start whose command reads its credential back: %+v, %v", rec, err)
	}
	if again, err := pooled().take(ctx, reads); err != nil || again == nil {
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
	if rec, err := pooled().take(ctx, &first{Argv: []string{"stale"}, ReadsBack: true, Bytes: 22}); err == nil {
		t.Fatalf("a command that wrote another credential than its start brought: %+v", rec)
	}
	// A command that was named says what it will, and a start that brings
	// no credential sends none.
	rec, err = pooled().take(ctx, &first{Argv: []string{"node", "-v"}})
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
