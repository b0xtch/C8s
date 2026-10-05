package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func ask(t *testing.T, req request) answer {
	t.Helper()
	line, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return run(strings.NewReader(string(line) + "\n"))
}

// A command's answer is what it wrote and how it ended, and a command that
// does not start is an error and no answer of its own.
func TestRunAnswersWithWhatTheCommandWroteAndHowItEnded(t *testing.T) {
	if got := ask(t, request{Argv: []string{"sh", "-c", "echo out; echo err >&2; exit 3"}}); got.ExitCode != 3 || string(got.Stdout) != "out\n" || string(got.Stderr) != "err\n" || got.Error != "" {
		t.Fatalf("the answer: %+v", got)
	}
	if got := ask(t, request{Argv: []string{filepath.Join(t.TempDir(), "none")}}); got.Error == "" {
		t.Fatalf("a command that is not there was answered %+v", got)
	}
	for name, line := range map[string]string{"no command": "{}\n", "no JSON": "true\n", "no line": `{"argv":["true"]}`} {
		if got := run(strings.NewReader(line)); got.Error == "" {
			t.Fatalf("%s: answered %+v", name, got)
		}
	}
}

// A request's credentials are in place when its command runs, readable by
// the command's user alone, and one of an earlier request is replaced. A
// name that would leave the directory is refused, and so is any credential
// for an agent that has no directory for them: the command then does not
// run.
func TestCredentialsAreInPlaceBeforeTheCommandRuns(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(credentialsDir, dir)
	read := []string{"sh", "-c", `cat "$C8S_CREDENTIALS_DIR/api-token"`}
	for _, secret := range []string{"s3cr3t", "another"} {
		if got := ask(t, request{Argv: read, Credentials: map[string][]byte{"api-token": []byte(secret)}}); string(got.Stdout) != secret || got.ExitCode != 0 || got.Error != "" {
			t.Fatalf("the command read %q back, want %q: %+v", got.Stdout, secret, got)
		}
	}
	if info, err := os.Stat(filepath.Join(dir, "api-token")); err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("the credential as it was written: %v, %v", info, err)
	}
	marker := filepath.Join(t.TempDir(), "ran")
	touch := []string{"sh", "-c", `: > "$0"`, marker}
	for _, name := range []string{"", ".", "..", "../outside", "a/b"} {
		if got := ask(t, request{Argv: touch, Credentials: map[string][]byte{name: []byte("x")}}); got.Error == "" {
			t.Fatalf("a credential named %q was taken: %+v", name, got)
		}
	}
	t.Setenv(credentialsDir, "")
	if got := ask(t, request{Argv: touch, Credentials: map[string][]byte{"api-token": []byte("x")}}); got.Error == "" {
		t.Fatalf("an agent with no directory for credentials took one: %+v", got)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a command ran whose credentials were refused")
	}
}

// An init's environment is a variable a line, with whatever follows the
// first equals sign as its value, and any other line is skipped.
func TestEnvironmentIsAVariableALine(t *testing.T) {
	got := environment([]byte("PATH=/usr/local/bin:/bin\nNODE_VERSION=24.1.0\n\nnot a variable\nEMPTY=\nA=b=c\n=nameless\n"))
	want := [][2]string{{"PATH", "/usr/local/bin:/bin"}, {"NODE_VERSION", "24.1.0"}, {"EMPTY", ""}, {"A", "b=c"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the environment read: %v, want %v", got, want)
	}
}

// A request to read a directory reads every file under it and answers once
// it has, with or without a command after it. One for a directory that is
// not there is an error, and its command does not run.
func TestReadReadsATreeBeforeItsCommand(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a", "sub/b", "sub/deeper/c"} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("nowhere", filepath.Join(root, "dangling")); err != nil {
		t.Fatal(err)
	}
	if got := ask(t, request{Read: root}); got.Error != "" || got.ExitCode != 0 {
		t.Fatalf("a read alone: %+v", got)
	}
	if got := ask(t, request{Read: root, Argv: []string{"sh", "-c", "echo after"}}); string(got.Stdout) != "after\n" || got.Error != "" {
		t.Fatalf("a read and a command: %+v", got)
	}
	marker := filepath.Join(t.TempDir(), "ran")
	if got := ask(t, request{Read: filepath.Join(root, "none"), Argv: []string{"sh", "-c", `: > "$0"`, marker}}); got.Error == "" {
		t.Fatalf("a read of a directory that is not there: %+v", got)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a command ran after a read that failed")
	}
}
