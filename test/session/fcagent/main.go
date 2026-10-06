// Command fcagent is the agent in the guest of the Firecracker baselines of
// test/session/timing.sh and test/session/burst.sh. It takes one command a
// connection over vsock and answers with what the command wrote and how it
// ended.
//
//	fcagent [<port>]
//
// A request is one line of JSON, {"argv": ["true"]}. With "credentials", a
// name and its bytes in base64 each, the agent first writes each under
// $C8S_CREDENTIALS_DIR, where a session's first command finds a credential
// that came with its bind. The answer is one line too: {"exit_code": 0,
// "stdout": "...", "stderr": "..."}, both outputs in base64, or {"error":
// "..."} for a command that did not start. A request with "read", a
// directory, has the agent read every file of that directory's file system
// first, as a pooled session guest has its sandbox image unpacked, and in
// its memory, before anybody binds it. A request with "word" is answered
// twice: with the line {"taken": true} once the agent has the command and
// its credentials in place, before it runs it, and then with the answer.
//
// Started as a guest's init it is all the user space that guest has: the
// leanest guest that takes a command. It mounts what a command expects of a
// system, takes its environment from the file env beside it, a variable a
// line, keeps $C8S_CREDENTIALS_DIR in memory, and serves on port 5000. The
// guest's root file system is then the sandbox: the tree commands run in.
//
// It authenticates nobody, encrypts nothing and confines nothing: it is what
// a platform that runs sessions in such a guest would have to add to, and so
// a floor for one, reached the way a session's first command is reached.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/confidential-dot-ai/c8s/internal/vsock"
)

const (
	maxRequest = 64 << 10
	maxOutput  = 1 << 20
	// initPort is where an agent that is its guest's init serves.
	initPort = 5000
	// credentialsDir names the directory a command finds its credentials in.
	credentialsDir = "C8S_CREDENTIALS_DIR"
)

type request struct {
	Argv        []string          `json:"argv"`
	Credentials map[string][]byte `json:"credentials,omitempty"`
	Read        string            `json:"read,omitempty"`
	Word        bool              `json:"word,omitempty"`
}

type answer struct {
	ExitCode int    `json:"exit_code"`
	Stdout   []byte `json:"stdout"`
	Stderr   []byte `json:"stderr"`
	Error    string `json:"error,omitempty"`
}

// taken is the agent's word that it has a command and will now run it.
const taken = `{"taken":true}` + "\n"

func main() {
	port := uint64(initPort)
	if os.Getpid() == 1 {
		// A kernel hands its init whatever words of its command line it
		// did not know: none of them is the agent's.
		if err := becomeInit(); err != nil {
			fmt.Fprintln(os.Stderr, "fcagent:", err)
			os.Exit(1)
		}
	} else {
		if len(os.Args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: fcagent <port>")
			os.Exit(2)
		}
		var err error
		if port, err = strconv.ParseUint(os.Args[1], 10, 32); err != nil {
			fmt.Fprintln(os.Stderr, "fcagent: port:", err)
			os.Exit(2)
		}
	}
	listener, err := vsock.Listen(uint32(port), 128)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fcagent:", err)
		os.Exit(1)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, "fcagent:", err)
			os.Exit(1)
		}
		go serve(conn)
	}
}

func serve(conn net.Conn) {
	defer conn.Close()
	out := run(conn, func() { _, _ = io.WriteString(conn, taken) })
	data, err := json.Marshal(out)
	if err != nil {
		return
	}
	_, _ = conn.Write(append(data, '\n'))
}

// run reads a request and does what it asks. It calls word once the
// request's command is the next thing it does, if the request asked for it.
func run(conn io.Reader, word func()) answer {
	line, err := bufio.NewReaderSize(io.LimitReader(conn, maxRequest), maxRequest).ReadBytes('\n')
	if err != nil {
		return answer{Error: "the request is one line of at most " + strconv.Itoa(maxRequest) + " bytes"}
	}
	var req request
	if err := json.Unmarshal(line, &req); err != nil || len(req.Argv) == 0 && req.Read == "" {
		return answer{Error: "the request names no command"}
	}
	if req.Read != "" {
		if err := readTree(req.Read); err != nil {
			return answer{Error: err.Error()}
		}
		if len(req.Argv) == 0 {
			return answer{}
		}
	}
	for name, value := range req.Credentials {
		if err := putCredential(name, value); err != nil {
			return answer{Error: err.Error()}
		}
	}
	if req.Word {
		word()
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(req.Argv[0], req.Argv[1:]...)
	cmd.Stdout, cmd.Stderr = &capped{to: &stdout}, &capped{to: &stderr}
	err = cmd.Run()
	var exited *exec.ExitError
	switch {
	case errors.As(err, &exited):
		return answer{ExitCode: exited.ExitCode(), Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	case err != nil:
		return answer{Error: err.Error()}
	}
	return answer{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
}

// putCredential writes a credential where the command that follows finds
// it, readable by the command's user alone.
func putCredential(name string, value []byte) error {
	dir := os.Getenv(credentialsDir)
	if dir == "" {
		return errors.New("this agent has no " + credentialsDir + " to put a credential in")
	}
	if name == "" || name == "." || name == ".." || name != filepath.Base(name) {
		return fmt.Errorf("%q is no name for a credential", name)
	}
	path := filepath.Join(dir, name)
	// One from a request before is replaced, whatever its mode.
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("credential %s: %w", name, err)
	}
	if err := os.WriteFile(path, value, 0o400); err != nil {
		return fmt.Errorf("credential %s: %w", name, err)
	}
	return nil
}

// readTree reads every regular file under root that is on root's own file
// system, and keeps nothing of them: they are then in the guest's memory.
func readTree(root string) error {
	top, err := os.Stat(root)
	if err != nil {
		return err
	}
	on, known := device(top)
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			// A file that went away, or one of the kernel's that is not to
			// be read, is no part of the tree.
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			if here, ok := device(info); known && ok && here != on {
				return filepath.SkipDir
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()
		_, _ = io.Copy(io.Discard, file)
		return nil
	})
}

// device is the file system a file is on, where the system says.
func device(info fs.FileInfo) (uint64, bool) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Dev), true //nolint:unconvert // the field's type differs by system
	}
	return 0, false
}

// environment reads a variable a line, NAME=value, and skips any other line.
func environment(data []byte) [][2]string {
	var out [][2]string
	for _, line := range strings.Split(string(data), "\n") {
		if name, value, ok := strings.Cut(line, "="); ok && name != "" {
			out = append(out, [2]string{name, value})
		}
	}
	return out
}

// capped keeps the first maxOutput bytes written to it and drops the rest.
type capped struct{ to *bytes.Buffer }

func (c *capped) Write(p []byte) (int, error) {
	if room := maxOutput - c.to.Len(); room > 0 {
		c.to.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}
