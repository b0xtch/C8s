// Command fcagent is the agent in the guest of the Firecracker baseline of
// test/session/timing.sh. It takes one command a connection over vsock and
// answers with what the command wrote and how it ended.
//
//	fcagent <port>
//
// A request is one line of JSON, {"argv": ["true"]}. The answer is one line
// too: {"exit_code": 0, "stdout": "...", "stderr": "..."}, both outputs in
// base64, or {"error": "..."} for a command that did not start.
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
	"net"
	"os"
	"os/exec"
	"strconv"

	"github.com/confidential-dot-ai/c8s/internal/vsock"
)

const (
	maxRequest = 64 << 10
	maxOutput  = 1 << 20
)

type request struct {
	Argv []string `json:"argv"`
}

type answer struct {
	ExitCode int    `json:"exit_code"`
	Stdout   []byte `json:"stdout"`
	Stderr   []byte `json:"stderr"`
	Error    string `json:"error,omitempty"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: fcagent <port>")
		os.Exit(2)
	}
	port, err := strconv.ParseUint(os.Args[1], 10, 32)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fcagent: port:", err)
		os.Exit(2)
	}
	listener, err := vsock.Listen(uint32(port), 16)
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
	out := run(conn)
	data, err := json.Marshal(out)
	if err != nil {
		return
	}
	_, _ = conn.Write(append(data, '\n'))
}

func run(conn io.Reader) answer {
	line, err := bufio.NewReaderSize(io.LimitReader(conn, maxRequest), maxRequest).ReadBytes('\n')
	if err != nil {
		return answer{Error: "the request is one line of at most " + strconv.Itoa(maxRequest) + " bytes"}
	}
	var req request
	if err := json.Unmarshal(line, &req); err != nil || len(req.Argv) == 0 {
		return answer{Error: "the request names no command"}
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

// capped keeps the first maxOutput bytes written to it and drops the rest.
type capped struct{ to *bytes.Buffer }

func (c *capped) Write(p []byte) (int, error) {
	if room := maxOutput - c.to.Len(); room > 0 {
		c.to.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}
