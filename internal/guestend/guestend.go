// Package guestend carries a session guest's last word to its launcher: how
// far the guest had come and why it ends, as the disclosure schema lets it
// say. The guest's init sends it once, as the guest ends itself, over a
// connection to a port its host named. The word is for whoever operates the
// guests. Nothing that guards a session rests on it, so neither side is
// held up by the other: a guest waits a short time for its launcher and ends
// either way, and a launcher takes a word that is not the schema's for none.
//
// The guest writes its word and ends its writing. The launcher reads to that
// end, keeps the word, and closes, which is its answer: a guest that powered
// off on its own write could take the word with it, still on its way out.
package guestend

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/session/disclosure"
)

const (
	// LaunchDir is where a guest's load step stages its launch files.
	LaunchDir = "/run/c8s-session/launch"
	// HostConfigFile is the host's own file among them, which names the port.
	HostConfigFile = LaunchDir + "/host.json"
	// PhaseFile is where a guest's service writes how far it has come, for
	// the init to read once the service has ended.
	PhaseFile = "/run/c8s-session/phase"
	// Wait is how long a guest gives its launcher to take the word, and a
	// launcher gives a guest to say it.
	Wait = 2 * time.Second
	// maxHostConfig bounds the host's file as it is read here.
	maxHostConfig = 16 * 1024
	maxPhase      = 32
)

// servicePhases are the phases a service may write. The init's own, booting
// and starting, are not among them.
var servicePhases = []disclosure.Code{"ready", "bound", "running"}

// Port is the vsock port of the host that a guest's last word goes to, as the
// host's staged file names it, or zero when it names none.
func Port(hostConfig []byte) uint32 {
	if len(hostConfig) > maxHostConfig {
		return 0
	}
	var named struct {
		EndPort uint32 `json:"end_port"`
	}
	if json.Unmarshal(hostConfig, &named) != nil || named.EndPort == ^uint32(0) {
		return 0
	}
	return named.EndPort
}

// Phase is how far a guest had come, from what its service last wrote. A
// service that wrote nothing, or anything else than a phase, had started and
// was not ready.
func Phase(written []byte) disclosure.Code {
	if len(written) > maxPhase {
		return disclosure.EndedStarting
	}
	phase := disclosure.Code(bytes.TrimSpace(written))
	if slices.Contains(servicePhases, phase) {
		return phase
	}
	return disclosure.EndedStarting
}

// Stream is a connection whose one end can stop writing and still read, as
// a vsock stream can.
type Stream interface {
	net.Conn
	CloseWrite() error
}

// Send writes the word to a launcher, ends its writing there and waits for
// the launcher to close, which a launcher does once it has kept the word or
// will keep none. It returns within wait whatever the launcher does, and
// with an error when the launcher had not closed by then.
func Send(conn Stream, end disclosure.End, wait time.Duration) error {
	defer conn.Close()
	word, err := disclosure.Encode(disclosure.MessageEnd, end)
	if err != nil {
		return err
	}
	if err := conn.SetDeadline(time.Now().Add(wait)); err != nil {
		return err
	}
	if _, err := conn.Write(word); err != nil {
		return err
	}
	if err := conn.CloseWrite(); err != nil {
		return err
	}
	// A launcher says nothing back: the end of its stream is its answer.
	if _, err := io.Copy(io.Discard, conn); err != nil {
		return fmt.Errorf("its launcher had not taken the word: %w", err)
	}
	return nil
}

// Receive reads one word from a guest, to the end of the guest's writing,
// and holds it to the schema. A word that arrived whole is taken though the
// stream failed after it, as the stream of a guest that is gone does. It
// returns within wait whatever the guest does. The caller closes the
// connection once it has done with the word what it will: the guest waits
// for that.
func Receive(conn net.Conn, wait time.Duration) (*disclosure.End, error) {
	if err := conn.SetDeadline(time.Now().Add(wait)); err != nil {
		return nil, err
	}
	word, failed := io.ReadAll(io.LimitReader(conn, disclosure.MaxEnd+1))
	end, err := disclosure.ParseEnd(bytes.TrimSpace(word))
	if err != nil && failed != nil {
		return nil, errors.New("the guest's last word did not arrive whole")
	}
	return end, err
}
