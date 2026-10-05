package sessionlauncher

import (
	"encoding/json"
	"log/slog"
	"net"
	"sync"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/internal/guestend"
	"github.com/confidential-dot-ai/c8s/internal/vsock"
	"github.com/confidential-dot-ai/c8s/pkg/session/disclosure"
)

// lastWord takes the word a guest says as it ends itself: how far it had
// come and why. One word is taken, the first that is the schema's and comes
// from this launcher's guest. It is logged, and written to a file for whoever
// started the launcher when a file is named. A guest that says none, or
// anything else, leaves none: the launcher's log then says only that its
// VMM ended.
type lastWord struct {
	ln   net.Listener
	own  func(net.Conn) bool
	file string
	log  *slog.Logger
	once sync.Once
}

// listenLastWord listens for the word of the guest whose context id is cid.
// The port it returns is what the guest's init dials.
func listenLastWord(cid uint32, file string, log *slog.Logger) (*lastWord, uint32, error) {
	ln, err := vsock.Listen(vsock.AnyPort, 1)
	if err != nil {
		return nil, 0, err
	}
	w := &lastWord{
		ln: ln, file: file, log: log,
		own: func(conn net.Conn) bool { peer, ok := conn.(*vsock.Conn); return ok && peer.Peer() == cid },
	}
	go w.serve()
	return w, ln.Port(), nil
}

func (w *lastWord) Close() error { return w.ln.Close() }

// serve takes connections until the listener is closed. Each is read for a
// bounded time, one at a time: a guest has one word to say.
func (w *lastWord) serve() {
	for {
		conn, err := w.ln.Accept()
		if err != nil {
			return
		}
		w.take(conn)
	}
}

func (w *lastWord) take(conn net.Conn) {
	defer conn.Close()
	if !w.own(conn) {
		return
	}
	end, err := guestend.Receive(conn, guestend.Wait)
	if err != nil {
		w.log.Warn("the guest's last word is none the disclosure schema allows", "error", err)
		return
	}
	w.once.Do(func() { w.keep(end) })
}

func (w *lastWord) keep(end *disclosure.End) {
	said := []any{"phase", end.Phase, "code", end.Code}
	if end.Status != nil {
		said = append(said, "status", *end.Status)
	}
	if end.Signal != nil {
		said = append(said, "signal", *end.Signal, "memory", end.Memory)
	}
	w.log.Info("the guest said why it ends", said...)
	if w.file == "" {
		return
	}
	data, err := json.Marshal(end)
	if err == nil {
		err = fileutil.WriteAtomic(w.file, append(data, '\n'), 0o600)
	}
	if err != nil {
		w.log.Warn("the guest's last word was not kept", "error", err)
	}
}
