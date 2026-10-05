package sessiond

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The reason of a TD whose guest ended carries the guest's last word, as its
// launcher kept it, held to the schema again. A TD with no word, or with a
// file that is no word, ended and nothing more is said.
func TestGuestEndedCarriesTheGuestsLastWord(t *testing.T) {
	d := &Daemon{
		cfg: &Config{StateDir: t.TempDir()}, log: slog.New(slog.DiscardHandler), now: time.Now,
		tds: map[string]*td{}, changed: make(chan struct{}),
	}
	for name, tc := range map[string]struct {
		kept *string
		want string
	}{
		"the session's process ended": {ptr(`{"phase":"running","code":"process_ended"}` + "\n"), "the guest ended: process_ended in phase running"},
		"the service exited":          {ptr(`{"phase":"ready","code":"service_exited","status":1}`), "the guest ended: service_exited (status 1) in phase ready"},
		"the service was killed":      {ptr(`{"phase":"running","code":"service_killed","signal":9,"memory":true}`), "the guest ended: service_killed (signal 9, by the kernel for memory) in phase running"},
		"no word":                     {nil, "the guest ended"},
		"a file that is no word":      {ptr(`{"phase":"running","code":"the tenant's secret"}`), "the guest ended"},
		"an empty file":               {ptr(""), "the guest ended"},
	} {
		td := &td{rec: record{ID: "td-" + filepath.Base(t.TempDir())}}
		if err := os.MkdirAll(d.dir(td.rec.ID), 0o700); err != nil {
			t.Fatal(err)
		}
		if tc.kept != nil {
			if err := os.WriteFile(filepath.Join(d.dir(td.rec.ID), endFile), []byte(*tc.kept), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if got := d.guestEnded(td); got != tc.want {
			t.Errorf("%s: the reason is %q, want %q", name, got, tc.want)
		}
	}
}

func ptr(s string) *string { return &s }
