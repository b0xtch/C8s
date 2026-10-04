package sessionagent_test

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/keyservice"
	"github.com/confidential-dot-ai/c8s/pkg/session/sessionsim"
)

// A key service's guest stages its launch document as an agent stages a
// pool's: for its own image, and on a machine the document lists. On
// another machine it measures nothing and ends. Under a document that lists
// none it goes on, and its service then releases nothing.
func TestMeasureDocumentHoldsAGuestToItsListedMachines(t *testing.T) {
	pool := sessionsim.NewPool(t)
	for name, tc := range map[string]struct {
		machines func(td *sessiontest.TD) []string
		want     string
	}{
		"the machine it is": {func(td *sessiontest.TD) []string { return []string{hex.EncodeToString(td.RTMR[0][:])} }, ""},
		"another machine":   {func(*sessiontest.TD) []string { return []string{strings.Repeat("0", 96)} }, "is none of the 1 its launch document lists"},
		"none listed":       {func(*sessiontest.TD) []string { return nil }, ""},
	} {
		td := sessiontest.NewTD()
		dir := filepath.Join(t.TempDir(), "key-service")
		if err := keyservice.NewBundle(keyservice.BundleOptions{
			Dir: dir, ManifestPath: td.WriteManifest(t), Machines: tc.machines(td),
			Pools: []keyservice.PoolOptions{{ManifestPath: pool.ManifestPath, LaunchKeyPath: pool.LaunchKeyPath}},
		}); err != nil {
			t.Fatal(err)
		}
		opkey := filepath.Join(dir, session.OpkeyDir)
		pub, err := os.ReadFile(filepath.Join(opkey, session.PubkeyFile))
		if err != nil {
			t.Fatal(err)
		}
		td.SeedLaunchKey(pub)
		seeded := td.RTMR[3]
		measured, err := sessionagent.MeasureDocument(ctxT(t), sessiontest.TEE{TD: td}, "tdx", filepath.Join(opkey, session.PubkeyFile), opkey,
			func(pub, launch []byte, signature string) (session.Image, *session.Machine, error) {
				doc, err := keyservice.VerifySigned(pub, launch, signature)
				if err != nil {
					return session.Image{}, nil, err
				}
				return doc.Image, doc.Machine, nil
			})
		if tc.want == "" {
			if err != nil || measured == nil || td.RTMR[3] == seeded {
				t.Errorf("%s: %v (measured %v)", name, err, td.RTMR[3] != seeded)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error naming %q", name, err, tc.want)
		}
		if td.RTMR[3] != seeded {
			t.Errorf("%s: the guest measured a document it does not run under", name)
		}
	}
}
