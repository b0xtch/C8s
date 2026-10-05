package sessionagent_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/disclosure"
)

// A bind the guest refuses is refused for what it is: bytes that are no bind
// its schema takes, or a bind whose signature is not its authority's. The
// guest reads the document once to tell the two apart, and ends either way.
func TestRefusedBindSaysWhetherItIsNoBindOrBadlySigned(t *testing.T) {
	refused := func(t *testing.T, raw []byte, signature string) (int, disclosure.Code) {
		t.Helper()
		p := newPool(t)
		p.start(t)
		request, err := json.Marshal(session.BindRequest{Bind: raw, Signature: signature})
		if err != nil {
			t.Fatal(err)
		}
		client := insecureClient()
		defer client.CloseIdleConnections()
		resp, err := client.Post(p.url+session.PathBind, "application/json", bytes.NewReader(request))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.fatal(t); err == nil {
			t.Fatal("a guest that refused a bind carries on")
		}
		return resp.StatusCode, refusalCode(body)
	}
	// A bind in order, and another authority's signature over another one.
	p := newPool(t)
	p.start(t)
	ready, err := p.client(t, p.access).Ready(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	bind := p.bindFor(t, ready, nil)
	other := p.bindFor(t, ready, func(o *session.BindOptions) { o.Authority = newECKey(t) })
	spaced := append(bytes.Clone(bind.Raw), '\n')
	for name, tc := range map[string]struct {
		raw       []byte
		signature string
		want      disclosure.Code
	}{
		"no JSON":                            {[]byte("bind me"), bind.Signature, disclosure.BindInvalid},
		"another document":                   {[]byte(`{"schemaVersion":"c8s-bind/v1"}`), bind.Signature, disclosure.BindInvalid},
		"a bind that is not canonical":       {spaced, bind.Signature, disclosure.BindInvalid},
		"no bind under a signature too long": {[]byte("bind me"), strings.Repeat("A", 1<<16), disclosure.BindInvalid},
		"another authority's signature":      {bind.Raw, other.Signature, disclosure.BindSignature},
		"no signature that is one":           {bind.Raw, "c2lnbmF0dXJl", disclosure.BindSignature},
		"a signature too long":               {bind.Raw, strings.Repeat("A", 1<<16), disclosure.BindSignature},
	} {
		if status, code := refused(t, tc.raw, tc.signature); status != http.StatusBadRequest || code != tc.want {
			t.Errorf("%s: refused with %d %s, want %s", name, status, code, tc.want)
		}
	}
}
