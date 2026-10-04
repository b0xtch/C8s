package session

import (
	"strings"
	"testing"
)

func TestEgressAllows(t *testing.T) {
	policy := &Egress{Allow: []string{
		"api.example.com:443",
		"*.pkg.example.org:443",
		"192.0.2.10:5432",
		"[2001:db8::1]:443",
	}}
	if err := policy.validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host string
		port int
		want bool
	}{
		{"api.example.com", 443, true},
		{"API.Example.com.", 443, true},
		{"api.example.com", 80, false},
		{"evil-api.example.com", 443, false},
		{"example.com", 443, false},
		{"a.pkg.example.org", 443, true},
		{"A.Pkg.Example.org.", 443, true},
		// The wildcard stands for one label: not for two, not for none, which
		// is the suffix itself, and not for part of one.
		{"a.b.pkg.example.org", 443, false},
		{"pkg.example.org", 443, false},
		{".pkg.example.org", 443, false},
		{"evilpkg.example.org", 443, false},
		{"192.0.2.10", 5432, true},
		{"::ffff:192.0.2.10", 5432, true},
		{"192.0.2.11", 5432, false},
		{"2001:db8::1", 443, true},
		{"2001:db8:0:0:0:0:0:1", 443, true},
		// A rule that names a host says nothing about an address, whatever
		// the host resolves to.
		{"203.0.113.7", 443, false},
	} {
		if got := policy.Allows(tc.host, tc.port); got != tc.want {
			t.Errorf("Allows(%q, %d) = %t, want %t", tc.host, tc.port, got, tc.want)
		}
	}

	// No policy leaves every destination to the proxy's own rules. A policy
	// with an empty list allows none.
	if !(*Egress)(nil).Allows("anything.example", 1) {
		t.Error("a sandbox with no egress policy was refused")
	}
	if (&Egress{Allow: []string{}}).Allows("api.example.com", 443) {
		t.Error("an empty allowlist allowed a destination")
	}
}

func TestEgressValidate(t *testing.T) {
	for name, tc := range map[string]struct {
		allow []string
		want  string
	}{
		"no list":             {nil, "must be a list"},
		"no port":             {[]string{"example.com"}, "host:port"},
		"port zero":           {[]string{"example.com:0"}, "port must be"},
		"port out of range":   {[]string{"example.com:65536"}, "port must be"},
		"a second spelling":   {[]string{"example.com:0443"}, "port must be"},
		"a port name":         {[]string{"example.com:https"}, "port must be"},
		"upper case":          {[]string{"Example.com:443"}, "lowercase DNS name"},
		"a bare wildcard":     {[]string{"*:443"}, "lowercase DNS name"},
		"a wildcard inside":   {[]string{"a.*.example.com:443"}, "lowercase DNS name"},
		"a scheme":            {[]string{"https://example.com:443"}, "host:port"},
		"a zone":              {[]string{"[fe80::1%eth0]:443"}, "no zone"},
		"twice":               {[]string{"example.com:443", "example.com:443"}, "twice"},
		"too many":            {make([]string, maxEgressRules+1), "more than"},
		"an unbracketed IPv6": {[]string{"2001:db8::1:443"}, "host:port"},
	} {
		err := (&Egress{Allow: tc.allow}).validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error naming %q", name, err, tc.want)
		}
	}
	for _, allow := range [][]string{
		{},
		{"example.com:443", "*.example.com:443", "192.0.2.1:22", "[::1]:8080", "xn--bcher-kva.example:443"},
	} {
		if err := (&Egress{Allow: allow}).validate(); err != nil {
			t.Errorf("allow %v: %v", allow, err)
		}
	}
}
