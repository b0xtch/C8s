package session

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

// Egress is the sandbox's outbound allowlist. The sandbox has no network of
// its own: every connection it opens leaves through the agent's proxy, which
// refuses a destination this list does not name.
type Egress struct {
	// Allow lists destinations as host:port. A host is a DNS name, a name
	// with a leading "*." that stands for exactly one label, or an IP
	// address, in brackets when it is IPv6. An empty list allows nothing.
	Allow []string `yaml:"allow" json:"allow"`
}

const maxEgressRules = 64

// egressRule is one parsed entry of Egress.Allow.
type egressRule struct {
	// name is a lowercase DNS name, or the suffix after "*" of a wildcard
	// (".example.com"). Empty when the rule names an address.
	name     string
	wildcard bool
	addr     netip.Addr
	port     int
}

func parseEgressRule(rule string) (egressRule, error) {
	host, portText, err := net.SplitHostPort(rule)
	if err != nil {
		return egressRule{}, errors.New("must be host:port")
	}
	port, err := strconv.Atoi(portText)
	// Atoi takes a sign and leading zeros, which would be a second spelling.
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portText {
		return egressRule{}, errors.New("port must be 1..65535")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return egressRule{}, errors.New("an address takes no zone")
		}
		return egressRule{addr: addr.Unmap(), port: port}, nil
	}
	name, wildcard := strings.CutPrefix(host, "*.")
	if name != strings.ToLower(name) || len(validation.IsDNS1123Subdomain(name)) > 0 {
		return egressRule{}, errors.New("host must be a lowercase DNS name, such a name under \"*.\", or an IP address")
	}
	if wildcard {
		name = "." + name
	}
	return egressRule{name: name, wildcard: wildcard, port: port}, nil
}

func (e *Egress) validate() error {
	// A missing list would read as an empty one. Whoever signs says which.
	if e.Allow == nil {
		return errors.New("allow must be a list; an empty one allows nothing")
	}
	if len(e.Allow) > maxEgressRules {
		return fmt.Errorf("allow has more than %d entries", maxEgressRules)
	}
	seen := make(map[string]bool, len(e.Allow))
	for _, rule := range e.Allow {
		if _, err := parseEgressRule(rule); err != nil {
			return fmt.Errorf("allow entry %q: %w", rule, err)
		}
		if seen[rule] {
			return fmt.Errorf("allow lists %q twice", rule)
		}
		seen[rule] = true
	}
	return nil
}

// Allows reports whether the sandbox may connect to host:port. host is what
// the sandbox asked for, a name or an address, before anything resolved it.
// A nil Egress allows every destination.
func (e *Egress) Allows(host string, port int) bool {
	if e == nil {
		return true
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	asked, askedErr := netip.ParseAddr(host)
	for _, raw := range e.Allow {
		rule, err := parseEgressRule(raw)
		if err != nil || rule.port != port {
			continue
		}
		switch {
		case rule.addr.IsValid():
			if askedErr == nil && asked.Unmap() == rule.addr {
				return true
			}
		case askedErr == nil:
			// A name never matches an address: the rule's author chose what
			// the name resolves to by choosing the name.
		case rule.wildcard:
			// One label and no more.
			if label, under := strings.CutSuffix(host, rule.name); under && label != "" && !strings.Contains(label, ".") {
				return true
			}
		case host == rule.name:
			return true
		}
	}
	return false
}
