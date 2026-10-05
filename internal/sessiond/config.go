// Package sessiond is the c8s daemon of the session API: it keeps pools of
// ready TDs on one host and hands them to sessions. docs/session-api.md is
// the design.
//
// The daemon is outside the trust boundary. It relays documents and
// evidence it does not judge, moves bytes it cannot read, and starts and
// ends TDs. A daemon that cheats can deny service and nothing more: every
// caller acts on evidence it has verified itself.
package sessiond

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

const (
	// DefaultBindGrace is how long a claim waits for its bind.
	DefaultBindGrace = 30 * time.Second
	// DefaultBootTimeout is how long a TD may take to serve.
	DefaultBootTimeout = 5 * time.Minute
	// maxConfigBytes bounds the daemon's configuration file.
	maxConfigBytes = 1 << 20
	// maxBinders bounds the callers a pool's configuration lets watch it,
	// and maxAuthorities the authorities it names for one of them.
	maxBinders     = 64
	maxAuthorities = 64
)

// binderRE is a binder as a pool's configuration names it, and an authority
// it names for one: the digest of a public key.
var binderRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Binder is a caller a pool names by the key of its certificate. It may
// watch the pool's ready TDs, and claim one with a bind under an authority
// the pool names for it.
type Binder struct {
	// Key is the SHA-256 of the public key in the binder's certificate, as
	// sha256:<64 hex>.
	Key string `yaml:"key"`
	// Authorities are the owners' authorities whose binds the binder may
	// send to a ready TD of the pool that no claim holds, each as the
	// SHA-256 of its public key. With none the binder watches the pool and
	// claims nothing: an outsider, or one tenant's binder signing under
	// another authority, starts no session on the pool's TDs.
	Authorities []string `yaml:"authorities,omitempty"`
}

// UnmarshalYAML takes a binder as its key alone, which names one that only
// watches, or as a mapping with the authorities it may bind under.
func (b *Binder) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		return node.Decode(&b.Key)
	}
	if node.Kind != yaml.MappingNode {
		return errors.New("a binder is the digest of its key, or a mapping with key and authorities")
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		switch name := node.Content[i].Value; name {
		case "key":
			if err := node.Content[i+1].Decode(&b.Key); err != nil {
				return err
			}
		case "authorities":
			if err := node.Content[i+1].Decode(&b.Authorities); err != nil {
				return err
			}
		default:
			return fmt.Errorf("a binder has no field %q", name)
		}
	}
	return nil
}

// binder returns the pool's entry for the caller of this key, or nil.
func (p *Pool) binder(key string) *Binder {
	for i := range p.Binders {
		if p.Binders[i].Key == key {
			return &p.Binders[i]
		}
	}
	return nil
}

// binds reports whether the pool lets the caller of this key claim a TD
// with a bind under this authority.
func (p *Pool) binds(key, authority string) bool {
	b := p.binder(key)
	return b != nil && slices.Contains(b.Authorities, authority)
}

// Networks a TD's guest can be given.
const (
	// NetworkTap gives each TD a tap of its own with an address block of its
	// own, and filters what its guest may reach.
	NetworkTap = "tap"
	// NetworkUser is the VMM's user-mode stack, with the guest's TLS port
	// forwarded to a loopback port. It needs no privilege and filters
	// nothing: for development only.
	NetworkUser = "user"
)

// Config is the daemon's configuration file.
type Config struct {
	// Listen is the address the session API is served on.
	Listen string `yaml:"listen"`
	// Host is the name the daemon gives its host in answers. Empty is the
	// host's own name.
	Host string `yaml:"host,omitempty"`
	// StateDir holds a directory per TD: its record, its launch disk and its
	// launcher's log.
	StateDir string `yaml:"stateDir"`
	// Capacity is the most TDs this host runs at once, in every state.
	Capacity int       `yaml:"capacity"`
	TLS      TLSConfig `yaml:"tls"`
	Network  Network   `yaml:"network"`
	VMM      VMM       `yaml:"vmm,omitempty"`
	// Classes are the launch shapes this host offers, by name. A pool's
	// launch document names one.
	Classes map[string]Class `yaml:"classes"`
	Pools   []Pool           `yaml:"pools"`
}

// TLSConfig is the daemon's own identity and the authority its orchestrators
// present certificates of.
type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	// ClientCA signs the certificates of callers that may claim, bind and
	// destroy. Evidence and connections to bound TDs need none.
	ClientCA string `yaml:"clientCA"`
}

// Network is how TDs are attached.
type Network struct {
	Mode string `yaml:"mode"`
	// GuestCIDR is the block TDs' addresses are cut from, four to a TD
	// (NetworkTap). It must be the daemon's alone.
	GuestCIDR string `yaml:"guestCIDR,omitempty"`
	// EgressInterface, when set, is the one interface guests' traffic may
	// leave the host on, under the host's address (NetworkTap). Unset, a
	// guest reaches nothing.
	EgressInterface string `yaml:"egressInterface,omitempty"`
	// Reach lists what every guest may connect to whatever else is closed, as
	// address:port over TCP: the key service of its pool, for one
	// (NetworkTap).
	Reach []string `yaml:"reach,omitempty"`
	// TapPrefix starts the name of each TD's tap (NetworkTap), and names
	// the daemon's table in the packet filter. A second daemon on a host
	// takes one of its own, which neither begins the other's: each then
	// matches its own taps alone. Empty is "c8st".
	TapPrefix string `yaml:"tapPrefix,omitempty"`
	// DNS are the resolvers a guest is told, up to three.
	DNS []string `yaml:"dns,omitempty"`
	// FirstPort is the loopback port of the first TD (NetworkUser).
	FirstPort int `yaml:"firstPort,omitempty"`
}

// VMM is how this host boots a TD.
type VMM struct {
	// QEMU is the VMM binary.
	QEMU string `yaml:"qemu,omitempty"`
	// QuoteSocket is the host's quoting service (TDX).
	QuoteSocket string `yaml:"quoteSocket,omitempty"`
	// Confine runs the VMM as this numeric uid[:gid] with no capability.
	Confine string `yaml:"confine,omitempty"`
	// Console attaches each guest's console to its launcher's log. A locked
	// image prints nothing there.
	Console bool `yaml:"console,omitempty"`
}

// Class is a launch shape: what a TD of the class is booted with. The shape
// decides RTMR[0], so a class is a set of reference values.
type Class struct {
	VCPUs  int    `yaml:"vcpus"`
	Memory string `yaml:"memory"`
	// LowMemory is how much of the memory sits below 4 GiB. Empty leaves the
	// machine's own split.
	LowMemory string `yaml:"lowMemory,omitempty"`
	// Scratch is the size of the encrypted scratch disk.
	Scratch string `yaml:"scratch,omitempty"`
}

// Pool is a set of ready TDs of one image and one class.
type Pool struct {
	// ImageDir is the session guest image: its disk, firmware and manifest.
	ImageDir string `yaml:"imageDir"`
	// LaunchDir is the opkeydata directory of the pool's launch bundle. The
	// pool takes its name and its class from the launch document there.
	LaunchDir string `yaml:"launchDir"`
	// Depth is how many TDs the pool keeps ready.
	Depth int `yaml:"depth"`
	// BindGrace is how long a claim waits for its bind before the TD returns
	// to the pool.
	BindGrace Duration `yaml:"bindGrace,omitempty"`
	// ImageStore is a store of public images handed to every guest.
	ImageStore string `yaml:"imageStore,omitempty"`
	// Binders are the callers that may watch the pool's ready TDs
	// (WatchReady), each named by the SHA-256 of the public key in its
	// certificate. A stream shows how fast the pool refills, which is every
	// tenant's starts together, so it is open to nobody else: with none
	// named, to nobody. A binder may also claim a ready TD with a bind, under
	// the authorities the pool names for it.
	Binders []Binder `yaml:"binders,omitempty"`

	// From the launch document.
	name     string
	class    string
	platform string
}

// Name is the pool's name: its launch document's.
func (p *Pool) Name() string { return p.name }

// Duration is a time.Duration written as Go writes one: 30s, 2m.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var text string
	if err := node.Decode(&text); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(text)
	if err != nil {
		return fmt.Errorf("line %d: %w", node.Line, err)
	}
	*d = Duration(parsed)
	return nil
}

var sizeRE = regexp.MustCompile(`^[1-9][0-9]{0,6}[MG]$`)

// LoadConfig reads and checks the daemon's configuration file. Relative
// paths in it are taken from the file's directory.
func LoadConfig(path string) (*Config, error) {
	data, err := session.ReadBounded(path, maxConfigBytes)
	if err != nil {
		return nil, err
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	base := filepath.Dir(path)
	for _, p := range []*string{&cfg.StateDir, &cfg.TLS.Cert, &cfg.TLS.Key, &cfg.TLS.ClientCA} {
		*p = resolve(base, *p)
	}
	for i := range cfg.Pools {
		pool := &cfg.Pools[i]
		for _, p := range []*string{&pool.ImageDir, &pool.LaunchDir, &pool.ImageStore} {
			*p = resolve(base, *p)
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &cfg, nil
}

func resolve(base, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}

// Validate checks the configuration and reads each pool's launch document.
func (c *Config) Validate() error {
	if c.Listen == "" {
		return errors.New("listen is required")
	}
	if c.StateDir == "" {
		return errors.New("stateDir is required")
	}
	if c.Capacity <= 0 {
		return errors.New("capacity must be at least 1: it is the most TDs this host runs at once")
	}
	if c.TLS.Cert == "" || c.TLS.Key == "" || c.TLS.ClientCA == "" {
		return errors.New("tls.cert, tls.key and tls.clientCA are required")
	}
	if c.Host == "" {
		host, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("host: %w", err)
		}
		c.Host = host
	}
	if err := c.Network.validate(c.Capacity); err != nil {
		return fmt.Errorf("network: %w", err)
	}
	if len(c.Classes) == 0 {
		return errors.New("classes: at least one is required")
	}
	for name, class := range c.Classes {
		if err := class.validate(); err != nil {
			return fmt.Errorf("class %s: %w", name, err)
		}
	}
	if len(c.Pools) == 0 {
		return errors.New("pools: at least one is required")
	}
	seen := map[string]bool{}
	depth := 0
	for i := range c.Pools {
		pool := &c.Pools[i]
		if err := pool.load(); err != nil {
			return fmt.Errorf("pool %d: %w", i, err)
		}
		if seen[pool.name] {
			return fmt.Errorf("two pools are named %s", pool.name)
		}
		seen[pool.name] = true
		if _, ok := c.Classes[pool.class]; !ok {
			return fmt.Errorf("pool %s: its launch document names class %s, which this host does not offer", pool.name, pool.class)
		}
		depth += pool.Depth
	}
	if depth > c.Capacity {
		return fmt.Errorf("the pools keep %d TDs ready and the host's capacity is %d", depth, c.Capacity)
	}
	return nil
}

func (n *Network) validate(capacity int) error {
	if len(n.DNS) > 3 {
		return errors.New("dns: a guest takes three resolvers at most")
	}
	for _, dns := range n.DNS {
		if _, err := netip.ParseAddr(dns); err != nil {
			return fmt.Errorf("dns: %w", err)
		}
	}
	switch n.Mode {
	case NetworkTap:
		prefix, err := netip.ParsePrefix(n.GuestCIDR)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
			return fmt.Errorf("guestCIDR %q is not an IPv4 network", n.GuestCIDR)
		}
		if slots := 1 << (30 - prefix.Bits()); prefix.Bits() > 30 || slots < capacity {
			return fmt.Errorf("guestCIDR %s holds fewer than the %d TDs of the host's capacity: each takes four addresses", n.GuestCIDR, capacity)
		}
		if n.FirstPort != 0 {
			return errors.New("firstPort belongs to mode user")
		}
		if n.TapPrefix != "" && !tapPrefixRE.MatchString(n.TapPrefix) {
			return fmt.Errorf("tapPrefix %q is not a lower-case letter and up to nine more letters or digits", n.TapPrefix)
		}
		if len(n.Reach) > maxReach {
			return fmt.Errorf("reach lists more than %d destinations", maxReach)
		}
		if _, err := n.reach(); err != nil {
			return err
		}
	case NetworkUser:
		if n.GuestCIDR != "" || n.EgressInterface != "" || len(n.Reach) > 0 || n.TapPrefix != "" {
			return errors.New("guestCIDR, egressInterface, reach and tapPrefix belong to mode tap")
		}
		if n.FirstPort < 1024 || n.FirstPort+capacity > 65535 {
			return fmt.Errorf("firstPort %d leaves no room for %d loopback ports above 1023", n.FirstPort, capacity)
		}
	default:
		return fmt.Errorf("mode %q is neither %s nor %s", n.Mode, NetworkTap, NetworkUser)
	}
	return nil
}

// maxReach bounds the destinations opened to every guest.
const maxReach = 16

// reach parses the destinations every guest may connect to.
func (n *Network) reach() ([]netip.AddrPort, error) {
	var out []netip.AddrPort
	for _, entry := range n.Reach {
		dest, err := netip.ParseAddrPort(entry)
		if err != nil || !dest.Addr().Is4() || dest.Port() == 0 || dest.String() != entry {
			return nil, fmt.Errorf("reach %q is not an IPv4 address:port", entry)
		}
		out = append(out, dest)
	}
	return out, nil
}

func (c Class) validate() error {
	if c.VCPUs < 1 || c.VCPUs > 512 {
		return fmt.Errorf("vcpus %d is out of range", c.VCPUs)
	}
	if !sizeRE.MatchString(c.Memory) {
		return fmt.Errorf("memory %q needs a size such as 16G", c.Memory)
	}
	for name, size := range map[string]string{"lowMemory": c.LowMemory, "scratch": c.Scratch} {
		if size != "" && !sizeRE.MatchString(size) {
			return fmt.Errorf("%s %q needs a size such as 512M", name, size)
		}
	}
	return nil
}

// load reads the pool's launch document, which names the pool and its class.
// The guest is who enforces the document: reading it here only turns a bundle
// that could never boot into an error at start.
func (p *Pool) load() error {
	if p.ImageDir == "" || p.LaunchDir == "" {
		return errors.New("imageDir and launchDir are required")
	}
	if p.Depth < 0 {
		return errors.New("depth cannot be negative")
	}
	if p.BindGrace == 0 {
		p.BindGrace = Duration(DefaultBindGrace)
	}
	if grace := time.Duration(p.BindGrace); grace < time.Second || grace > 10*time.Minute {
		return fmt.Errorf("bindGrace %s is outside one second to ten minutes", grace)
	}
	if len(p.Binders) > maxBinders {
		return fmt.Errorf("binders: at most %d may watch a pool", maxBinders)
	}
	for i, binder := range p.Binders {
		if !binderRE.MatchString(binder.Key) {
			return fmt.Errorf("binders: %q is not the digest of a certificate's public key, sha256:<64 lowercase hex>", binder.Key)
		}
		if p.binder(binder.Key) != &p.Binders[i] {
			return fmt.Errorf("binders: %s is named twice", binder.Key)
		}
		if len(binder.Authorities) > maxAuthorities {
			return fmt.Errorf("binders: at most %d authorities are named for one binder", maxAuthorities)
		}
		for j, authority := range binder.Authorities {
			if !binderRE.MatchString(authority) {
				return fmt.Errorf("binders: authority %q of %s is not the digest of a public key, sha256:<64 lowercase hex>", authority, binder.Key)
			}
			if slices.Contains(binder.Authorities[:j], authority) {
				return fmt.Errorf("binders: authority %s is named twice for %s", authority, binder.Key)
			}
		}
	}
	pub, err := session.ReadBounded(filepath.Join(p.LaunchDir, session.PubkeyFile), 8192)
	if err != nil {
		return err
	}
	launch, err := session.ReadBounded(filepath.Join(p.LaunchDir, session.DocumentFile), session.MaxDocumentSize)
	if err != nil {
		return err
	}
	signature, err := session.ReadBounded(filepath.Join(p.LaunchDir, session.SignatureFile), 4096)
	if err != nil {
		return err
	}
	doc, err := session.VerifySigned(pub, launch, string(signature))
	if err != nil {
		return fmt.Errorf("launch bundle in %s: %w", p.LaunchDir, err)
	}
	p.name, p.class, p.platform = doc.Pool, doc.Class, doc.Image.Platform
	return nil
}
