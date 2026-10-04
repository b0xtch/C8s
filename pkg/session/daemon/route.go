package daemon

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// RouteFile is the name of a route in a binding directory.
const RouteFile = "route.json"

const maxRouteBytes = 256 << 10

// Route is how a session's guest is reached through the daemon of its host:
// what a binding directory keeps beside the bind, so that the owner's next
// command finds the guest. It is trusted for nothing. Whatever answers at the
// end of it is verified as the guest of the bind, or refused.
type Route struct {
	// Daemon is the daemon's address, as host:port.
	Daemon string `json:"daemon"`
	// ServerName is the name the daemon's certificate carries, when that is
	// not Daemon's host.
	ServerName string `json:"serverName,omitempty"`
	// CA is the PEM the daemon's certificate chains to. Empty is the
	// system's roots.
	CA []byte `json:"ca,omitempty"`
	// TD is the guest's TD, as its daemon names it.
	TD string `json:"td"`
}

// WriteRoute keeps r in the binding directory dir.
func WriteRoute(dir string, r *Route) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, RouteFile), append(data, '\n'), 0o600)
}

// LoadRoute reads the route kept in dir. A directory with none, as 'c8s
// session bind' writes for a guest reached by its address, gives nil.
func LoadRoute(dir string) (*Route, error) {
	data, err := session.ReadBounded(filepath.Join(dir, RouteFile), maxRouteBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r Route
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("route: %w", err)
	}
	if r.Daemon == "" || r.TD == "" {
		return nil, errors.New("route: it names no daemon or no TD")
	}
	return &r, nil
}

// Options is how the route's daemon is dialed, with cert for the calls that
// need an orchestrator's.
func (r *Route) Options(cert *tls.Certificate) (Options, error) {
	opts := Options{Address: r.Daemon, ServerName: r.ServerName, Certificate: cert}
	if len(r.CA) > 0 {
		opts.RootCAs = x509.NewCertPool()
		if !opts.RootCAs.AppendCertsFromPEM(r.CA) {
			return Options{}, errors.New("the daemon's CA holds no certificate")
		}
	}
	return opts, nil
}
