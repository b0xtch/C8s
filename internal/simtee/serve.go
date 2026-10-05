package simtee

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

const (
	// documentParam names, in a request to Handler, the address the document
	// has at the vendor's service.
	documentParam = "document"
	// maxDocumentBytes bounds one document a Remote reads.
	maxDocumentBytes = 1 << 20
)

// Handler serves a simulated vendor's documents over plain HTTP, to the
// verifiers of another process: GET /?document=<the address the document has
// at the vendor's service>. The answer's headers and body are the vendor's
// own. Nothing here is secret, and nothing is authenticated: a document is
// held to the authority's signature by whoever reads it.
func Handler(v *Vendor) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET alone", http.StatusMethodNotAllowed)
			return
		}
		document := r.URL.Query().Get(documentParam)
		if document == "" {
			http.Error(w, "which document", http.StatusBadRequest)
			return
		}
		header, body, err := v.GetContext(r.Context(), document)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		for name, values := range header {
			w.Header()[http.CanonicalHeaderKey(name)] = values
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(body)
	})
}

// Remote is a simulated vendor served by Handler, as a verifier asks it for
// a document by the address that document has at the vendor's service.
type Remote struct {
	client *http.Client
	base   string
}

// NewRemote reaches the simulated vendor at address, host:port, over dial,
// or over TCP when dial is nil. A guest with no network device reaches it
// over the road its launcher carries, which leads there and nowhere else.
func NewRemote(address string, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *Remote {
	transport := &http.Transport{
		DialContext:           dial,
		MaxIdleConns:          2,
		IdleConnTimeout:       time.Minute,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	return &Remote{client: &http.Client{Transport: transport, Timeout: 20 * time.Second}, base: "http://" + address + "/"}
}

// Get asks for one document.
func (r *Remote) Get(document string) (map[string][]string, []byte, error) {
	return r.GetContext(context.Background(), document)
}

// GetContext is Get under ctx.
func (r *Remote) GetContext(ctx context.Context, document string) (map[string][]string, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.base+"?"+url.Values{documentParam: {document}}.Encode(), nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("the simulated vendor: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("the simulated vendor: %w", err)
	}
	if len(body) > maxDocumentBytes {
		return nil, nil, errors.New("the simulated vendor answered with more than a document")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("the simulated vendor answered %s for %s", resp.Status, document)
	}
	return resp.Header, body, nil
}
