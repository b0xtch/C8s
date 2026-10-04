package operatorauth

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
)

// Authorizer binds an Authorization header to an HTTP method, URL path, and
// body. Signer implements it with a short-lived operator token.
type Authorizer interface {
	Authorization(method, path string, body []byte) (string, error)
}

// AudienceAuthorizer binds an Authorization header to the one verifier it is
// for as well: see Verifier.Audience. Signer implements it.
type AudienceAuthorizer interface {
	AuthorizationFor(audience, method, path string, body []byte) (string, error)
}

// For is auth held to one audience.
func For(auth AudienceAuthorizer, audience string) Authorizer {
	return forAudience{auth: auth, audience: audience}
}

type forAudience struct {
	auth     AudienceAuthorizer
	audience string
}

func (a forAudience) Authorization(method, path string, body []byte) (string, error) {
	return a.auth.AuthorizationFor(a.audience, method, path, body)
}

// NewRequest constructs a request and authorizes its actual method, parsed URL
// path, and body. It owns a copy of body so later changes to the input cannot
// invalidate the token. Callers must not change the returned method, path, or
// body; content type, transport, and response handling remain their concern.
func NewRequest(ctx context.Context, method, url string, body []byte, auth Authorizer) (*http.Request, error) {
	if auth == nil {
		return nil, fmt.Errorf("operatorauth: nil Authorizer")
	}
	body = bytes.Clone(body)
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	authz, err := auth.Authorization(req.Method, req.URL.Path, body)
	if err != nil {
		return nil, fmt.Errorf("authorize request: %w", err)
	}
	req.Header.Set("Authorization", authz)
	return req, nil
}
