package goha

import (
	"net/http"
	"strings"
)

// NewClient creates and initializes a new http client that will be able to
// authorize its requests via Basic / Digest authentication scheme.
func NewClient(username, password string) *http.Client {
	t := &transport{username, password}
	return &http.Client{Transport: t}
}

// transport is an implementation of http.RoundTripper that takes care of
// http authentication.
type transport struct {
	username string
	password string
}

// RoundTrip makes an authorized requests. First it sends a http request to
// obtain the authentication challenge and then authorizes the request via
// Basic / Digest authentication scheme.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clones the request so the input is not modified.
	creq := cloneRequest(req)

	// Make a request to get the 401 that contains the challenge.
	resp, err := http.DefaultTransport.RoundTrip(req)

	if err != nil || resp.StatusCode != 401 {
		return resp, err
	}

	header := resp.Header.Get("WWW-Authenticate")

	// We should use Digest scheme to authorize the request
	if strings.HasPrefix(header, "Digest ") { // TODO: Case sensitive
		c := newCredentials(t.username, t.password, header, creq.URL.RequestURI(), creq.Method)
		creq.Header.Set("Authorization", c.authHeader())
	}

	// We should use Basic scheme to authorize the request
	if strings.HasPrefix(header, "Basic ") { // TODO: Case sensitive
		creq.SetBasicAuth(t.username, t.password)
	}

	return http.DefaultTransport.RoundTrip(creq)
}

// cloneRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r

	// deep copy of the Header
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}

	return r2
}
