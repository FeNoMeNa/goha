package goha

import (
	"net/http"
	"strings"
)

func NewClient(username, password string) *http.Client {
	t := &transport{username, password, http.DefaultTransport}
	return &http.Client{Transport: t}
}

// Transport is an implementation of http.RoundTripper that takes care of http authentication.
type transport struct {
	username  string
	password  string
	transport http.RoundTripper
}

// RoundTrip makes an authorized request using digest authentication.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clones the request so the input is not modified.
	creq := cloneRequest(req)

	// Make a request to get the 401 that contains the challenge.
	resp, err := t.transport.RoundTrip(req)

	if err != nil || resp.StatusCode != 401 {
		return resp, err
	}

	header := resp.Header.Get("WWW-Authenticate")

	if strings.HasPrefix(header, "Digest ") { // TODO: Case sensitive
		c := newCredentials(t.username, t.password, header, creq.URL.RequestURI(), creq.Method)
		creq.Header.Set("Authorization", c.authHeader())
	}

	if strings.HasPrefix(header, "Basic ") { // TODO: Case sensitive
		creq.SetBasicAuth(t.username, t.password)
	}

	// Make authenticated request.
	return t.transport.RoundTrip(creq)
}

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
