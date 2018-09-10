package goha

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// Client is a wrapper to http.client. It is used as builder to construct
// the real http client
type Client struct {
	client *http.Client
}

// NewClient creates and initializes a new goha http client that will be able
// to authorize its requests via Basic / Digest authentication scheme.
func NewClient(username, password string) *Client {
	t := &transportStruct{username: username, password: password, transport: http.DefaultTransport}
	c := &http.Client{Transport: t}

	return &Client{client: c}
}

// NewClient creates a new goha http client with provided http.Transport
func NewClientWithTransport(username, password string, transport http.RoundTripper) *Client {
	t := &transportStruct{username: username, password: password, transport: transport}
	c := &http.Client{Transport: t}

	return &Client{client: c}
}

// Timeout initializes the default timeout of the http client.
// A Timeout of zero means no timeout.
func (c *Client) Timeout(t time.Duration) *Client {
	c.client.Timeout = t
	return c
}

// Jar sets Client.Jar to passed cookiejar.Jar
func (c *Client) Jar(j *cookiejar.Jar) *Client {
	c.client.Jar = j
	return c
}

func (c *Client) Do(req *http.Request) (resp *http.Response, err error) {
	return c.client.Do(req)
}

func (c *Client) Get(url string) (resp *http.Response, err error) {
	return c.client.Get(url)
}

func (c *Client) Post(url string, bodyType string, body io.Reader) (resp *http.Response, err error) {
	return c.client.Post(url, bodyType, body)
}

func (c *Client) PostForm(url string, data url.Values) (resp *http.Response, err error) {
	return c.client.PostForm(url, data)
}

func (c *Client) Head(url string) (resp *http.Response, err error) {
	return c.client.Head(url)
}

// transportStruct is an implementation of http.RoundTripper that takes care of
// http authentication.
type transportStruct struct {
	username  string
	password  string
	transport http.RoundTripper
}

// RoundTrip makes an authorized requests. First it sends a http request to
// obtain the authentication challenge and then authorizes the request via
// Basic / Digest authentication scheme.
func (t *transportStruct) RoundTrip(req *http.Request) (*http.Response, error) {
	// Make a request to get the 401 that contains the challenge.
	resp, err := t.transport.RoundTrip(req)

	if err != nil || resp.StatusCode != 401 {
		return resp, err
	}

	// Clones the request so the input is not modified.
	creq := cloneRequest(req)

	header := resp.Header.Get("WWW-Authenticate")

	if strings.HasPrefix(header, "Digest ") {
		// We should use Digest scheme to authorize the request
		c := newCredentials(t.username, t.password, header, creq.URL.RequestURI(), creq.Method)
		creq.Header.Set("Authorization", c.authHeader())
	} else if strings.HasPrefix(header, "Basic ") {
		// We should use Basic scheme to authorize the request
		creq.SetBasicAuth(t.username, t.password)
	} else {
		return resp, err
	}

	return t.transport.RoundTrip(creq)
}

// CancelRequest cancels an in-flight request by closing its connection.
// CancelRequest should only be called after RoundTrip has returned.
func (t *transportStruct) CancelRequest(req *http.Request) {
	type canceler interface {
		CancelRequest(*http.Request)
	}

	tr, _ := t.transport.(canceler)

	tr.CancelRequest(req)
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
