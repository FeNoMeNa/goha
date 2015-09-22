package goha

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"io"
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

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.transport.RoundTrip(req)
}

type challenge struct {
	realm     string
	nonce     string
	opaque    string
	algorithm string
	qop       string
}

func newChallenge(header string) *challenge {
	realm := parseDirective(header, "realm", "")
	nonce := parseDirective(header, "nonce", "")
	opaque := parseDirective(header, "opaque", "")
	algorithm := parseDirective(header, "algorithm", "MD5")
	qop := parseDirective(header, "qop", "")

	return &challenge{realm, nonce, opaque, algorithm, qop}
}

type credentials struct {
	username    string
	password    string
	realm       string
	nonce       string
	digestURI   string
	algorithm   string
	cnonce      string
	opaque      string
	qop         string
	nonceCount  int
	method      string
	randomNonce func() string
}

func (c *credentials) authHeader() string {
	return ""
}

func (c *credentials) response() string {
	c.nonceCount++

	if c.qop == "" {
		return h(c.ha1(), c.nonce, c.ha2())
	}

	c.cnonce = c.randomNonce()

	return h(c.ha1(), c.nonce, c.nonceCountStr(), c.cnonce, c.qop, c.ha2())
}

func (c *credentials) nonceCountStr() string {
	return fmt.Sprintf("%08x", c.nonceCount)
}

func (c *credentials) ha1() string {
	return h(c.username, c.realm, c.password)
}

func (c *credentials) ha2() string {
	return h(c.method, c.digestURI)
}

func h(parts ...string) string {
	var content bytes.Buffer

	for _, part := range parts {
		content.WriteString(part)
		content.WriteString(":")
	}

	data := content.String()
	data = data[:len(data)-1]

	return fmt.Sprintf("%x", md5.Sum([]byte(data)))
}

func randomNonce() string {
	b := make([]byte, 8)
	io.ReadFull(rand.Reader, b)

	return fmt.Sprintf("%x", b)[:16]
}

func parseDirective(header, name, value string) string {
	index := strings.Index(header, name)

	if index == -1 {
		return value // it returns default value
	}

	start := 1 + index + strings.Index(header[index:], `"`)
	end := start + strings.Index(header[start:], `"`)

	return strings.TrimSpace(header[start:end])
}
