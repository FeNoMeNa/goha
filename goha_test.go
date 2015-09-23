package goha

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseDirective(t *testing.T) {
	cases := []struct {
		header, name, want string
	}{
		{
			`WWW-Authenticate: Digest realm="Huawei", nonce="7d03f89029d63508cbd6033dc6cce81b", qop="auth", algorithm="MD5"`,
			`realm`,
			`Huawei`,
		},

		{
			`WWW-Authenticate: Digest realm="Huawei", nonce="7d03f89029d63508cbd6033dc6cce81b", qop="auth", algorithm="   MD5   "`,
			`algorithm`,
			`MD5`,
		},

		{
			`WWW-Authenticate: Digest realm="Huawei", nonce="7d03f89029d63508cbd6033dc6cce81b", algorithm="MD5"`,
			`qop`,
			``,
		},
	}

	for _, c := range cases {
		got := parseDirective(c.header, c.name)

		if got != c.want {
			t.Errorf("expected %v", c.want)
			t.Errorf("     got %v", got)
		}
	}
}

func TestHashing(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{
			[]string{"A", "B", "C"},
			"0b1b7405e6b7debe720439c9a8b9735b",
		},

		{
			[]string{"username", "password"},
			"133e1b8eda335c4c7f7a508620ca7f10",
		},
	}

	for _, c := range cases {
		got := h(c.in...)

		if got != c.want {
			t.Errorf("expected %v", c.want)
			t.Errorf("     got %v", got)
		}
	}
}

func TestHA1(t *testing.T) {
	cases := []struct {
		username, realm, password string
		want                      string
	}{
		{
			"username",
			"realm",
			"password",
			"66999343281b2624585fd58cc9d36dfc",
		},

		{
			"FeNoMeNa",
			"github",
			"parola",
			"17195d9eb2b40fe9e971457b2e9924b2",
		},
	}

	for _, c := range cases {
		crdls := credentials{username: c.username, realm: c.realm, password: c.password}

		got := crdls.ha1()

		if got != c.want {
			t.Errorf("expected %v", c.want)
			t.Errorf("     got %v", got)
		}
	}
}

func TestHA2(t *testing.T) {
	cases := []struct {
		method, digestURI string
		want              string
	}{
		{
			"GET",
			"/r/users",
			"fc6751725e146fc4f8d6d2c7edbac22b",
		},

		{
			"POST",
			"/r/books",
			"86f692593a7693ab1b3120b3e1f9d854",
		},
	}

	for _, c := range cases {
		crdls := credentials{method: c.method, digestURI: c.digestURI}

		got := crdls.ha2()

		if got != c.want {
			t.Errorf("expected %v", c.want)
			t.Errorf("     got %v", got)
		}
	}
}

func TestNonceCountStringConversion(t *testing.T) {
	cases := []struct {
		count int
		want  string
	}{
		{
			1,
			"00000001",
		},

		{
			22,
			"00000016",
		},
	}

	for _, c := range cases {
		crdls := credentials{nonceCount: c.count}

		got := crdls.nonceCountStr()

		if got != c.want {
			t.Errorf("expected %v", c.want)
			t.Errorf("     got %v", got)
		}
	}
}

func TestResponseCalculation(t *testing.T) {
	cases := []struct {
		credentials *credentials
		want        string
	}{
		{
			&credentials{
				"acs",
				"acs",
				"HuaweiHomeGateway",
				"7d03f89029d63508cbd6033dc6cce81b",
				"/3ca3509d413fde4048e6bfce19a8481f",
				"MD5",
				"f411c12de944bdf5",
				"",
				"auth",
				0,
				"GET",
			},

			"7e664d656eaa8b7d4d7a4b504b57caa1",
		},

		{
			&credentials{
				"Mufasa",
				"Circle Of Life",
				"testrealm@host.com",
				"dcd98b7102dd2f0e8b11d0f600bfb0c093",
				"/dir/index.html",
				"MD5",
				"0a4f113b",
				"5ccc069c403ebaf9f0171e9517f40e41",
				"auth",
				0,
				"GET",
			},

			"6629fae49393a05397450978507c4ef1",
		},

		{
			&credentials{
				"Mufasa",
				"Circle Of Life",
				"testrealm@host.com",
				"dcd98b7102dd2f0e8b11d0f600bfb0c093",
				"/dir/index.html",
				"MD5",
				"",
				"",
				"",
				0,
				"GET",
			},

			"670fd8c2df070c60b045671b8b24ff02",
		},
	}

	for _, c := range cases {
		got := c.credentials.response()

		if got != c.want {
			t.Errorf("expected %v", c.want)
			t.Errorf("     got %v", got)
		}
	}
}

func TestAuthHeader(t *testing.T) {
	cases := []struct {
		credentials *credentials
		want        string
	}{
		{
			&credentials{
				"acs",
				"acs",
				"HuaweiHomeGateway",
				"ed85d48bc2ef4b3d2958ff8434326a08",
				"/f9e8d48857a9d759417e3b2488ee76a5",
				"MD5",
				"1f37abb0877a794a",
				"",
				"auth",
				0,
				"GET",
			},

			`Digest username="acs", realm="HuaweiHomeGateway", nonce="ed85d48bc2ef4b3d2958ff8434326a08", uri="/f9e8d48857a9d759417e3b2488ee76a5", response="34ab5ab421382d014d9900f095d65b9b", qop=auth, nc=00000001, cnonce="1f37abb0877a794a", algorithm=MD5`,
		},

		{
			&credentials{
				"Mufasa",
				"Circle Of Life",
				"testrealm@host.com",
				"dcd98b7102dd2f0e8b11d0f600bfb0c093",
				"/dir/index.html",
				"",
				"0a4f113b",
				"5ccc069c403ebaf9f0171e9517f40e41",
				"auth",
				0,
				"GET",
			},

			`Digest username="Mufasa", realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/dir/index.html", response="6629fae49393a05397450978507c4ef1", opaque="5ccc069c403ebaf9f0171e9517f40e41", qop=auth, nc=00000001, cnonce="0a4f113b"`,
		},

		{
			&credentials{
				"Mufasa",
				"Circle Of Life",
				"testrealm@host.com",
				"dcd98b7102dd2f0e8b11d0f600bfb0c093",
				"/dir/index.html",
				"MD5",
				"",
				"",
				"",
				0,
				"GET",
			},

			`Digest username="Mufasa", realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/dir/index.html", response="670fd8c2df070c60b045671b8b24ff02", algorithm=MD5`,
		},
	}

	for _, c := range cases {
		got := c.credentials.authHeader()

		if got != c.want {
			t.Errorf("expected %v", c.want)
			t.Errorf("     got %v", got)
		}
	}
}

func TestRealmParsing(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{
			`WWW-Authenticate: Digest realm="Huawei", nonce="7d03f89029d63508cbd6033dc6cce81b", qop="auth", algorithm="MD5"`,
			`Huawei`,
		},

		{
			`WWW-Authenticate: Digest nonce="7d03f89029d63508cbd6033dc6cce81b", qop="auth", algorithm="MD5"`,
			``,
		},
	}

	for _, c := range cases {
		h := newDigestHeader(c.in)
		got := h.realm()

		if got != c.want {
			t.Errorf("expected %v", c.want)
			t.Errorf("     got %v", got)
		}
	}

}

func TestNonceParsing(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{
			`WWW-Authenticate: Digest realm="Huawei", nonce="7d03f89029d63508cbd6033dc6cce81b", qop="auth", algorithm="MD5"`,
			`7d03f89029d63508cbd6033dc6cce81b`,
		},

		{
			`WWW-Authenticate: Digest realm="Huawei", qop="auth", algorithm="MD5"`,
			``,
		},
	}

	for _, c := range cases {
		h := newDigestHeader(c.in)
		got := h.nonce()

		if got != c.want {
			t.Errorf("expected %v", c.want)
			t.Errorf("     got %v", got)
		}
	}

}

func TestAlgorithmParsing(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{
			`WWW-Authenticate: Digest realm="Huawei", nonce="7d03f89029d63508cbd6033dc6cce81b", qop="auth", algorithm="MD5"`,
			`MD5`,
		},

		{
			`WWW-Authenticate: Digest realm="Huawei", nonce="7d03f89029d63508cbd6033dc6cce81b", qop="auth"`,
			``,
		},
	}

	for _, c := range cases {
		h := newDigestHeader(c.in)
		got := h.algorithm()

		if got != c.want {
			t.Errorf("expected %v", c.want)
			t.Errorf("     got %v", got)
		}
	}

}

func TestOpaqueParsing(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{
			`WWW-Authenticate: Digest realm="Huawei", opaque="7d03f89029d63508cbd6033dc6cce81b", qop="auth", algorithm="MD5"`,
			`7d03f89029d63508cbd6033dc6cce81b`,
		},

		{
			`WWW-Authenticate: Digest realm="Huawei" qop="auth", algorithm="MD5"`,
			``,
		},
	}

	for _, c := range cases {
		h := newDigestHeader(c.in)
		got := h.opaque()

		if got != c.want {
			t.Errorf("expected %v", c.want)
			t.Errorf("     got %v", got)
		}
	}
}

func TestQopParsing(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{
			`WWW-Authenticate: Digest realm="Huawei", opaque="7d03f89029d63508cbd6033dc6cce81b", qop="auth", algorithm="MD5"`,
			`auth`,
		},

		{
			`WWW-Authenticate: Digest realm="Huawei", opaque="7d03f89029d63508cbd6033dc6cce81b", algorithm="MD5"`,
			``,
		},
	}

	for _, c := range cases {
		h := newDigestHeader(c.in)
		got := h.qop()

		if got != c.want {
			t.Errorf("expected %v", c.want)
			t.Errorf("     got %v", got)
		}
	}
}

func fakeRandomNonce(nonce string) func() string {
	return func() string {
		return nonce
	}
}

func fakeHttpServer(callback func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callback(w, r)
	})

	return httptest.NewServer(handler)
}
