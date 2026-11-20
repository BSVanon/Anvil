package clientkey

import (
	"net/http/httptest"
	"testing"
)

// TestIP_ChoosesAsTheRateLimitersDo: the address IP chooses, for each
// trust_proxy setting, is the one internal/api's limiters chose before it
// moved here (internal/api's TestClientIPParsing runs the same cases through
// its wrapper).
func TestIP_ChoosesAsTheRateLimitersDo(t *testing.T) {
	for _, c := range []struct {
		remote string
		xff    []string
		trust  bool
		hops   int
		want   string
	}{
		{"127.0.0.1:5555", []string{"forged, 203.0.113.7"}, false, 1, "203.0.113.7"},
		{"[::1]:5555", []string{"198.51.100.1, 203.0.113.7"}, false, 1, "203.0.113.7"},
		{"198.51.100.2:1234", []string{"1.2.3.4"}, false, 1, "198.51.100.2"},
		{"198.51.100.2:1234", []string{"198.51.100.1, 198.51.100.2, 198.51.100.3"}, true, 2, "198.51.100.2"},
		{"198.51.100.2:1234", []string{"198.51.100.1, 198.51.100.2"}, true, 9, "198.51.100.1"},
		{"198.51.100.2:1234", []string{"garbage"}, true, 1, "198.51.100.2"},
		{"127.0.0.1:5555", nil, false, 1, "127.0.0.1"},
		{"2001:db8::1", nil, false, 1, "2001:db8::1"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := IP(r, c.trust, c.hops); got != c.want {
			t.Errorf("IP(%q, xff %q, trust %v, hops %d) = %q, want %q", c.remote, c.xff, c.trust, c.hops, got, c.want)
		}
	}
}

// TestKey_GroupsIPv6ByItsSlash64: IPv4 addresses, and strings that are no
// address, are their own keys; IPv6 addresses of one /64 share one, which no
// other /64 and no IPv4 address shares.
func TestKey_GroupsIPv6ByItsSlash64(t *testing.T) {
	for _, ip := range []string{"203.0.113.7", "not an address"} {
		if got := Key(ip); got != ip {
			t.Errorf("Key(%q) = %q, want the address itself", ip, got)
		}
	}
	a, b := Key("2001:db8:1:2::1"), Key("2001:db8:1:2:ffff::")
	if a != b {
		t.Errorf("one /64 has two keys: %q and %q", a, b)
	}
	if c := Key("2001:db8:1:3::1"); c == a {
		t.Errorf("two /64s share the key %q", a)
	}
	if a == "2001:db8:1:2::1" || a == Key("203.0.113.7") {
		t.Errorf("an IPv6 address keys as %q, not as its /64", a)
	}
}

// TestShared_OnlyPublicAddressesAreClients: an address no internet client
// can connect from, or no address at all, is shared; a public one is not.
func TestShared_OnlyPublicAddressesAreClients(t *testing.T) {
	for ip, want := range map[string]bool{
		"127.0.0.1":          true,
		"::1":                true,
		"10.1.2.3":           true,
		"172.17.0.1":         true, // Docker's bridge gateway
		"192.168.1.20":       true,
		"fd12:3456::1":       true,
		"169.254.10.10":      true,
		"fe80::1":            true,
		"100.64.0.9":         true,
		"100.127.255.254":    true,
		"0.0.0.0":            true,
		"::ffff:10.0.0.1":    true,
		"":                   true,
		"@":                  true, // a Unix socket's peer
		"203.0.113.7":        false,
		"198.51.100.2":       false,
		"100.128.0.1":        false,
		"8.8.8.8":            false,
		"2001:db8:1:2::1":    false,
		"::ffff:203.0.113.7": false,
	} {
		if got := Shared(ip); got != want {
			t.Errorf("Shared(%q) = %v, want %v", ip, got, want)
		}
	}
}

// TestForwarded_SeesEachProxyHeader: each header a proxy adds to name its
// client counts; a request with none does not.
func TestForwarded_SeesEachProxyHeader(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if Forwarded(r) {
		t.Fatal("a request with no proxy header counts as forwarded")
	}
	for _, h := range []string{"X-Forwarded-For", "X-Real-IP", "Forwarded"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set(h, "203.0.113.7")
		if !Forwarded(r) {
			t.Errorf("a request with %s does not count as forwarded", h)
		}
	}
}
