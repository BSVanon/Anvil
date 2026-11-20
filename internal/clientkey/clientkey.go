// Package clientkey derives the key the node's per-client limits count a
// request under: its client's address, chosen by the API's trust_proxy
// settings, with an IPv6 address grouped by its /64. The API's rate limiters
// (internal/api) and the overlay route guard (internal/overlay/routeguard)
// share it, so a client is the same client to both.
package clientkey

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// IP extracts a canonical client IP using the configured proxy trust
// semantics. Local reverse proxies are trusted for their rightmost XFF entry
// even when trustProxy is disabled, which preserves per-client buckets for the
// shipped local nginx deployment without trusting direct remote clients.
func IP(r *http.Request, trustProxy bool, hops int) string {
	peer := Peer(r)
	entries := xForwardedForEntries(r.Header.Values("X-Forwarded-For"))
	if len(entries) == 0 {
		return peer
	}

	chosen := ""
	if trustProxy {
		if hops < 1 {
			hops = 1
		}
		idx := len(entries) - hops
		if idx < 0 {
			idx = 0
		}
		chosen = entries[idx]
	} else if ip := net.ParseIP(peer); ip != nil && ip.IsLoopback() {
		chosen = entries[len(entries)-1]
	}
	if chosen == "" {
		return peer
	}
	if ip := parseForwardedIP(chosen); ip != nil {
		return ip.String()
	}
	return peer
}

// Peer is the address of r's connection, the host of r.RemoteAddr in its
// canonical form when it is an IP address.
func Peer(r *http.Request) string {
	addr := r.RemoteAddr
	if host, _, err := net.SplitHostPort(addr); err == nil {
		addr = host
	}
	if ip := net.ParseIP(addr); ip != nil {
		return ip.String()
	}
	return addr
}

// Key is the key a limit counts ip under: ip itself, or the /64 of an IPv6
// address.
func Key(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return ip
	}
	return net.IP(parsed.To16()[:8]).String() + "/64"
}

// cgnat is the shared address space of RFC 6598, which carrier-grade NAT and
// overlay networks such as Tailscale use inside a network.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Shared reports whether ip, an address IP chose, may stand for many clients
// at once, so that a limit must not count it as one client: it is not a
// public unicast address but a loopback, private (RFC 1918, RFC 4193),
// link-local, shared (RFC 6598) or unspecified one, or not an address at
// all. A request comes from one when it reaches the node through a proxy on
// the same host or network that names no client the node may trust: a local
// proxy that sends no X-Forwarded-For, Docker's userland proxy, a load
// balancer inside a private network. No client on the internet can open a
// connection from one, so such a request cannot have chosen its address.
func Shared(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return true
	}
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsUnspecified() || cgnat.Contains(a)
}

// Forwarded reports whether r carries a header that a proxy adds to name the
// client it forwards for: X-Forwarded-For, X-Real-IP or Forwarded.
func Forwarded(r *http.Request) bool {
	for _, h := range [...]string{"X-Forwarded-For", "X-Real-Ip", "Forwarded"} {
		if len(r.Header.Values(h)) > 0 {
			return true
		}
	}
	return false
}

func xForwardedForEntries(values []string) []string {
	var entries []string
	for _, value := range values {
		for _, entry := range strings.Split(value, ",") {
			if entry = strings.TrimSpace(entry); entry != "" {
				entries = append(entries, entry)
			}
		}
	}
	return entries
}

func parseForwardedIP(value string) net.IP {
	value = strings.TrimSpace(value)
	if ip := net.ParseIP(value); ip != nil {
		return ip
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return net.ParseIP(host)
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		return net.ParseIP(strings.TrimSuffix(strings.TrimPrefix(value, "["), "]"))
	}
	return nil
}
