// TLS for gateway mode: the autocert.Manager wiring, HostPolicy, and
// the two listeners this package's Router rides on once [gateway] turns
// TLS on — see acmecache.go for the replicated challenge Cache that lets
// two gateways answer the same domain.
//
// With [gateway] off, none of this is constructed — cmd/anvil's wiring
// never calls NewACMEManager/NewHTTPSServer/NewHTTPServer at all — so the
// hard constraint holds: nothing listens on 80 or 443, and a standard
// node's behaviour, config and output stay byte-for-byte what they are
// today.
package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Timeouts (overseer amendment, 2026-11-20). The 443 write timeout is
// deliberately long: a 60s cap would cut a large site response for a
// slow client (a 10 MiB inscription at 1 Mbit/s takes about 84s, and the
// per-fetch cap is 16 MiB), and SSE streams aren't affected by it either
// way — every SSE writer extends its own deadline before each write
// (writeSSE, internal/api/sse_deadline.go), which overrides WriteTimeout
// for that connection (see tls_test.go's TestHTTPSServerSSEOutlivesShortWriteTimeout).
const (
	gatewayReadHeaderTimeout = 10 * time.Second
	gatewayIdleTimeout       = 120 * time.Second
	gatewayHTTPSWriteTimeout = 10 * time.Minute
	gatewayHTTPWriteTimeout  = 60 * time.Second
)

// errHostNotAllowed is HostPolicy's refusal error for every reason it
// can refuse a host: not an allowed site, not api_host, a loopback name,
// or an IP literal. Exported as a sentinel (via errors.Is) so
// wrapGetCertificate can tell "HostPolicy already counted this" apart
// from a genuine issuance error, without string-matching autocert's own
// error text.
var errHostNotAllowed = errors.New("gateway: host is not an allowed site or api_host")

// ACMEManagerConfig builds the one autocert.Manager the 443 and 80
// listeners share.
type ACMEManagerConfig struct {
	// Cache is almost always *Cache (acmecache.go) wrapping
	// autocert.DirCache — a plain autocert.DirCache works too (no
	// replication, same as an empty [mesh] allowed_peers).
	Cache autocert.Cache
	// Policy is the gateway's one allow rule (see policy.go). A nil
	// Policy refuses every host that isn't api_host — only a test or a
	// degenerate wiring would pass nil; cmd/anvil's real wiring always
	// has one.
	Policy *Policy
	// APIHost is the Host that reaches this node's own API (D1) — see
	// GatewayConfig.APIHost. Allowed to get a certificate too, same as
	// an allowed site.
	APIHost string
	// Email is the optional ACME account contact address.
	Email string
	// Directory is the ACME directory URL. Internal/config defaults
	// this to Let's Encrypt production when [gateway] acme_directory is
	// unset — this field is never defaulted here.
	Directory string
	// AcceptTOS gates issuance entirely: left false, Manager.Prompt
	// stays nil and every issuance attempt fails with a clear
	// "missing Manager.Prompt" error (acme/rfc8555.go) rather than
	// silently agreeing to a CA's terms on the operator's behalf.
	AcceptTOS bool
	// Counters is the shared gateway counters. A nil Counters
	// is replaced with a fresh one (counts are simply discarded) rather
	// than panicking, so a caller that doesn't care about stats can
	// omit it.
	Counters *Counters
}

// NewACMEManager builds the autocert.Manager. Both challenge types stay
// available (TLSConfig's NextProtos includes acme-tls/1; NewHTTPServer
// below always calls manager.HTTPHandler) so an ACME server reaches
// whichever of this gateway's two listeners it dials.
func NewACMEManager(cfg ACMEManagerConfig) *autocert.Manager {
	counters := ensureCounters(cfg.Counters)
	m := &autocert.Manager{
		Cache:      cfg.Cache,
		Email:      cfg.Email,
		HostPolicy: newHostPolicy(cfg.Policy, cfg.APIHost, counters),
		Client:     &acme.Client{DirectoryURL: cfg.Directory},
	}
	if cfg.AcceptTOS {
		m.Prompt = autocert.AcceptTOS
	}
	return m
}

// ensureCounters returns c, or a fresh *Counters if c is nil, so the
// rest of this file never has to nil-check before incrementing.
func ensureCounters(c *Counters) *Counters {
	if c == nil {
		return &Counters{}
	}
	return c
}

// newHostPolicy is this package's issuance gate. A host
// is refused before any ACME traffic for four reasons, checked in this
// order: it's a loopback name, it's an IP literal (both always refused,
// regardless of Policy or APIHost — the hard constraint this function
// exists to enforce), it isn't api_host, and Policy.Allowed refuses it.
// Every refusal increments ACMERefusedHost exactly once.
func newHostPolicy(policy *Policy, apiHost string, counters *Counters) autocert.HostPolicy {
	normAPIHost := normalizeHost(apiHost)
	return func(ctx context.Context, host string) error {
		normHost := normalizeHost(host)
		if isLoopbackHost(normHost) {
			counters.ACMERefusedHost.Add(1)
			return fmt.Errorf("%w: %q is a loopback host", errHostNotAllowed, host)
		}
		if net.ParseIP(normHost) != nil {
			counters.ACMERefusedHost.Add(1)
			return fmt.Errorf("%w: %q is an IP literal", errHostNotAllowed, host)
		}
		if normAPIHost != "" && normHost == normAPIHost {
			return nil
		}
		if policy != nil {
			if _, ok := policy.Allowed(ctx, normHost); ok {
				return nil
			}
		}
		counters.ACMERefusedHost.Add(1)
		return fmt.Errorf("%w: %q", errHostNotAllowed, host)
	}
}

// NewHTTPSServer builds the gateway's 443 listener: router (the
// package's own Router) with TLSConfig = manager.TLSConfig() so HTTP/2
// and acme-tls/1 are both on, plus the fixed timeouts below. counters'
// TLSHandshakes and CertErrors are incremented per handshake via a thin
// wrapper around manager.GetCertificate — gateway_cert_issued is counted
// on the Cache side instead (acmecache.go's Put), the only point that
// can tell a fresh issuance apart from a cache hit.
//
// If manager.Cache implements errorRecorder (true for *Cache,
// acmecache.go — false for a plain autocert.DirCache or a nil Cache), a
// genuine issuance error is also recorded against the requested host, so
// doctor can report it later without access to this process's memory.
func NewHTTPSServer(addr string, router http.Handler, manager *autocert.Manager, counters *Counters) *http.Server {
	counters = ensureCounters(counters)
	recorder, _ := manager.Cache.(errorRecorder)
	tlsConfig := manager.TLSConfig()
	tlsConfig.GetCertificate = wrapGetCertificate(manager, counters, recorder)
	return &http.Server{
		Addr:              addr,
		Handler:           router,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: gatewayReadHeaderTimeout,
		IdleTimeout:       gatewayIdleTimeout,
		WriteTimeout:      gatewayHTTPSWriteTimeout,
	}
}

// errorRecorder is implemented by *Cache (acmecache.go). Kept as a small
// unexported interface, checked with a type assertion in NewHTTPSServer,
// so this file never imports acmecache.go's concrete type and a test's
// plain autocert.DirCache (which doesn't implement it) stays valid —
// wrapGetCertificate then simply has nothing to call.
type errorRecorder interface {
	RecordIssuanceError(domain, errText string)
}

// wrapGetCertificate counts every TLS handshake that needs a certificate
// lookup, and every error other than a HostPolicy refusal (already
// counted once, in newHostPolicy, via the errHostNotAllowed sentinel) as
// a cert error — a missing account TOS agreement, an ACME network
// failure, or (briefly, harmlessly) a token cert requested before the
// challenge that provisions it has run. The same non-refusal errors are
// handed to recorder, if non-nil and manager's own HostPolicy currently
// allows the request's host (see recordableHost) — keyed by the
// normalised host, never the raw ClientHello ServerName.
func wrapGetCertificate(manager *autocert.Manager, counters *Counters, recorder errorRecorder) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		counters.TLSHandshakes.Add(1)
		cert, err := manager.GetCertificate(hello)
		if err != nil {
			if !errors.Is(err, errHostNotAllowed) {
				counters.CertErrors.Add(1)
				if recorder != nil {
					if host, ok := recordableHost(manager, hello.ServerName); ok {
						recorder.RecordIssuanceError(host, err.Error())
					}
				}
			}
			return nil, err
		}
		return cert, nil
	}
}

// recordableHost reports the normalised host to record an issuance error
// against, and whether recording is allowed at all: only when manager's
// own HostPolicy — the same gate a normal GetCertificate call consults —
// currently allows rawHost. autocert's tls-alpn-01 "+token" challenge
// path (wantsTokenCert, golang.org/x/crypto@v0.59.0/acme/autocert/autocert.go)
// skips HostPolicy entirely before reaching the cache lookup that can
// fail, so an error from that path has never been policy-checked by the
// time it reaches wrapGetCertificate — rawHost there is the TLS
// ClientHello's raw, unauthenticated, pre-certificate ServerName. This
// re-check is what makes "RecordIssuanceError records only for a host
// the issuance policy allows" (acmecache.go's own doc comment on that
// method) actually true, regardless of which autocert code path produced
// the error being handled. A caller must never pass rawHost itself, or
// any string this function didn't return, to RecordIssuanceError.
//
// Calling manager.HostPolicy here a second time never double-counts a
// refusal: the only way execution reaches this function at all is when
// GetCertificate's error did NOT already wrap errHostNotAllowed, which
// means either HostPolicy was never consulted for this request (the
// bypass path above) or it already returned nil (allowed) and something
// else about issuance failed afterward — calling it again is deterministic
// and returns nil again in that second case, counting nothing new.
func recordableHost(manager *autocert.Manager, rawHost string) (string, bool) {
	if manager.HostPolicy == nil {
		return "", false
	}
	normHost := normalizeHost(rawHost)
	if err := manager.HostPolicy(context.Background(), normHost); err != nil {
		return "", false
	}
	return normHost, true
}

// NewHTTPServer builds the gateway's 80 listener. manager.HTTPHandler
// answers "/.well-known/acme-challenge/..." itself — running HostPolicy
// first (golang.org/x/crypto/acme@v0.59.0/acme/autocert/autocert.go:405)
// and then httpToken's cache/in-memory read (:409, reading back through
// :860) — and calls the fallback handler, built here, for every other
// path. The fallback is NOT protected by HostPolicy (autocert.go:381),
// so it makes its own allow decision: a 308 to https for an allowed site
// host or api_host, a plain 404 otherwise.
func NewHTTPServer(addr string, manager *autocert.Manager, policy *Policy, apiHost string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           manager.HTTPHandler(httpRedirectHandler(policy, apiHost)),
		ReadHeaderTimeout: gatewayReadHeaderTimeout,
		IdleTimeout:       gatewayIdleTimeout,
		WriteTimeout:      gatewayHTTPWriteTimeout,
	}
}

// httpRedirectHandler is NewHTTPServer's fallback. The redirect preserves
// the request's path and query (RequestURI) and uses a 308 so the method
// is preserved too, though every caller here is a GET in practice.
func httpRedirectHandler(policy *Policy, apiHost string) http.Handler {
	normAPIHost := normalizeHost(apiHost)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := normalizeHost(r.Host)
		allowed := normAPIHost != "" && host == normAPIHost
		if !allowed && policy != nil {
			_, allowed = policy.Allowed(r.Context(), host)
		}
		if !allowed {
			http.NotFound(w, r)
			return
		}
		target := "https://" + stripHostPort(r.Host) + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusPermanentRedirect)
	})
}

// stripHostPort drops an optional ":port" suffix from a Host header, the
// same way autocert's own unexported stripPort does for its default
// redirect handler (autocert.go:427) — needed here because the 308
// target is always https (443), never whatever port this listener
// itself bound as http (typically 80).
func stripHostPort(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}
