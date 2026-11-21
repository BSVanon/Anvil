package gateway

// A replicated ACME challenge cache: an autocert.Cache that writes every
// entry locally, exactly as a plain autocert.DirCache would, and
// additionally replicates only the challenge entries — a tls-alpn-01
// token certificate ("<domain>+token") or an http-01 token value
// ("<token>+http-01") — to every connected, allowed peer gateway. That is
// the one thing two gateways answering the same domain need to share:
// whichever of them the ACME server's validation request actually
// reaches, it finds the challenge answer in its own local cache.
// Certificates, legacy RSA certificates and the account key never leave
// this node.
//
// Why not data envelopes: private envelopes are never pushed to peers at
// all (internal/gossip/manager.go:344-346 — Manager's BroadcastEnvelope
// early-returns on env.Private before ever reaching a peer;
// handlers.go:267's onData mirrors the same rule for a locally forwarded
// envelope), and a public envelope is readable by anyone on GET /data —
// but a tls-alpn-01 token entry's value is a certificate *and private
// key* (autocert.go's cachePut/encodeECDSAKey). So this cache's own
// point-to-point mesh message (internal/gossip's MsgACMEChallenge) is
// never stored in the envelope store, never relayed onward by a
// receiving peer, and never served over any read path.

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

const (
	// acmeChallengeExpiryCap bounds how far ahead Put sets the expiry it
	// sends with a replicated entry: at most 600s. autocert.Cache.Put
	// carries no expiry of its own, so there is no finer-grained real
	// deadline to use — this is a flat, safe default, not a measured
	// remaining lifetime.
	acmeChallengeExpiryCap = 600 * time.Second

	// acmeHTTPTokenCap and acmeHTTPTokenLifetime bound what this node
	// accepts for a received "+http-01" key, which carries no domain to
	// check against Policy: accepted only from allowed peers, capped at
	// 256 entries with a 10-minute lifetime.
	acmeHTTPTokenCap      = 256
	acmeHTTPTokenLifetime = 10 * time.Minute
)

// errSenderNotAllowed and errKeyNotReplicable are ApplyReceived's two
// refusal sentinels (via errors.Is), so a caller or test can tell the
// reason apart from a genuine write failure without string-matching.
var (
	errSenderNotAllowed = errors.New("gateway: sender is not in [mesh] allowed_peers")
	errKeyNotReplicable = errors.New("gateway: key is not a replicable ACME challenge entry")
	errDomainNotAllowed = errors.New("gateway: domain is not allowed by policy")
	errHTTPTokenAtCap   = errors.New("gateway: http-01 token cap reached")
)

// ACMEPeerSender sends one ACME challenge cache entry to every
// currently connected, allowed mesh peer, point-to-point, returning how
// many peers it reached. Satisfied by (*gossip.Manager).BroadcastACMEChallenge
// — this package never imports internal/gossip (cmd/anvil's wiring
// supplies the closure), so Cache can be built and tested with a fake.
type ACMEPeerSender func(key string, value []byte, expires time.Time) int

// Cache implements autocert.Cache over autocert.DirCache(dir), mode
// 0700. See the package-level doc comment above for the replication
// contract.
type Cache struct {
	dir      autocert.DirCache
	send     ACMEPeerSender // nil = replication disabled (see NewCache)
	policy   *Policy
	counters *Counters

	allowedPeers map[string]struct{} // lowercase hex identity keys; nil/empty = replication disabled

	mu         sync.Mutex
	httpTokens map[string]time.Time // received "+http-01" key -> this node's own capped expiry
}

// NewCache builds a Cache rooted at dir (typically <data_dir>/acme),
// creating it at mode 0700 up front — autocert.DirCache would also
// create it on first Put, but doctor and a freshly started manager may
// Get before any Put ever happens, and the directory belongs to the
// daemon's own user by construction here, since this always runs inside
// the daemon process (see cmd/anvil's wiring — never a CLI path).
//
// send is the point-to-point sender for outbound replication, called
// for every connected allowed peer. allowedPeers is [mesh] allowed_peers
// verbatim; with it empty, replication is off regardless of send — the
// one case a peer's own connection-time admission can't cover, since an
// empty allowlist admits anyone — so Put can never replicate into an
// open mesh by a wiring mistake. policy gates which
// domains a received "+token" entry may apply for; it should be the
// same Policy the gateway's HostPolicy uses, so acceptance and issuance
// never disagree about what this node serves.
func NewCache(dir string, send ACMEPeerSender, policy *Policy, allowedPeers []string, counters *Counters) *Cache {
	_ = os.MkdirAll(dir, 0700)
	c := &Cache{
		dir:        autocert.DirCache(dir),
		policy:     policy,
		counters:   ensureCounters(counters),
		httpTokens: make(map[string]time.Time),
	}
	for _, k := range allowedPeers {
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		if c.allowedPeers == nil {
			c.allowedPeers = make(map[string]struct{}, len(allowedPeers))
		}
		c.allowedPeers[k] = struct{}{}
	}
	if len(c.allowedPeers) > 0 {
		c.send = send
	}
	return c
}

// Get implements autocert.Cache.
func (c *Cache) Get(ctx context.Context, key string) ([]byte, error) {
	return c.dir.Get(ctx, key)
}

// Put implements autocert.Cache: every key is written locally exactly as
// autocert.DirCache would. A key ending in "+token" or "+http-01" is
// also replicated to every connected allowed peer — synchronously, on
// this call: Put's own
// callers inside autocert already ignore its returned error
// (putHTTPToken, putCertToken), and a gateway federates with a small,
// operator-configured peer set, so the added latency of one or a few
// point-to-point sends on the challenge-fulfillment path is an accepted
// trade for not needing a second, async delivery path to reason about in
// tests. A non-replicated Put that names neither a challenge key nor the
// account key is a certificate just issued — see CertIssued's doc
// comment on Counters.
func (c *Cache) Put(ctx context.Context, key string, data []byte) error {
	if err := c.dir.Put(ctx, key, data); err != nil {
		return err
	}
	if isChallengeKey(key) {
		if c.send != nil {
			c.send(key, data, time.Now().Add(acmeChallengeExpiryCap))
		}
		return nil
	}
	if !isAccountKey(key) {
		// A <domain> or <domain>+rsa certificate entry. cert()
		// (autocert.go) calls cachePut only once, right after
		// createCert succeeds — a cache hit never re-Puts — so this is
		// exactly "a certificate was just issued," not "served."
		c.counters.CertIssued.Add(1)
	}
	return nil
}

// RecordIssuanceError persists a short, human-readable note of the most
// recent non-refusal certificate error for domain, so doctor — a
// separate process started later, with no access to this daemon's
// memory — can report it. Called from tls.go's wrapGetCertificate, the
// only place a genuine issuance error (as opposed to a HostPolicy
// refusal, which is never persisted) is observed. Overwrites any
// previous note for the same domain: this is a diagnostic breadcrumb for
// the most recent attempt, not an audit log.
//
// Written directly to the Cache's own directory rather than through
// autocert.Cache.Put/dir.Put: autocert.DirCache derives its on-disk
// filename from the cache key via url.QueryEscape, and a plain domain
// name never needs escaping, so a literal join is equivalent here and
// avoids giving this note a key shape (certKey.String) that might someday
// collide with a real cache entry.
func (c *Cache) RecordIssuanceError(domain, errText string) {
	path := filepath.Join(string(c.dir), domain+"+lasterror")
	note := time.Now().UTC().Format(time.RFC3339) + " " + errText + "\n"
	_ = os.WriteFile(path, []byte(note), 0600)
}

// Delete implements autocert.Cache: removes the entry locally only. A
// replicated entry a peer applied expires by its own TTL instead — this
// node sends no corresponding delete message, since an older peer
// would only ever ignore it (see internal/gossip/handlers.go's dispatch
// default case) and a receiving peer's own cleanup already bounds how
// long a stale entry can live.
func (c *Cache) Delete(ctx context.Context, key string) error {
	return c.dir.Delete(ctx, key)
}

// isChallengeKey reports whether key is one of the two entry shapes this
// cache replicates: a tls-alpn-01 token certificate ("<domain>+token" —
// certKey.String, golang.org/x/crypto/acme/autocert@v0.59.0/acme/autocert/autocert.go:216-224)
// or an http-01 token value ("<token>+http-01" — httpTokenCacheKey,
// same file, :895-897).
func isChallengeKey(key string) bool {
	return strings.HasSuffix(key, "+token") || strings.HasSuffix(key, "+http-01")
}

// isAccountKey reports whether key is autocert's ACME account private
// key: "acme_account+key" (current) or "acme_account.key" (legacy,
// still read as a fallback — autocert.go:933-937's accountKey). Never
// replicated, and — unlike a certificate — never counted as an issuance.
func isAccountKey(key string) bool {
	return key == "acme_account+key" || key == "acme_account.key"
}

// ApplyReceived validates and, if accepted, writes one entry received
// from a peer via a MsgACMEChallenge mesh message — called from
// cmd/anvil's wiring of gossip.Manager.SetACMEChallengeHook.
//
// Accepted only if both hold:
//
//   - senderPKHex is in [mesh] allowed_peers (the same list NewCache was
//     built with — checked here, independently of whatever connection-time
//     peer admission already applied, so this package's own guarantee
//     doesn't depend on a detail of how the mesh layer is wired);
//   - for a "+token" key, the domain it names (the key with "+token"
//     trimmed) passes c.policy.Allowed. A "+http-01" key carries only
//     the ACME token, not a domain, so there is nothing to check it
//     against — those are accepted from any allowed peer, capped at
//     acmeHTTPTokenCap entries with a acmeHTTPTokenLifetime lifetime,
//     refusing a new key once the cap is reached (an existing key being
//     refreshed is never refused by the cap).
//
// Every other key shape (a certificate, +rsa, or the account key) is
// refused outright. A key already expired by the sender's own claim is
// refused before it is ever written.
func (c *Cache) ApplyReceived(senderPKHex, key string, value []byte, expires time.Time) error {
	if _, ok := c.allowedPeers[strings.ToLower(strings.TrimSpace(senderPKHex))]; !ok {
		return fmt.Errorf("%w: %q", errSenderNotAllowed, senderPKHex)
	}
	if !isChallengeKey(key) {
		return fmt.Errorf("%w: %q", errKeyNotReplicable, key)
	}
	if !expires.After(time.Now()) {
		return fmt.Errorf("gateway: refusing an already-expired replicated entry for %q", key)
	}

	if strings.HasSuffix(key, "+token") {
		domain := strings.TrimSuffix(key, "+token")
		if c.policy == nil {
			return fmt.Errorf("%w: %q (no policy configured)", errDomainNotAllowed, domain)
		}
		if _, ok := c.policy.Allowed(context.Background(), domain); !ok {
			return fmt.Errorf("%w: %q", errDomainNotAllowed, domain)
		}
		return c.dir.Put(context.Background(), key, value)
	}

	// "+http-01": no domain to check — cap and lifetime instead.
	cappedExpiry := expires
	if maxExpiry := time.Now().Add(acmeHTTPTokenLifetime); cappedExpiry.After(maxExpiry) {
		cappedExpiry = maxExpiry
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictExpiredHTTPTokensLocked()
	if _, exists := c.httpTokens[key]; !exists && len(c.httpTokens) >= acmeHTTPTokenCap {
		return fmt.Errorf("%w: %q (%d entries)", errHTTPTokenAtCap, key, acmeHTTPTokenCap)
	}
	c.httpTokens[key] = cappedExpiry
	return c.dir.Put(context.Background(), key, value)
}

// evictExpiredHTTPTokensLocked removes every tracked "+http-01" entry
// past its capped expiry, both from the in-memory accounting map and
// from the underlying DirCache — a replicated entry expiring by TTL, for
// the one entry shape this package tracks a lifetime for at all (a
// "+token" entry's own embedded certificate NotAfter already bounds it —
// see autocert.go's validCert — so no separate tracking is needed
// there). The caller must hold c.mu.
func (c *Cache) evictExpiredHTTPTokensLocked() {
	now := time.Now()
	for key, exp := range c.httpTokens {
		if !exp.After(now) {
			delete(c.httpTokens, key)
			_ = c.dir.Delete(context.Background(), key)
		}
	}
}

// CertState describes one site's on-disk certificate entry, for doctor's
// benefit — never consulted by the gateway's own request path, which
// always goes through autocert.Manager.GetCertificate instead.
type CertState struct {
	// Present is false when there is no cached certificate for the
	// domain yet.
	Present bool
	// NotAfter is the leaf certificate's expiry. Valid only if Present.
	NotAfter time.Time
	// LastError is the most recent note RecordIssuanceError wrote for
	// this domain, or "" if none exists.
	LastError string
}

// SiteCertState reads domain's cached certificate, if any, and its most
// recently recorded issuance error, if any.
func (c *Cache) SiteCertState(ctx context.Context, domain string) CertState {
	var state CertState
	if blob, err := c.dir.Get(ctx, domain); err == nil {
		if leaf, perr := parseLeafCertificate(blob); perr == nil {
			state.Present = true
			state.NotAfter = leaf.NotAfter
		}
	}
	if note, err := os.ReadFile(filepath.Join(string(c.dir), domain+"+lasterror")); err == nil {
		state.LastError = strings.TrimSpace(string(note))
	}
	return state
}

// parseLeafCertificate extracts the leaf certificate from a cache entry
// blob: a private key PEM block (ignored here) followed by one or more
// CERTIFICATE PEM blocks (encodeECDSAKey, autocert.go:552-559; the RSA
// branch of cachePut, :531-536). cachePut writes tlscert.Certificate in
// order, leaf first, so the first CERTIFICATE block found is the leaf.
func parseLeafCertificate(blob []byte) (*x509.Certificate, error) {
	rest := blob
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			return nil, errors.New("gateway: no CERTIFICATE block found in cache entry")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
		rest = remainder
	}
}
