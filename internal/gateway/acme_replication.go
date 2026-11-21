package gateway

// ApplyReceived and the cap/lifetime accounting the two replicated ACME
// challenge entry kinds share — split out of acmecache.go to keep that
// file under its line budget. acmecache.go keeps Cache's "write
// locally, maybe send to peers" half (Put) plus doctor's read-only
// view; this file is Cache's "receive a replicated entry from a peer"
// half.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// acmeReplicatedEntryCap and acmeReplicatedEntryLifetime bound what
	// this node accepts for a received replicated entry — both "+token"
	// and "+http-01" keys get the same cap and lifetime. The cap is
	// enforced per kind, not shared between them (see
	// countReplicatedKindLocked): a flood of one kind can never crowd
	// out the other, so up to acmeReplicatedEntryCap "+token" entries
	// and, independently, up to acmeReplicatedEntryCap "+http-01"
	// entries may be tracked at once. A "+token" key also has its
	// domain checked against Policy (see ApplyReceived); a "+http-01"
	// key carries no domain to check, so this cap and lifetime are the
	// only guard it gets.
	acmeReplicatedEntryCap      = 256
	acmeReplicatedEntryLifetime = 10 * time.Minute
)

// errSenderNotAllowed and errKeyNotReplicable are ApplyReceived's two
// refusal sentinels (via errors.Is), so a caller or test can tell the
// reason apart from a genuine write failure without string-matching.
var (
	errSenderNotAllowed     = errors.New("gateway: sender is not in [mesh] allowed_peers")
	errKeyNotReplicable     = errors.New("gateway: key is not a replicable ACME challenge entry")
	errDomainNotAllowed     = errors.New("gateway: domain is not allowed by policy")
	errReplicatedEntryAtCap = errors.New("gateway: replicated entry cap reached")
)

// ApplyReceived validates every field of one entry received from a peer
// via a MsgACMEChallenge mesh message, and only if all of it is valid,
// writes it — called from cmd/anvil's wiring of
// gossip.Manager.SetACMEChallengeHook. Nothing is written until every
// check below has passed; there is no partial-validation path.
//
// Accepted only if all of these hold:
//
//   - senderPKHex is in [mesh] allowed_peers (the same list NewCache was
//     built with — checked here, independently of whatever connection-time
//     peer admission already applied, so this package's own guarantee
//     doesn't depend on a detail of how the mesh layer is wired);
//   - key is shaped like one of the two replicable kinds, and the part
//     of it that isn't the suffix is itself valid for that kind: for a
//     "+token" key, the domain (the key with "+token" trimmed) must be a
//     syntactically valid hostname (isValidHostname); for a "+http-01"
//     key, the token (the key with "+http-01" trimmed) must be
//     syntactically valid base64url (isValidACMEToken). A key that fails
//     either shape check is refused before anything else about it is
//     consulted — it is never passed to Policy.Allowed or written
//     anywhere;
//   - for a "+token" key, the domain also passes c.policy.Allowed. A
//     "+http-01" key carries only the ACME token, not a domain, so there
//     is nothing to check it against Policy — those are accepted from
//     any allowed peer instead;
//   - the entry isn't already expired by the sender's own claim.
//
// Both kinds are then capped and given a lifetime: up to
// acmeReplicatedEntryCap entries of EACH kind (counted independently —
// see countReplicatedKindLocked) may be tracked at once, each for at
// most acmeReplicatedEntryLifetime from now, whichever is sooner than
// the sender's own claimed expires. A new key beyond the cap is refused;
// an existing key being refreshed never is.
//
// Every other key shape (a certificate, +rsa, or the account key) is
// refused outright.
func (c *Cache) ApplyReceived(senderPKHex, key string, value []byte, expires time.Time) error {
	if _, ok := c.allowedPeers[strings.ToLower(strings.TrimSpace(senderPKHex))]; !ok {
		return fmt.Errorf("%w: %q", errSenderNotAllowed, senderPKHex)
	}

	switch {
	case strings.HasSuffix(key, "+token"):
		rawDomain := strings.TrimSuffix(key, "+token")
		domain, ok := isValidHostname(rawDomain)
		if !ok {
			return fmt.Errorf("%w: %q", errKeyNotReplicable, key)
		}
		if !expires.After(c.now()) {
			return fmt.Errorf("gateway: refusing an already-expired replicated entry for %q", key)
		}
		if c.policy == nil {
			return fmt.Errorf("%w: %q (no policy configured)", errDomainNotAllowed, domain)
		}
		if _, ok := c.policy.Allowed(context.Background(), domain); !ok {
			return fmt.Errorf("%w: %q", errDomainNotAllowed, domain)
		}
		// Store under the normalised domain, not rawDomain: this node's
		// own autocert.Manager only ever looks a "+token" key up by a
		// ClientHello name that already went through the same
		// normalisation (newHostPolicy), so a received key differing
		// only in case must resolve to that same, single cache entry.
		return c.applyCappedReplicatedEntryLocked(domain+"+token", "+token", value, expires)

	case strings.HasSuffix(key, "+http-01"):
		token := strings.TrimSuffix(key, "+http-01")
		if !isValidACMEToken(token) {
			return fmt.Errorf("%w: %q", errKeyNotReplicable, key)
		}
		if !expires.After(c.now()) {
			return fmt.Errorf("gateway: refusing an already-expired replicated entry for %q", key)
		}
		// No domain to check against Policy — cap and lifetime instead.
		return c.applyCappedReplicatedEntryLocked(key, "+http-01", value, expires)

	default:
		return fmt.Errorf("%w: %q", errKeyNotReplicable, key)
	}
}

// applyCappedReplicatedEntryLocked writes key (already validated and
// policy-checked by ApplyReceived) through the shared cap-and-lifetime
// accounting both replicated kinds share, keyed by suffix
// ("+token" or "+http-01") so the two are counted independently.
func (c *Cache) applyCappedReplicatedEntryLocked(key, suffix string, value []byte, expires time.Time) error {
	cappedExpiry := expires
	if maxExpiry := c.now().Add(acmeReplicatedEntryLifetime); cappedExpiry.After(maxExpiry) {
		cappedExpiry = maxExpiry
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictExpiredReplicatedEntriesLocked()
	if _, exists := c.replicatedEntries[key]; !exists && c.countReplicatedKindLocked(suffix) >= acmeReplicatedEntryCap {
		return fmt.Errorf("%w: %q (%d entries)", errReplicatedEntryAtCap, key, acmeReplicatedEntryCap)
	}
	c.replicatedEntries[key] = cappedExpiry
	return c.dir.Put(context.Background(), key, value)
}

// evictExpiredReplicatedEntriesLocked removes every tracked replicated
// entry — "+token" or "+http-01" — past its capped expiry, both from the
// in-memory accounting map and from the underlying DirCache. The caller
// must hold c.mu.
func (c *Cache) evictExpiredReplicatedEntriesLocked() {
	now := c.now()
	for key, exp := range c.replicatedEntries {
		if !exp.After(now) {
			delete(c.replicatedEntries, key)
			_ = c.dir.Delete(context.Background(), key)
		}
	}
}

// countReplicatedKindLocked counts tracked entries sharing suffix
// ("+token" or "+http-01") — the cap is enforced per kind, not shared,
// so a flood of one can never crowd out the other. The caller must hold
// c.mu.
func (c *Cache) countReplicatedKindLocked(suffix string) int {
	n := 0
	for k := range c.replicatedEntries {
		if strings.HasSuffix(k, suffix) {
			n++
		}
	}
	return n
}
