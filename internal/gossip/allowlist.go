package gossip

import (
	"strings"
	"sync"
	"time"
)

// allowedPeerRefusalLogInterval rate-limits repeated refusal log lines for
// the same identity, so a peer stuck in a reconnect loop cannot spam the
// log — each refused identity is logged once per interval, not once per
// attempt.
const allowedPeerRefusalLogInterval = time.Minute

// peerAllowlist enforces [mesh] allowed_peers: a closed-network mode where
// only listed identity public keys (hex) may stay connected, inbound or
// outbound. An empty/unset list disables the restriction entirely — that is
// today's behaviour, preserved exactly.
type peerAllowlist struct {
	set map[string]struct{} // nil/empty = disabled; keys are lowercase hex

	mu       sync.Mutex
	lastWarn map[string]time.Time
}

// newPeerAllowlist builds a peerAllowlist from the configured hex identity
// keys. Blank entries are ignored; comparisons are case-insensitive (keys
// are lowercased on both sides, mirroring how identity hex is produced
// elsewhere in this package via fmt.Sprintf("%x", ...)).
func newPeerAllowlist(hexKeys []string) *peerAllowlist {
	a := &peerAllowlist{lastWarn: make(map[string]time.Time)}
	for _, k := range hexKeys {
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		if a.set == nil {
			a.set = make(map[string]struct{}, len(hexKeys))
		}
		a.set[k] = struct{}{}
	}
	return a
}

// enabled reports whether the allowlist restricts connections at all.
func (a *peerAllowlist) enabled() bool {
	return a != nil && len(a.set) > 0
}

// allows reports whether pkHex may connect. Always true when the allowlist
// is disabled (empty allowed_peers — today's behaviour).
func (a *peerAllowlist) allows(pkHex string) bool {
	if !a.enabled() {
		return true
	}
	_, ok := a.set[strings.ToLower(pkHex)]
	return ok
}

// shouldLog reports whether a refusal for pkHex should be logged now,
// rate-limiting repeated refusals from the same identity to one line per
// allowedPeerRefusalLogInterval.
func (a *peerAllowlist) shouldLog(pkHex string, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := strings.ToLower(pkHex)
	if last, seen := a.lastWarn[key]; seen && now.Sub(last) < allowedPeerRefusalLogInterval {
		return false
	}
	a.lastWarn[key] = now
	return true
}

// checkAllowedPeer enforces [mesh] allowed_peers for a freshly authenticated
// peer identity, right after the BRC-31 handshake completes and before any
// of its messages are processed. A refused peer is removed immediately
// (closing its transport); the refusal is logged once per
// allowedPeerRefusalLogInterval for that identity, not on every attempt.
// Returns true if the peer may proceed.
func (m *Manager) checkAllowedPeer(pkHex, direction, endpoint string) bool {
	if m.allowlist == nil || m.allowlist.allows(pkHex) {
		return true
	}
	if m.allowlist.shouldLog(pkHex, time.Now()) {
		m.logger.Warn("peer identity refused: not in [mesh] allowed_peers",
			"peer", truncate(pkHex),
			"direction", direction,
			"endpoint", endpoint)
	}
	m.removePeerWithReason(pkHex, "not_allowed")
	return false
}
