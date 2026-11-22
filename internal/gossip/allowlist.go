package gossip

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
)

// errPeerRefused is returned by establishAndAuthorizePeer when the peer's
// authenticated identity is not in [mesh] allowed_peers. Callers use
// errors.Is to tell this apart from a handshake failure (timeout, transport
// error), since the two call for different retry/backoff treatment.
var errPeerRefused = errors.New("peer identity not in allowed_peers")

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

// establishAndAuthorizePeer completes the BRC-31 handshake for an outbound
// dial — ConnectPeer / ConnectSeedWithReconnect — and checks the resulting
// identity against [mesh] allowed_peers before the caller sends anything
// derived from local state (topic interests, the SHIP directory, catch-up
// requests) to it.
//
// peer.GetAuthenticatedSession(ctx, nil, maxWaitMs) performs (or reuses) the
// handshake only — unlike peer.ToPeer, which performs the same handshake
// then immediately sends a payload on it with no way for the caller to
// intervene in between. Once this returns, go-sdk's autoPersistLastSession
// (on by default, see auth.PeerOptions) means a subsequent ToPeer(ctx, msg,
// nil, ...) call from the same peer reuses this session instead of
// re-handshaking, so callers can go straight to announcing once this
// succeeds.
//
// mp is the exact connection registered under a unique temporary key. On
// success bindPeerIdentity applies the duplicate rule and re-keys that exact
// connection to the authenticated identity. expectedIdentity is non-empty for
// learned peer records and is checked before any local state is sent.
//
// Returns the peer's identity hex and a nil error when the caller may
// proceed. Identity mismatch, self-connection, duplicate, and allowlist errors
// have already closed or detached this exact transport; the caller owns cleanup
// for a plain handshake error.
func (m *Manager) establishAndAuthorizePeer(ctx context.Context, peer *auth.Peer, mp *MeshPeer, expectedIdentity, endpoint string, maxWaitMs int) (pkHex string, err error) {
	session, err := peer.GetAuthenticatedSession(ctx, nil, maxWaitMs)
	if err != nil {
		return "", fmt.Errorf("handshake: %w", err)
	}
	senderPK := session.PeerIdentityKey
	pkHex = fmt.Sprintf("%x", senderPK.Compressed())
	if expectedIdentity != "" && pkHex != expectedIdentity {
		m.logger.Debug("mesh peer identity did not match advertisement",
			"endpoint", endpoint, "expected", truncate(expectedIdentity), "received", truncate(pkHex))
		m.removeMeshPeerWithReason(mp, "identity_mismatch")
		return pkHex, errIdentityMismatch
	}
	if pkHex == m.localIdentity && pkHex != "" {
		m.removeMeshPeerWithReason(mp, "self_connection")
		return pkHex, errSelfConnection
	}

	mp.admissionMu.Lock()
	defer mp.admissionMu.Unlock()
	if !m.allowPeerExact(mp, pkHex, "outbound", endpoint) {
		return pkHex, errPeerRefused
	}
	balance := 0
	if m.bondChecker != nil && m.bondChecker.Required() {
		balance, err = m.bondChecker.VerifyBond(senderPK)
		if err != nil {
			m.logger.Warn("peer rejected: insufficient bond", "peer", truncate(pkHex), "endpoint", endpoint, "error", err)
			m.removeMeshPeerWithReason(mp, "bond_rejected")
			return pkHex, fmt.Errorf("%w: %v", errBondRejected, err)
		}
	}
	if _, bindErr := m.bindPeerIdentity(mp, senderPK, true); bindErr != nil {
		return pkHex, bindErr
	}
	if !m.admitPeer(mp, balance) {
		return pkHex, errDuplicateConnection
	}
	return pkHex, nil
}
