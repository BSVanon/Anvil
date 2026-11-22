package gossip

import (
	"context"
	"strings"
	"time"
)

// defaultSHIPForwardWindow bounds how often this node relays one SHIP entry.
// It stays well under the 45-minute re-announce interval, so refreshes still
// travel several hops, and well above the time a sync takes to cross a cycle.
const defaultSHIPForwardWindow = 10 * time.Minute

const maxSHIPForwarded = 10000 // matches the default cap for the other gossip dedup sets

func (m *Manager) storeAndSelectSHIP(entries []SHIPPeerInfo) (int, []SHIPPeerInfo) {
	added := 0
	forward := make([]SHIPPeerInfo, 0, len(entries))
	now := time.Now()
	for _, entry := range entries {
		if entry.IdentityPub == "" || entry.Domain == "" || entry.Topic == "" {
			continue
		}
		// The directory refresh happens for every valid arrival, even when the
		// forwarding window suppresses that entry on this pass.
		if err := m.overlayDir.AddSHIPPeerFromGossip(
			entry.IdentityPub, entry.Domain, entry.NodeName, entry.Version, entry.Topic,
		); err == nil {
			added++
			if m.markSHIPForwarded(entry, now) {
				forward = append(forward, entry)
			}
		}
		if entry.Version != "" {
			m.mu.Lock()
			if peer, ok := m.peers[entry.IdentityPub]; ok {
				peer.Version = entry.Version
			}
			m.mu.Unlock()
		}
	}
	return added, forward
}

// forwardSHIPToAll forwards SHIP sync to all peers except the sender.
func (m *Manager) forwardSHIPToAll(senderPK string, payload SHIPSyncPayload) {
	encoded, err := Encode(MsgSHIPSync, payload)
	if err != nil {
		return
	}
	for _, peer := range m.admittedPeers(senderPK) {
		_ = peer.peer.ToPeer(context.Background(), encoded, peer.identityPK, 5000)
	}
}

// markSHIPForwarded reports whether entry has not been forwarded during this
// manager's forwarding window. Directory writes happen before this check, so
// duplicate refreshes still update LastSeen even when they are not relayed.
func (m *Manager) markSHIPForwarded(entry SHIPPeerInfo, now time.Time) bool {
	if strings.EqualFold(entry.IdentityPub, m.localIdentity) {
		return false
	}
	key := shipForwardKey(entry)
	m.shipForwardMu.Lock()
	defer m.shipForwardMu.Unlock()
	if last, ok := m.shipForwarded[key]; ok && now.Sub(last) < m.shipForwardWindow {
		return false
	}
	if len(m.shipForwarded) >= maxSHIPForwarded {
		m.evictSHIPForwardedLocked(now)
	}
	m.shipForwarded[key] = now
	return true
}

func shipForwardKey(entry SHIPPeerInfo) string {
	return strings.Join([]string{
		entry.Topic,
		entry.IdentityPub,
		entry.Domain,
		entry.NodeName,
		entry.Version,
	}, "|")
}

// evictSHIPForwardedLocked first removes entries whose suppression window has
// elapsed, then trims to half the hard cap if the map is still full. The
// second pass mirrors the bounded seen-set eviction and prevents adversarial
// unique registrations from growing process memory without bound.
func (m *Manager) evictSHIPForwardedLocked(now time.Time) {
	for key, forwardedAt := range m.shipForwarded {
		if now.Sub(forwardedAt) >= m.shipForwardWindow {
			delete(m.shipForwarded, key)
		}
	}
	if len(m.shipForwarded) < maxSHIPForwarded {
		return
	}
	for key := range m.shipForwarded {
		delete(m.shipForwarded, key)
		if len(m.shipForwarded) <= maxSHIPForwarded/2 {
			break
		}
	}
}
