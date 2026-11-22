package gossip

import (
	"context"
	"errors"
	"time"
)

const maxRefusalBackoff = 10 * time.Minute

// ConnectSeedWithReconnect maintains one configured seed. Once the endpoint's
// identity is known, a connection for that identity in either direction
// suppresses redials. This prevents reciprocal seed entries from churning.
func (m *Manager) ConnectSeedWithReconnect(ctx context.Context, endpoint string, interval time.Duration) {
	consecutiveFails := 0
	consecutiveRefusals := 0
	knownIdentity := ""
	forceEndpointRedial := false
	for {
		if forceEndpointRedial && m.identitySupportsExactRemoval(knownIdentity) {
			forceEndpointRedial = false
		}
		if !forceEndpointRedial && knownIdentity != "" && m.hasIdentityConnection(knownIdentity) {
			if !waitSeedInterval(ctx, interval) {
				return
			}
			continue
		}
		forceEndpointRedial = false

		mp, transport, identity, err := m.connectPeer(ctx, endpoint, connectPeerOptions{seed: true, dialTimeout: 10 * time.Second})
		if identity != "" {
			knownIdentity = identity
			m.noteSeedIdentity(identity)
		}
		if err != nil {
			switch {
			case errors.Is(err, errSelfConnection):
				m.logger.Warn("[mesh] seeds entry is this node itself; not dialing it again", "endpoint", endpoint)
				return
			case errors.Is(err, errDuplicateConnection):
				if !waitSeedInterval(ctx, interval) {
					return
				}
				continue
			case errors.Is(err, errPeerRefused):
				consecutiveRefusals++
				delay := interval * time.Duration(uint64(1)<<min(consecutiveRefusals, 5))
				if delay > maxRefusalBackoff {
					delay = maxRefusalBackoff
				}
				m.logger.Warn("seed peer refused by allowed_peers, backing off",
					"endpoint", endpoint, "peer", truncate(identity), "retry_in", delay)
				if !waitSeedInterval(ctx, delay) {
					return
				}
				continue
			default:
				consecutiveFails++
				delay := interval * time.Duration(uint64(1)<<min(consecutiveFails-1, 4))
				if delay > 5*time.Minute {
					delay = 5 * time.Minute
				}
				m.logger.Warn("seed peer connect failed, retrying", "endpoint", endpoint,
					"error", err, "retry_in", delay, "consecutive_fails", consecutiveFails)
				if !waitSeedInterval(ctx, delay) {
					return
				}
				continue
			}
		}

		consecutiveFails = 0
		consecutiveRefusals = 0
		m.logger.Info("seed peer connected", "endpoint", endpoint, "peer", truncate(identity))
		select {
		case <-transport.Done():
			reason := transport.CloseReason()
			if reason == "" {
				reason = "transport_closed"
			}
			m.removeMeshPeerWithReason(mp, reason)
			forceEndpointRedial = m.needsCompatibilityRedial(mp, knownIdentity)
			m.logger.Warn("seed peer disconnected, reconnecting", "endpoint", endpoint, "reason", reason, "retry_in", interval)
		case <-ctx.Done():
			m.removeMeshPeerWithReason(mp, "context_cancelled")
			return
		}
		if !waitSeedInterval(ctx, interval) {
			return
		}
	}
}

func (m *Manager) identitySupportsExactRemoval(identity string) bool {
	m.mu.RLock()
	_, ok := m.duplicateSafePeers[identity]
	m.mu.RUnlock()
	return ok
}

func (m *Manager) needsCompatibilityRedial(peer *MeshPeer, identity string) bool {
	if peer == nil || identity == "" {
		return false
	}
	m.mu.RLock()
	reason := peer.closeReason
	_, exactRemoval := m.duplicateSafePeers[identity]
	m.mu.RUnlock()
	return !exactRemoval && reason != "duplicate_connection" &&
		reason != "self_connection" && reason != "identity_mismatch"
}

func waitSeedInterval(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// Stop gracefully disconnects all peers, closing their transport connections.
func (m *Manager) Stop() {
	m.mu.Lock()
	unique := make(map[*MeshPeer]struct{}, len(m.peers))
	peers := make([]*MeshPeer, 0, len(m.peers))
	for _, peer := range m.peers {
		if _, seen := unique[peer]; seen {
			continue
		}
		unique[peer] = struct{}{}
		peer.closed = true
		peer.closeReason = "shutdown"
		peers = append(peers, peer)
	}
	m.peers = make(map[string]*MeshPeer)
	m.mu.Unlock()
	for _, peer := range peers {
		m.closeDetachedPeer(peer, "shutdown", 0)
	}
}

// allowPeerMessage checks the per-identity gossip token bucket.
func (m *Manager) allowPeerMessage(peerPK string) bool {
	m.peerRateMu.Lock()
	defer m.peerRateMu.Unlock()
	now := time.Now()
	pr, ok := m.peerRates[peerPK]
	if !ok {
		m.peerRates[peerPK] = &peerRate{tokens: float64(m.rateBurst) - 1, lastSeen: now}
		return true
	}
	pr.tokens += now.Sub(pr.lastSeen).Seconds() * m.ratePerSec
	if pr.tokens > float64(m.rateBurst) {
		pr.tokens = float64(m.rateBurst)
	}
	pr.lastSeen = now
	if pr.tokens < 1 {
		pr.dropCount++
		if pr.dropCount >= 200 && now.Sub(pr.lastWarnAt) > 10*time.Minute {
			pr.dropCount = 0
			pr.lastWarnAt = now
			m.peerRateMu.Unlock()
			m.logger.Warn("gossip spam detected, sending warning", "peer", truncate(peerPK), "drops", 200)
			m.broadcastSlashWarning(peerPK, SlashGossipSpam, "sustained rate limit violation (200+ drops)")
			m.peerRateMu.Lock()
		}
		return false
	}
	pr.tokens--
	return true
}

func truncate(s string) string {
	if len(s) > 16 {
		return s[:16] + "..."
	}
	return s
}
