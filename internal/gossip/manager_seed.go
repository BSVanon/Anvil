package gossip

import (
	"context"
	"fmt"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// ConnectSeedWithReconnect connects to a seed peer and automatically
// reconnects if the connection drops. Blocks until ctx is cancelled.
// Designed to run in a goroutine per seed peer.
func (m *Manager) ConnectSeedWithReconnect(ctx context.Context, endpoint string, interval time.Duration) {
	for {
		transport, err := NewWSTransportAdapter(endpoint)
		if err != nil {
			m.logger.Warn("seed peer connect failed, retrying",
				"endpoint", endpoint, "error", err, "retry_in", interval)
			select {
			case <-ctx.Done():
				return
			case <-time.After(interval):
				continue
			}
		}

		peer := auth.NewPeer(&auth.PeerOptions{
			Wallet:    m.wallet,
			Transport: transport,
		})

		peer.ListenForGeneralMessages(func(ctx context.Context, senderPK *ec.PublicKey, payload []byte) error {
			pkHex := fmt.Sprintf("%x", senderPK.Compressed())

			m.mu.Lock()
			needsBondCheck := false
			if mp, ok := m.peers[endpoint]; ok && mp.IdentityPK == nil {
				mp.IdentityPK = senderPK
				m.peers[pkHex] = mp
				delete(m.peers, endpoint)
				needsBondCheck = true
			}
			m.mu.Unlock()

			if needsBondCheck && m.bondChecker != nil && m.bondChecker.Required() {
				balance, err := m.bondChecker.VerifyBond(senderPK)
				if err != nil {
					m.logger.Warn("outbound peer rejected: insufficient bond",
						"peer", truncate(pkHex),
						"endpoint", endpoint,
						"error", err.Error())
					m.recordConnectionEvent(ConnectionEvent{
						Direction: "outbound",
						Event:     "rejected",
						Endpoint:  endpoint,
						Identity:  pkHex,
						Reason:    err.Error(),
					})
					m.removePeerWithReason(pkHex, "bond_rejected")
					return fmt.Errorf("bond required: %w", err)
				}
				m.mu.Lock()
				if mp, ok := m.peers[pkHex]; ok {
					mp.BondSats = balance
				}
				m.mu.Unlock()
				m.logger.Info("outbound peer bond verified",
					"peer", truncate(pkHex),
					"bond_sats", balance)
			}
			if needsBondCheck {
				m.notePeerIdentity(pkHex)
			}

			return m.handleMessage(pkHex, senderPK, payload)
		})

		if err := peer.Start(); err != nil {
			m.logger.Warn("seed peer start failed, retrying",
				"endpoint", endpoint, "error", err, "retry_in", interval)
			transport.Close()
			select {
			case <-ctx.Done():
				return
			case <-time.After(interval):
				continue
			}
		}

		m.mu.Lock()
		m.peers[endpoint] = &MeshPeer{
			Peer:        peer,
			Endpoint:    endpoint,
			Direction:   "outbound",
			ConnectedAt: time.Now(),
			origKey:     endpoint,
			closeFunc:   transport.Close,
		}
		peerCount := len(m.peers)
		m.mu.Unlock()

		m.logger.Info("seed peer connected", "endpoint", endpoint)
		m.recordConnectionEvent(ConnectionEvent{
			Direction: "outbound",
			Event:     "connected",
			Endpoint:  endpoint,
			PeerCount: peerCount,
		})
		m.logLiveDataReady(peerCount)

		go transport.StartReceive()

		if err := m.announceInterests(peer); err != nil {
			m.logger.Warn("seed peer interest announce failed", "endpoint", endpoint, "error", err)
		}
		m.announceSHIP(peer)
		m.requestCatchUp(peer)

		// Wait for connection to drop or context cancel
		select {
		case <-transport.Done():
			m.removePeerWithReason(endpoint, "transport_closed")
			m.logger.Warn("seed peer disconnected, reconnecting",
				"endpoint", endpoint, "retry_in", interval)
		case <-ctx.Done():
			m.removePeerWithReason(endpoint, "context_cancelled")
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// Stop gracefully disconnects all peers, closing their transport connections.
// Emits disconnect events to the connection log so restarts are visible.
func (m *Manager) Stop() {
	m.mu.Lock()
	var events []ConnectionEvent
	for _, peer := range m.peers {
		events = append(events, m.disconnectEventForPeer(peer, "shutdown", len(m.peers)-1))
		if peer.Peer != nil {
			peer.Peer.Stop()
		}
		if peer.closeFunc != nil {
			peer.closeFunc()
		}
	}
	m.peers = make(map[string]*MeshPeer)
	m.mu.Unlock()
	for _, event := range events {
		m.recordConnectionEvent(event)
	}
}

// allowPeerMessage checks if a peer is within gossip rate limits.
// Returns true if allowed, false if rate-limited (drop silently).
// After sustained violations, broadcasts a gossip spam warning.
func (m *Manager) allowPeerMessage(peerPK string) bool {
	m.peerRateMu.Lock()
	defer m.peerRateMu.Unlock()

	now := time.Now()
	pr, ok := m.peerRates[peerPK]
	if !ok {
		m.peerRates[peerPK] = &peerRate{tokens: float64(m.rateBurst) - 1, lastSeen: now}
		return true
	}

	// Refill tokens
	elapsed := now.Sub(pr.lastSeen).Seconds()
	pr.tokens += elapsed * m.ratePerSec
	if pr.tokens > float64(m.rateBurst) {
		pr.tokens = float64(m.rateBurst)
	}
	pr.lastSeen = now

	if pr.tokens < 1 {
		pr.dropCount++
		// Escalate after sustained violation: 200 drops (generous for reconnect bursts),
		// max one warning per 10 minutes
		if pr.dropCount >= 200 && now.Sub(pr.lastWarnAt) > 10*time.Minute {
			pr.dropCount = 0
			pr.lastWarnAt = now
			// Release lock before broadcasting (broadcastSlashWarning acquires its own locks)
			m.peerRateMu.Unlock()
			m.logger.Warn("gossip spam detected, sending warning",
				"peer", truncate(peerPK), "drops", 200)
			m.broadcastSlashWarning(peerPK, SlashGossipSpam,
				"sustained rate limit violation (200+ drops)")
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
