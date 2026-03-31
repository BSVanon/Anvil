package gossip

// Slash warning tracking and enforcement.
// 48-hour grace period. Deregistration (soft slash) after threshold.
// Redistribution of bond value to remaining peers is v2 (requires on-chain).

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	sdk "github.com/bsv-blockchain/go-sdk/wallet"
)

const (
	slashGracePeriod   = 48 * time.Hour
	slashSpamThreshold = 3 // warnings within grace period before deregister
)

// slashRecord tracks warnings against a single peer.
type slashRecord struct {
	Warnings  []SlashWarningPayload
	FirstWarn time.Time
}

// slashTracker accumulates warnings per peer and triggers deregistration.
type slashTracker struct {
	mu      sync.Mutex
	records map[string]*slashRecord // target pubkey hex → record
}

func newSlashTracker() *slashTracker {
	return &slashTracker{records: make(map[string]*slashRecord)}
}

// addWarning records a warning. Returns true if the peer should be deregistered.
// Requires warnings from multiple unique reporters to prevent single-node attacks.
func (st *slashTracker) addWarning(w SlashWarningPayload) (shouldDeregister bool) {
	st.mu.Lock()
	defer st.mu.Unlock()

	rec, ok := st.records[w.Target]
	if !ok {
		rec = &slashRecord{FirstWarn: time.Now()}
		st.records[w.Target] = rec
	}

	// Expire old warnings outside grace period
	if time.Since(rec.FirstWarn) > slashGracePeriod {
		rec.Warnings = nil
		rec.FirstWarn = time.Now()
	}

	rec.Warnings = append(rec.Warnings, w)

	// Require 3+ same-reason warnings from 2+ unique reporters before deregistering.
	// This prevents single-node false positives from triggering mesh-wide action.
	count, reporters := st.countByReason(rec, w.Reason)
	return count >= slashSpamThreshold && reporters >= 2
}

// countByReason counts warnings and unique reporters for a specific reason.
func (st *slashTracker) countByReason(rec *slashRecord, reason SlashReason) (count, reporters int) {
	seen := make(map[string]struct{})
	for _, w := range rec.Warnings {
		if w.Reason == reason {
			count++
			seen[w.Reporter] = struct{}{}
		}
	}
	return count, len(seen)
}

// activeWarnings returns all unexpired warnings for a peer.
func (st *slashTracker) activeWarnings(target string) []SlashWarningPayload {
	st.mu.Lock()
	defer st.mu.Unlock()

	rec, ok := st.records[target]
	if !ok {
		return nil
	}
	if time.Since(rec.FirstWarn) > slashGracePeriod {
		delete(st.records, target)
		return nil
	}
	return rec.Warnings
}

// allActive returns warnings for all peers (for /stats exposure).
func (st *slashTracker) allActive() map[string][]SlashWarningPayload {
	st.mu.Lock()
	defer st.mu.Unlock()

	now := time.Now()
	result := make(map[string][]SlashWarningPayload)
	for target, rec := range st.records {
		if now.Sub(rec.FirstWarn) > slashGracePeriod {
			delete(st.records, target)
			continue
		}
		if len(rec.Warnings) > 0 {
			result[target] = rec.Warnings
		}
	}
	return result
}

// --- Manager methods for slash handling ---

// onSlashWarning handles an incoming slash warning from a peer.
func (m *Manager) onSlashWarning(senderPK string, raw json.RawMessage) error {
	var w SlashWarningPayload
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil
	}

	// Ignore warnings from unknown peers or self-reports
	if w.Target == "" || w.Reporter == "" || w.Target == senderPK {
		return nil
	}

	// Ignore double_publish warnings entirely. This reason was removed in v1.0.0
	// because second-granular timestamps make it a false-positive factory for fast
	// publishers. Old nodes may still send these — drop silently, don't forward.
	if w.Reason == SlashDoublePublish {
		return nil
	}

	// Dedup: use seen map to prevent gossip loops. Hash the warning payload.
	warnHash := fmt.Sprintf("slash:%s:%s:%s:%d", w.Target, w.Reporter, w.Reason, w.Timestamp)
	m.seenMu.Lock()
	if _, seen := m.seen[warnHash]; seen {
		m.seenMu.Unlock()
		return nil
	}
	m.seen[warnHash] = struct{}{}
	m.seenMu.Unlock()

	m.logger.Warn("slash warning received",
		"target", truncate(w.Target),
		"reason", w.Reason,
		"reporter", truncate(w.Reporter),
		"evidence", w.Evidence)

	shouldDeregister := m.slashTracker.addWarning(w)

	if shouldDeregister {
		m.logger.Warn("SLASH: peer deregistered after threshold exceeded",
			"target", truncate(w.Target),
			"reason", w.Reason,
			"warnings", len(m.slashTracker.activeWarnings(w.Target)))

		// Disconnect the peer if connected
		m.removePeer(w.Target)

		// Deregister from overlay
		if m.overlayDir != nil {
			m.overlayDir.RemoveSHIPPeerByIdentity(w.Target)
		}
	}

	// Forward to all peers (so the whole mesh knows)
	m.forwardSlashWarning(senderPK, raw)
	return nil
}

// forwardSlashWarning relays a slash warning to all peers except sender.
func (m *Manager) forwardSlashWarning(senderPK string, rawPayload json.RawMessage) {
	encoded, err := Encode(MsgSlashWarning, json.RawMessage(rawPayload))
	if err != nil {
		return
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for pkHex, peer := range m.peers {
		if pkHex == senderPK {
			continue
		}
		if peer.Peer != nil {
			_ = peer.Peer.ToPeer(context.Background(), encoded, peer.IdentityPK, 5000)
		}
	}
}

// broadcastSlashWarning sends a slash warning from this node to all peers.
func (m *Manager) broadcastSlashWarning(target string, reason SlashReason, evidence string) {
	selfPK := m.selfIdentity()
	if selfPK == "" {
		return
	}

	w := SlashWarningPayload{
		Target:    target,
		Reason:    reason,
		Evidence:  evidence,
		Timestamp: time.Now().Unix(),
		Reporter:  selfPK,
	}

	// Track locally too
	shouldDeregister := m.slashTracker.addWarning(w)

	payload, err := Encode(MsgSlashWarning, w)
	if err != nil {
		return
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, peer := range m.peers {
		if peer.Peer != nil {
			_ = peer.Peer.ToPeer(context.Background(), payload, peer.IdentityPK, 5000)
		}
	}

	if shouldDeregister {
		m.logger.Warn("SLASH: peer deregistered (self-detected)",
			"target", truncate(target), "reason", reason)
		go func() {
			m.removePeer(target)
			if m.overlayDir != nil {
				m.overlayDir.RemoveSHIPPeerByIdentity(target)
			}
		}()
	}
}

// selfIdentity returns this node's identity pubkey hex, or empty if no wallet.
func (m *Manager) selfIdentity() string {
	if m.wallet == nil {
		return ""
	}
	ctx := context.Background()
	result, err := m.wallet.GetPublicKey(ctx, sdk.GetPublicKeyArgs{
		IdentityKey: true,
	}, "anvil")
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", result.PublicKey.Compressed())
}

// SlashWarnings returns active warnings for /stats exposure.
func (m *Manager) SlashWarnings() map[string][]SlashWarningPayload {
	return m.slashTracker.allActive()
}
