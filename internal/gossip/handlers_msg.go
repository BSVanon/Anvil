package gossip

import (
	"context"
	"encoding/json"

	"github.com/BSVanon/Anvil/internal/messaging"
)

// MsgForwardPayload carries a point-to-point message for cross-node delivery.
type MsgForwardPayload struct {
	Message messaging.Message `json:"message"`
}

// ForwardMessage sends a message to peers that might host the recipient.
// If the recipient is on a different node, the message is gossiped to all
// peers — the receiving node stores it if the recipient matches.
func (m *Manager) ForwardMessage(msg *messaging.Message) {
	if msg == nil {
		return
	}

	payload, err := Encode(MsgForward, MsgForwardPayload{Message: *msg})
	if err != nil {
		m.logger.Warn("failed to encode message forward", "error", err)
		return
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, peer := range m.peers {
		if peer.Peer != nil {
			_ = peer.Peer.ToPeer(context.Background(), payload, peer.IdentityPK, 5000)
		}
	}
}

// onMsgForward handles an incoming forwarded message from a peer.
// Stores the message locally if this node holds the recipient's inbox.
func (m *Manager) onMsgForward(senderPKHex string, raw json.RawMessage) error {
	var fwd MsgForwardPayload
	if err := json.Unmarshal(raw, &fwd); err != nil {
		return nil
	}

	msg := &fwd.Message
	if msg.Recipient == "" || msg.Body == "" {
		return nil
	}

	// Dedup: use message ID as seen key to prevent loops.
	dedup := "msg:" + msg.MessageID
	m.seenMu.Lock()
	if _, seen := m.seen[dedup]; seen {
		m.seenMu.Unlock()
		return nil
	}
	m.seen[dedup] = struct{}{}
	m.seenMu.Unlock()

	// Store if we have a message store configured.
	if m.msgStore != nil {
		if _, err := m.msgStore.Send(msg); err != nil {
			m.logger.Debug("forwarded message store failed", "error", err)
		}
	}

	// Forward to other peers (flood-fill with dedup).
	payload, err := Encode(MsgForward, fwd)
	if err != nil {
		return nil
	}
	m.mu.RLock()
	for pkHex, peer := range m.peers {
		if pkHex == senderPKHex {
			continue
		}
		if peer.Peer != nil {
			_ = peer.Peer.ToPeer(context.Background(), payload, peer.IdentityPK, 5000)
		}
	}
	m.mu.RUnlock()

	return nil
}

// SetMsgStore sets the message store for forwarded message delivery.
func (m *Manager) SetMsgStore(s *messaging.Store) {
	m.msgStore = s
}
