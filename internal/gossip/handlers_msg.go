package gossip

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/BSVanon/Anvil/internal/messaging"
)

// MsgForwardPayload carries a signed point-to-point message for cross-node delivery.
type MsgForwardPayload struct {
	Message   messaging.Message `json:"message"`
	Signature string            `json:"signature"` // DER hex, sender signs messageID:recipient:messageBox:body:timestamp
}

// signMessage computes a SHA-256 digest over the message fields and signs it.
func signMessage(msg *messaging.Message, key *ec.PrivateKey) (string, error) {
	digest := messageDigest(msg)
	sig, err := key.Sign(digest[:])
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sig.Serialize()), nil
}

// verifyMessageSignature checks the sender's signature over message fields.
func verifyMessageSignature(msg *messaging.Message, sigHex string) bool {
	if sigHex == "" || msg.Sender == "" {
		return false
	}
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	pubBytes, err := hex.DecodeString(msg.Sender)
	if err != nil {
		return false
	}
	pub, err := ec.PublicKeyFromBytes(pubBytes)
	if err != nil {
		return false
	}
	sig, err := ec.FromDER(sigBytes)
	if err != nil {
		return false
	}
	digest := messageDigest(msg)
	return sig.Verify(digest[:], pub)
}

func messageDigest(msg *messaging.Message) [32]byte {
	canonical := msg.MessageID + "\n" +
		msg.Recipient + "\n" +
		msg.MessageBox + "\n" +
		msg.Body + "\n" +
		fmt.Sprintf("%d", msg.Timestamp)
	return sha256.Sum256([]byte(canonical))
}

// ForwardMessage sends a signed message to peers for cross-node delivery.
func (m *Manager) ForwardMessage(msg *messaging.Message) {
	if msg == nil {
		return
	}

	// Sign the message with this node's identity key.
	var sigHex string
	if m.identityKey != nil {
		var err error
		sigHex, err = signMessage(msg, m.identityKey)
		if err != nil {
			m.logger.Warn("failed to sign message for forwarding", "error", err)
		}
	}

	payload, err := Encode(MsgForward, MsgForwardPayload{
		Message:   *msg,
		Signature: sigHex,
	})
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

// ForwardSignedMessage sends a pre-signed message to peers.
// Used by the API handler which has the sender's signature.
func (m *Manager) ForwardSignedMessage(msg *messaging.Message, sigHex string) {
	if msg == nil {
		return
	}

	payload, err := Encode(MsgForward, MsgForwardPayload{
		Message:   *msg,
		Signature: sigHex,
	})
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
// Only stores the message if the recipient is hosted on this node.
// Verifies sender signature before accepting.
func (m *Manager) onMsgForward(senderPKHex string, raw json.RawMessage) error {
	var fwd MsgForwardPayload
	if err := json.Unmarshal(raw, &fwd); err != nil {
		return nil
	}

	msg := &fwd.Message
	if msg.Recipient == "" || msg.Body == "" || msg.MessageID == "" {
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

	// Require and verify sender signature. Reject unsigned forwards
	// to prevent sender identity forgery by authenticated peers.
	if fwd.Signature == "" {
		m.logger.Debug("forwarded message rejected: no signature")
		return nil
	}
	if !verifyMessageSignature(msg, fwd.Signature) {
		m.logger.Warn("forwarded message signature invalid",
			"sender", msg.Sender[:16], "recipient", msg.Recipient[:16])
		return nil
	}

	// Store using Deliver (preserves original MessageID) — only if we
	// have a message store. Every node stores forwarded messages so the
	// recipient can query any node they're connected to.
	if m.msgStore != nil {
		if ok, err := m.msgStore.Deliver(msg); err != nil {
			m.logger.Debug("forwarded message store failed", "error", err)
		} else if ok {
			m.logger.Debug("forwarded message delivered",
				"id", msg.MessageID, "recipient", msg.Recipient[:16])
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
