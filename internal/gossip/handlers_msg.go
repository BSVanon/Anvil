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

// MsgForwardPayload carries a point-to-point message for cross-node delivery.
//
// Sender attestation (canonical BRC-33 model): under canonical MessageBox the
// SERVER establishes the sender from BRC-31 auth at submission and vouches for
// it (message-box-server sendMessage.ts: `sender = req.auth.identityKey`); there
// is no per-message end-to-end signature. Anvil mirrors that across its mesh: the
// origin node — which authenticated the sender via BRC-31 — sets OriginNode to
// its own identity and signs the forward with its node key over a digest that
// binds OriginNode + the attested Sender + content. Receivers verify against
// OriginNode and trust its sender attestation (the same inter-server trust
// BRC-34 federation relies on). msg.Sender is therefore the real user identity,
// not the relay.
//
// TRUST ASSUMPTION (important — not end-to-end authenticity): this proves only
// that *some* mesh peer with a valid OriginNode signature vouched for msg.Sender.
// Any authenticated mesh peer can attest an arbitrary Sender; a receiving node
// trusts its federation peers' attestations. This is intentionally weaker than
// direct BRC-31 user auth (same node) and weaker than BRC-34 overlay-routed
// host-to-host delivery. Do NOT treat a cross-node forwarded Sender as proof of
// cross-operator user identity. Same-node delivery (the DEX v1 single-node path)
// has full BRC-31 user auth; authoritative cross-node sender semantics await
// BRC-34 overlay-routed forwarding (tracked follow-up).
type MsgForwardPayload struct {
	Message    messaging.Message `json:"message"`
	Signature  string            `json:"signature"`            // DER hex over messageForwardDigest(msg, originNode)
	OriginNode string            `json:"originNode,omitempty"` // node that authenticated the sender + signed (empty = legacy pre-v3.2.0)
}

// verifyForwardSignature validates a forwarded message. v3.2.0+ payloads carry
// OriginNode: the signature is the origin node's, verified against the OriginNode
// key over a digest that binds OriginNode + Sender + content (so an intermediate
// relay cannot alter the attested sender without invalidating the signature).
// Legacy payloads (no OriginNode) keep the pre-v3.2.0 contract: the sender signed,
// verified against msg.Sender.
func verifyForwardSignature(fwd *MsgForwardPayload) bool {
	if fwd == nil || fwd.Signature == "" {
		return false
	}
	sigBytes, err := hex.DecodeString(fwd.Signature)
	if err != nil {
		return false
	}
	sig, err := ec.FromDER(sigBytes)
	if err != nil {
		return false
	}
	msg := &fwd.Message
	if fwd.OriginNode != "" {
		pub, err := pubKeyFromHex(fwd.OriginNode)
		if err != nil {
			return false
		}
		digest := messageForwardDigest(msg, fwd.OriginNode)
		return sig.Verify(digest[:], pub)
	}
	// Legacy: sender-signed.
	if msg.Sender == "" {
		return false
	}
	pub, err := pubKeyFromHex(msg.Sender)
	if err != nil {
		return false
	}
	digest := messageDigest(msg)
	return sig.Verify(digest[:], pub)
}

func pubKeyFromHex(h string) (*ec.PublicKey, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	return ec.PublicKeyFromBytes(b)
}

// messageDigest is the legacy (pre-v3.2.0) content digest: sender signs this.
func messageDigest(msg *messaging.Message) [32]byte {
	canonical := msg.MessageID + "\n" +
		msg.Recipient + "\n" +
		msg.MessageBox + "\n" +
		msg.Body + "\n" +
		fmt.Sprintf("%d", msg.Timestamp)
	return sha256.Sum256([]byte(canonical))
}

// messageForwardDigest binds the attesting origin node AND the attested sender to
// the message content, so a relay can neither forge the origin attestation nor
// swap the claimed sender without breaking the origin node's signature.
func messageForwardDigest(msg *messaging.Message, originNode string) [32]byte {
	canonical := originNode + "\n" +
		msg.Sender + "\n" +
		msg.MessageID + "\n" +
		msg.Recipient + "\n" +
		msg.MessageBox + "\n" +
		msg.Body + "\n" +
		fmt.Sprintf("%d", msg.Timestamp)
	return sha256.Sum256([]byte(canonical))
}

// ForwardMessage sends a message to peers for cross-node delivery, attesting the
// BRC-31-authenticated sender with this node's identity (origin-node attestation,
// per the canonical server-vouches-for-sender model). msg.Sender carries the real
// user identity; this node signs the forward so peers can verify the attestation.
func (m *Manager) ForwardMessage(msg *messaging.Message) {
	if msg == nil {
		return
	}

	// This node authenticated the sender (BRC-31) and attests it: OriginNode is
	// our identity, and we sign over (OriginNode + Sender + content).
	var sigHex, originNode string
	if m.identityKey != nil {
		originNode = hex.EncodeToString(m.identityKey.PubKey().Compressed())
		digest := messageForwardDigest(msg, originNode)
		sig, err := m.identityKey.Sign(digest[:])
		if err != nil {
			m.logger.Warn("failed to sign message for forwarding", "error", err)
		} else {
			sigHex = hex.EncodeToString(sig.Serialize())
		}
	}

	payload, err := Encode(MsgForward, MsgForwardPayload{
		Message:    *msg,
		Signature:  sigHex,
		OriginNode: originNode,
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

	// Require and verify the forward signature. v3.2.0+ forwards are signed by
	// the origin node attesting the BRC-31 sender (verified against OriginNode);
	// legacy forwards are sender-signed (verified against msg.Sender). Reject
	// unsigned/invalid forwards to prevent sender-identity forgery.
	if fwd.Signature == "" {
		m.logger.Debug("forwarded message rejected: no signature")
		return nil
	}
	if !verifyForwardSignature(&fwd) {
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
