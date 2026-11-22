package gossip

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/BSVanon/Anvil/internal/messaging"
)

// BroadcastHomeAck clears acknowledged IDs on the recipient's other homes.
// The same IDs remain as local persistent tombstones and are replayed during
// reconnect anti-entropy if this immediate send fails.
func (m *Manager) BroadcastHomeAck(recipient string, ids []string) {
	if !m.privateHomesEnabled() || len(ids) == 0 || len(ids) > maxHomeAckIDs {
		return
	}
	claim, ok, err := m.messagingPolicy.PrivateHomes.Current(recipient)
	if err != nil || !ok || !containsHome(claim.Homes, m.ownIdentity()) {
		return
	}
	payload, err := Encode(MsgHomeAck, HomeAckPayload{Recipient: recipient, MessageIDs: ids})
	if err != nil || len(payload) > maxHomeAckPayload {
		return
	}
	homes := make(map[string]struct{}, len(claim.Homes))
	for _, home := range claim.Homes {
		if home != m.ownIdentity() {
			homes[home] = struct{}{}
		}
	}
	m.sendToAllowedPeers(payload, "", homes)
}

func (m *Manager) onHomeAck(sender string, raw json.RawMessage) error {
	if !m.privateHomesEnabled() || !m.allowlist.allows(sender) || len(raw) > maxHomeAckPayload {
		return nil
	}
	var ack HomeAckPayload
	if json.Unmarshal(raw, &ack) != nil || len(ack.MessageIDs) == 0 || len(ack.MessageIDs) > maxHomeAckIDs {
		return nil
	}
	if !m.allowHomeControl(sender, len(ack.MessageIDs)) {
		m.logHomeDrop(sender, "private home control rate limited")
		return nil
	}
	if ack.Recipient != strings.ToLower(ack.Recipient) || !isCompressedKeyHex(ack.Recipient) {
		return nil
	}
	for _, id := range ack.MessageIDs {
		if strings.TrimSpace(id) == "" || len(id) > messaging.MaxMessageIDBytes {
			return nil
		}
	}
	claim, ok, err := m.messagingPolicy.PrivateHomes.Current(ack.Recipient)
	if err != nil || !ok || !containsHome(claim.Homes, sender) || !containsHome(claim.Homes, m.ownIdentity()) {
		return nil
	}
	if m.msgStore != nil {
		_, _ = m.msgStore.Acknowledge(ack.Recipient, ack.MessageIDs)
	}
	return nil
}

func (m *Manager) announcePrivateHomeAcks(target peerSendTarget, pacer *homeControlPacer) {
	if m.msgStore == nil || !m.privateHomesEnabled() {
		return
	}
	own := m.ownIdentity()
	_ = m.messagingPolicy.PrivateHomes.ForEachRecordPage(maxHomeRecords, func(records []messaging.PrivateHomeRecord) error {
		for _, claim := range records {
			if claim.Kind != messaging.PrivateHomeClaim || !containsHome(claim.Homes, own) || !containsHome(claim.Homes, target.identity) {
				continue
			}
			err := m.msgStore.ForEachAcknowledgementPage(claim.Member, maxHomeAckIDs, func(ids []string) error {
				if pacer != nil {
					pacer.wait(len(ids))
				}
				payload, encodeErr := Encode(MsgHomeAck, HomeAckPayload{Recipient: claim.Member, MessageIDs: ids})
				if encodeErr != nil || len(payload) > maxHomeAckPayload {
					return encodeErr
				}
				return target.peer.ToPeer(context.Background(), payload, target.identityPK, 5000)
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
}
