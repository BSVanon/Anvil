package gossip

// Message handlers and SHIP sync for the gossip manager.
// Split from manager.go for file size discipline.

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/BSVanon/Anvil/internal/envelope"
)

// announceInterests sends our topic declarations to a peer.
func (m *Manager) announceInterests(peer *auth.Peer) error {
	payload, err := Encode(MsgTopics, TopicsPayload{Prefixes: m.localInterests})
	if err != nil {
		return err
	}
	ctx := context.Background()
	return peer.ToPeer(ctx, payload, nil, 5000)
}

// announceSHIP sends all local SHIP registrations to a peer.
func (m *Manager) announceSHIP(peer *auth.Peer) {
	if m.overlayDir == nil {
		return
	}
	var peers []SHIPPeerInfo
	m.overlayDir.ForEachSHIP(func(identity, domain, nodeName, topic string) bool {
		peers = append(peers, SHIPPeerInfo{
			IdentityPub: identity,
			Domain:      domain,
			NodeName:    nodeName,
			Topic:       topic,
		})
		return true
	})
	if len(peers) == 0 {
		return
	}
	payload, err := Encode(MsgSHIPSync, SHIPSyncPayload{Peers: peers})
	if err != nil {
		return
	}
	peer.ToPeer(context.Background(), payload, nil, 5000)
}

// onSHIPSync handles SHIP registrations received from a peer.
func (m *Manager) onSHIPSync(senderPK string, raw json.RawMessage) error {
	if m.overlayDir == nil {
		return nil
	}
	var sp SHIPSyncPayload
	if err := json.Unmarshal(raw, &sp); err != nil {
		return nil
	}
	added := 0
	for _, p := range sp.Peers {
		if p.IdentityPub == "" || p.Domain == "" || p.Topic == "" {
			continue
		}
		if err := m.overlayDir.AddSHIPPeerFromGossip(p.IdentityPub, p.Domain, p.NodeName, p.Topic); err == nil {
			added++
		}
	}
	if added > 0 {
		m.logger.Info("SHIP sync received", "from", truncate(senderPK), "added", added)
		m.forwardSHIPToAll(senderPK, raw)
	}
	return nil
}

// forwardSHIPToAll forwards SHIP sync to all peers except the sender.
func (m *Manager) forwardSHIPToAll(senderPK string, rawPayload json.RawMessage) {
	encoded, err := Encode(MsgSHIPSync, json.RawMessage(rawPayload))
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
			peer.Peer.ToPeer(context.Background(), encoded, peer.IdentityPK, 5000)
		}
	}
}

// handleMessage processes an incoming mesh message from an authenticated peer.
func (m *Manager) handleMessage(senderPKHex string, senderPK *ec.PublicKey, payload []byte) error {
	msg, err := Decode(payload)
	if err != nil {
		m.logger.Warn("invalid mesh message", "error", err)
		return nil
	}

	switch msg.Type {
	case MsgData:
		return m.onData(senderPKHex, msg.Data)
	case MsgTopics:
		return m.onTopics(senderPKHex, msg.Data)
	case MsgDataRequest:
		return m.onDataRequest(senderPKHex, senderPK, msg.Data)
	case MsgDataResponse:
		return m.onDataResponse(msg.Data)
	case MsgSHIPSync:
		return m.onSHIPSync(senderPKHex, msg.Data)
	default:
		m.logger.Debug("unknown mesh message type", "type", msg.Type)
	}
	return nil
}

// onData handles an incoming data envelope from a peer.
func (m *Manager) onData(senderPK string, raw json.RawMessage) error {
	env, err := envelope.UnmarshalEnvelope(raw)
	if err != nil {
		return nil
	}

	hash := envelope.HashEnvelope(env.Topic, env.Pubkey, env.Payload, env.Timestamp)
	m.seenMu.Lock()
	if _, seen := m.seen[hash]; seen {
		m.seenMu.Unlock()
		return nil
	}
	if len(m.seen) >= m.maxSeen {
		count := 0
		for k := range m.seen {
			delete(m.seen, k)
			count++
			if count >= m.maxSeen/2 {
				break
			}
		}
	}
	m.seen[hash] = struct{}{}
	m.seenMu.Unlock()

	if err := env.Validate(); err != nil {
		m.logger.Debug("envelope signature invalid", "topic", env.Topic, "error", err)
		return nil
	}

	if m.store != nil {
		if err := m.store.Ingest(env); err != nil {
			m.logger.Warn("envelope store error", "error", err)
		}
	}

	if m.onEnvelope != nil {
		m.onEnvelope(env)
	}

	if !env.NoGossip {
		m.forwardToInterested(senderPK, env.Topic, raw)
	}

	return nil
}

// onTopics handles a peer's interest declaration.
func (m *Manager) onTopics(senderPK string, raw json.RawMessage) error {
	var tp TopicsPayload
	if err := json.Unmarshal(raw, &tp); err != nil {
		return nil
	}
	m.mu.Lock()
	m.interests[senderPK] = tp.Prefixes
	m.mu.Unlock()
	m.logger.Debug("peer interests updated", "peer", truncate(senderPK), "prefixes", tp.Prefixes)
	return nil
}

// onDataRequest handles a pull-based catch-up query.
func (m *Manager) onDataRequest(senderPKHex string, senderPK *ec.PublicKey, raw json.RawMessage) error {
	var req DataRequestPayload
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil
	}

	if m.store == nil {
		return nil
	}

	limit := req.Limit
	if limit <= 0 {
		limit = 100
	}
	results, _ := m.store.QueryByTopic(req.Topic, limit)

	resp, err := Encode(MsgDataResponse, DataResponsePayload{
		Topic:     req.Topic,
		Envelopes: results,
		HasMore:   false,
	})
	if err != nil {
		return err
	}

	m.mu.RLock()
	peer, ok := m.peers[senderPKHex]
	m.mu.RUnlock()
	if ok && peer.Peer != nil {
		return peer.Peer.ToPeer(context.Background(), resp, senderPK, 5000)
	}
	return nil
}

// onDataResponse handles catch-up response. Stores locally without re-gossiping.
func (m *Manager) onDataResponse(raw json.RawMessage) error {
	var resp DataResponsePayload
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil
	}

	for _, env := range resp.Envelopes {
		if err := env.Validate(); err != nil {
			continue
		}
		if m.store != nil {
			m.store.Ingest(env)
		}
	}
	return nil
}

// forwardToInterested sends an envelope to peers whose declared interests match the topic.
func (m *Manager) forwardToInterested(senderPK string, topic string, rawEnvelope json.RawMessage) {
	encoded, err := Encode(MsgData, rawEnvelope)
	if err != nil {
		return
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	for pkHex, peer := range m.peers {
		if pkHex == senderPK {
			continue
		}

		prefixes := m.interests[pkHex]
		for _, prefix := range prefixes {
			if strings.HasPrefix(topic, prefix) {
				if peer.Peer != nil {
					peer.Peer.ToPeer(context.Background(), encoded, peer.IdentityPK, 5000)
				}
				break
			}
		}
	}
}
