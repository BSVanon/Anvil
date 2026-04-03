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

// requestCatchUp asks a peer for recent envelopes on topics this node cares about.
// Called after connect so new/reconnecting nodes immediately get catalog, feeds, etc.
// Catches up on: (1) built-in catchUpTopics, (2) non-empty local interest prefixes.
func (m *Manager) requestCatchUp(peer *auth.Peer) {
	// Merge built-in topics with non-empty interest prefixes (deduped).
	seen := make(map[string]struct{})
	var topics []string
	for _, t := range m.catchUpTopics {
		if _, ok := seen[t]; !ok {
			seen[t] = struct{}{}
			topics = append(topics, t)
		}
	}
	for _, prefix := range m.localInterests {
		if prefix == "" {
			continue // wildcard = "forward everything live", not "backfill entire store"
		}
		if _, ok := seen[prefix]; !ok {
			seen[prefix] = struct{}{}
			topics = append(topics, prefix)
		}
	}
	if len(topics) == 0 {
		return
	}
	// No round counter reset needed here — catchUpRounds is keyed by
	// "peerPK:topic", so a new peer naturally starts at 0 for all topics.
	for _, topic := range topics {
		payload, err := Encode(MsgDataRequest, DataRequestPayload{
			Topic: topic,
			Limit: 50,
		})
		if err != nil {
			continue
		}
		_ = peer.ToPeer(context.Background(), payload, nil, 5000)
	}
	m.logger.Debug("catch-up requested", "topics", topics)
}

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
	m.overlayDir.ForEachSHIP(func(identity, domain, nodeName, version, topic string) bool {
		peers = append(peers, SHIPPeerInfo{
			IdentityPub: identity,
			Domain:      domain,
			NodeName:    nodeName,
			Version:     version,
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
	_ = peer.ToPeer(context.Background(), payload, nil, 5000)
}

// ReannounceToAll sends this node's own SHIP registrations to all connected peers.
// Only sends self-registered entries (TxID == "self-registered") to prevent
// keeping dead remote peers alive by re-gossiping their stale entries.
// Call periodically to keep LastSeen fresh on remote directories.
func (m *Manager) ReannounceToAll() {
	if m.overlayDir == nil {
		return
	}
	var peers []SHIPPeerInfo
	m.overlayDir.ForEachSHIP(func(identity, domain, nodeName, version, topic string) bool {
		// Only include entries owned by local pubkeys — skip learned gossip entries
		if _, isLocal := m.localPubkeys[identity]; isLocal {
			peers = append(peers, SHIPPeerInfo{
				IdentityPub: identity,
				Domain:      domain,
				NodeName:    nodeName,
				Version:     version,
				Topic:       topic,
			})
		}
		return true
	})
	if len(peers) == 0 {
		return
	}
	payload, err := Encode(MsgSHIPSync, SHIPSyncPayload{Peers: peers})
	if err != nil {
		return
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, mp := range m.peers {
		if mp.Peer != nil {
			_ = mp.Peer.ToPeer(context.Background(), payload, mp.IdentityPK, 5000)
		}
	}
}

// onSHIPSync handles SHIP registrations received from a peer.
// Uses full-replace semantics: for each domain in the incoming sync,
// the new entry replaces any existing entry for that domain+topic.
// This ensures restarts and reconnects fully refresh the directory.
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
		// AddSHIPPeerFromGossip handles domain-based dedup internally:
		// removes any existing entry for the same domain+topic with a
		// different identity before adding the new one.
		if err := m.overlayDir.AddSHIPPeerFromGossip(p.IdentityPub, p.Domain, p.NodeName, p.Version, p.Topic); err == nil {
			added++
		}
		if p.Version != "" {
			m.mu.Lock()
			if mp, ok := m.peers[p.IdentityPub]; ok {
				mp.Version = p.Version
			}
			m.mu.Unlock()
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
			_ = peer.Peer.ToPeer(context.Background(), encoded, peer.IdentityPK, 5000)
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
		return m.onDataResponse(senderPKHex, senderPK, msg.Data)
	case MsgSHIPSync:
		return m.onSHIPSync(senderPKHex, msg.Data)
	case MsgSlashWarning:
		return m.onSlashWarning(senderPKHex, msg.Data)
	case MsgTxAnnounce, MsgTxRequest, MsgTxResponse:
		// Deprecated: tx relay messages accepted but not processed.
		// Mempool-era feature, no longer relevant post-Teranode.
		return nil
	default:
		m.logger.Debug("unknown mesh message type", "type", msg.Type)
	}
	return nil
}

// onData handles an incoming data envelope from a peer.
func (m *Manager) onData(senderPK string, raw json.RawMessage) error {
	// Gossip rate limit — loose (30/s burst 100). Drop silently, don't slash.
	if !m.allowPeerMessage(senderPK) {
		m.logger.Debug("peer rate-limited, dropping envelope", "peer", truncate(senderPK))
		return nil
	}

	env, err := envelope.UnmarshalEnvelope(raw)
	if err != nil {
		return nil
	}

	pubkey := strings.ToLower(env.Pubkey)
	hash := envelope.HashEnvelope(env.Topic, pubkey, env.Payload, env.Timestamp)
	// Dedup: skip envelopes we've already processed (by full content hash).
	m.seenMu.Lock()
	if _, seen := m.seen[hash]; seen {
		m.seenMu.Unlock()
		return nil
	}
	m.seen[hash] = struct{}{}
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
	m.seenMu.Unlock()

	if err := env.Validate(); err != nil {
		m.logger.Debug("envelope signature invalid", "topic", env.Topic, "error", err)
		return nil
	}

	if m.store != nil {
		if err := m.store.Ingest(env); err != nil {
			m.logger.Warn("envelope store error", "error", err)
		}
		// Catalog dedup: one entry per publisher, latest wins.
		if env.Topic == "anvil:catalog" && env.Durable {
			m.store.DeduplicateDurable(env)
		}
	}

	m.IncrReceived()

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
	if limit > 100 {
		limit = 100
	}

	// Fetch one extra to detect HasMore.
	allResults, _ := m.store.QueryByTopic(req.Topic, limit+1)

	// Filter by Since timestamp if set. Results are newest-first.
	// Since acts as an "older than" cursor: return envelopes with
	// timestamps strictly less than Since, enabling backward pagination.
	if req.Since > 0 {
		var filtered []*envelope.Envelope
		for _, env := range allResults {
			if env.Timestamp < req.Since {
				filtered = append(filtered, env)
			}
		}
		allResults = filtered
	}

	hasMore := len(allResults) > limit
	results := allResults
	if hasMore {
		results = allResults[:limit]
	}

	resp, err := Encode(MsgDataResponse, DataResponsePayload{
		Topic:     req.Topic,
		Envelopes: results,
		HasMore:   hasMore,
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
// If HasMore is true, sends a follow-up request with Since set to the oldest
// timestamp received, up to maxCatchUpRounds total per topic.
func (m *Manager) onDataResponse(senderPKHex string, senderPK *ec.PublicKey, raw json.RawMessage) error {
	var resp DataResponsePayload
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil
	}

	var oldestTS int64
	for _, env := range resp.Envelopes {
		if err := env.Validate(); err != nil {
			continue
		}
		if m.store != nil {
			_ = m.store.Ingest(env)
		}
		if oldestTS == 0 || env.Timestamp < oldestTS {
			oldestTS = env.Timestamp
		}
	}

	// Follow up if the responder has more data and we haven't exceeded the
	// catch-up round limit (5 rounds = max 500 envelopes per topic per peer).
	if resp.HasMore && oldestTS > 0 {
		roundKey := senderPKHex + ":" + resp.Topic
		m.mu.RLock()
		rounds := m.catchUpRounds[roundKey]
		m.mu.RUnlock()
		if rounds < maxCatchUpRounds {
			m.mu.Lock()
			if m.catchUpRounds == nil {
				m.catchUpRounds = make(map[string]int)
			}
			m.catchUpRounds[roundKey] = rounds + 1
			m.mu.Unlock()

			payload, err := Encode(MsgDataRequest, DataRequestPayload{
				Topic: resp.Topic,
				Limit: 100,
				Since: oldestTS,
			})
			if err == nil {
				m.mu.RLock()
				peer, ok := m.peers[senderPKHex]
				m.mu.RUnlock()
				if ok && peer.Peer != nil {
					_ = peer.Peer.ToPeer(context.Background(), payload, senderPK, 5000)
				}
			}
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
					_ = peer.Peer.ToPeer(context.Background(), encoded, peer.IdentityPK, 5000)
					m.IncrSent()
				}
				break
			}
		}
	}
}
