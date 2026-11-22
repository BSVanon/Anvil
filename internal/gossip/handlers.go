package gossip

// Message handlers and SHIP sync for the gossip manager.
// Split from manager.go for file size discipline.

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/BSVanon/Anvil/internal/envelope"
)

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
	m.shipReceived.Add(1)
	added, forward := m.storeAndSelectSHIP(sp.Peers)
	if added > 0 {
		m.logger.Info("SHIP sync received", "from", truncate(senderPK), "added", added)
	}
	if len(forward) > 0 {
		m.forwardSHIPToAll(senderPK, SHIPSyncPayload{Peers: forward})
	}
	return nil
}

// handleMessage processes an incoming mesh message from an authenticated peer.
func (m *Manager) handleMessage(senderPKHex string, senderPK *ec.PublicKey, payload []byte) error {
	// Exact-socket admission is the application boundary. A temporary map key,
	// duplicate loser, refused identity, or bond-rejected socket cannot dispatch
	// any message type, including private-home control frames.
	if _, ok := m.admittedPeer(senderPKHex); !ok {
		return errPeerRefused
	}
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
	case MsgForward:
		return m.onMsgForward(senderPKHex, msg.Data)
	case MsgACMEChallenge:
		return m.onACMEChallenge(senderPKHex, msg.Data)
	case MsgHomeClaim:
		return m.onHomeClaim(senderPKHex, msg.Data)
	case MsgHomeRevoke:
		return m.onHomeRevoke(senderPKHex, msg.Data)
	case MsgHomeAck:
		return m.onHomeAck(senderPKHex, msg.Data)
	case MsgHomeStatus:
		return m.onHomeStatus(senderPKHex, msg.Data)
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
		m.IncrDuplicateArrival()
		return nil
	}
	m.seen[hash] = struct{}{}
	m.evictSeenLocked()
	m.seenMu.Unlock()

	if err := env.Validate(); err != nil {
		m.logger.Debug("envelope signature invalid", "topic", env.Topic, "error", err)
		return nil
	}
	m.observePeerAdvert(env)

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

	if !env.NoGossip && !env.Private {
		m.forwardToInterested(senderPK, env.Topic, raw)
	}

	return nil
}

// evictSeenLocked trims m.seen back to maxSeen/2 once it has reached
// maxSeen, amortizing the cost of the dedup set's otherwise-unbounded
// growth. Callers must hold seenMu and must already have inserted the key
// they just saw — map iteration order is unspecified, so (as before this
// was extracted from onData) the just-inserted key is not specially
// protected from eviction. onSlashWarning routes its own m.seen insert
// through this same path (it previously inserted with no bound at all,
// letting an attacker grow m.seen past maxSeen by varying each warning's
// timestamp) so every m.seen writer shares one bounded insert-and-evict
// path, the way onMsgForward/finishForwardSeen already share
// evictMsgSeenLocked for m.msgSeen.
func (m *Manager) evictSeenLocked() {
	if len(m.seen) < m.maxSeen {
		return
	}
	count := 0
	for k := range m.seen {
		delete(m.seen, k)
		m.IncrDedupEviction()
		count++
		if count >= m.maxSeen/2 {
			break
		}
	}
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

// dropPrivate returns envs with all Private envelopes removed. Private
// envelopes are read-gated to authenticated HTTP callers only and are never
// served over the mesh pull, so the sealed blob and its metadata never leave
// this node to a pulling peer. Filters in place (reuses the backing array).
func dropPrivate(envs []*envelope.Envelope) []*envelope.Envelope {
	kept := envs[:0]
	for _, env := range envs {
		if !env.Private {
			kept = append(kept, env)
		}
	}
	return kept
}

// visiblePage takes an envelope set, drops Private envelopes, applies the
// compound backward-pagination cursor, and returns one stable newest-first
// page. It remains as the small in-memory pagination oracle used by tests; the
// request path reads the bounded public store index directly.
func visiblePage(all []*envelope.Envelope, limit int, after envelope.PageCursor) (page []*envelope.Envelope, hasMore bool) {
	all = dropPrivate(all)
	sort.Slice(all, func(i, j int) bool {
		if all[i].Timestamp != all[j].Timestamp {
			return all[i].Timestamp > all[j].Timestamp
		}
		return envelope.CursorFor(all[i]).ID < envelope.CursorFor(all[j]).ID
	})
	if after.ID != "" {
		filtered := all[:0]
		for _, e := range all {
			cursor := envelope.CursorFor(e)
			if e.Timestamp < after.Timestamp || (e.Timestamp == after.Timestamp && cursor.ID > after.ID) {
				filtered = append(filtered, e)
			}
		}
		all = filtered
	}
	if limit > 0 && len(all) > limit {
		return all[:limit], true
	}
	return all, false
}

// onDataRequest handles a pull-based catch-up query.
func (m *Manager) onDataRequest(senderPKHex string, senderPK *ec.PublicKey, raw json.RawMessage) error {
	if !m.allowPeerMessage(senderPKHex) {
		m.logger.Debug("peer rate-limited, dropping data request", "peer", truncate(senderPKHex))
		return nil
	}

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

	after := envelope.PageCursor{}
	if req.Cursor != nil {
		after = *req.Cursor
	} else if req.Since > 0 {
		// Compatibility with timestamp-only peers. New peers always send the
		// compound cursor below, which is required to cross equal timestamps.
		after = envelope.PageCursor{Timestamp: req.Since, ID: strings.Repeat("f", 32)}
	}
	results, _ := m.store.QueryPublicTopicPrefix(req.Topic, limit+1, after)
	hasMore := len(results) > limit
	if hasMore {
		results = results[:limit]
	}
	var nextCursor *envelope.PageCursor
	if hasMore && len(results) > 0 {
		cursor := envelope.CursorFor(results[len(results)-1])
		nextCursor = &cursor
	}

	resp, err := Encode(MsgDataResponse, DataResponsePayload{
		Topic:      req.Topic,
		Envelopes:  results,
		HasMore:    hasMore,
		NextCursor: nextCursor,
	})
	if err != nil {
		return err
	}

	if peer, ok := m.admittedPeer(senderPKHex); ok {
		return peer.peer.ToPeer(context.Background(), resp, senderPK, 5000)
	}
	return nil
}

// onDataResponse handles catch-up response. Stores locally without re-gossiping
// and follows the last valid envelope's compound cursor when more data exists.
func (m *Manager) onDataResponse(senderPKHex string, senderPK *ec.PublicKey, raw json.RawMessage) error {
	var resp DataResponsePayload
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil
	}

	var lastValid *envelope.Envelope
	for _, env := range resp.Envelopes {
		if err := env.Validate(); err != nil {
			continue
		}
		m.observePeerAdvert(env)
		lastValid = env
		if m.store != nil {
			_ = m.store.Ingest(env)
		}
	}

	// Follow up if the responder has more data and we haven't exceeded the
	// catch-up round limit (5 rounds = max 500 envelopes per topic per peer).
	if resp.HasMore && lastValid != nil {
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

			cursorValue := envelope.CursorFor(lastValid)
			payload, err := Encode(MsgDataRequest, DataRequestPayload{
				Topic:  resp.Topic,
				Since:  cursorValue.Timestamp,
				Limit:  100,
				Cursor: &cursorValue,
			})
			if err == nil {
				if peer, ok := m.admittedPeer(senderPKHex); ok {
					_ = peer.peer.ToPeer(context.Background(), payload, senderPK, 5000)
				}
			}
		} else {
			// The peer still has more to send, but this peer+topic has already
			// used its maxCatchUpRounds budget — the catch-up stops here.
			m.IncrCatchupTruncated()
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
	peers := make([]admittedSendPeer, 0, len(m.peers))
	for pkHex, peer := range m.peers {
		if pkHex == senderPK {
			continue
		}
		if !admittedPrimaryLocked(pkHex, peer) {
			continue
		}
		prefixes := m.interests[pkHex]
		for _, prefix := range prefixes {
			if strings.HasPrefix(topic, prefix) {
				peers = append(peers, admittedSendPeer{
					identity: pkHex, peer: peer.Peer, identityPK: peer.IdentityPK,
				})
				break
			}
		}
	}
	m.mu.RUnlock()
	for _, peer := range peers {
		_ = peer.peer.ToPeer(context.Background(), encoded, peer.identityPK, 5000)
		m.IncrSent()
	}
}
