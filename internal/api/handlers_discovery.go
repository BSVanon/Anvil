package api

import (
	"encoding/json"
	"net/http"
	"strings"
)

// TopicInfo is the response for GET /topics/{topic} — everything a developer
// or agent needs to understand and use a topic.
type TopicInfo struct {
	Topic       string          `json:"topic"`
	Count       int             `json:"count"`                  // total envelopes
	LastUpdated int64           `json:"last_updated,omitempty"` // newest envelope timestamp
	Metadata    json.RawMessage `json:"metadata,omitempty"`     // from meta:<topic> envelope
	Publisher   string          `json:"publisher,omitempty"`    // pubkey of most recent envelope
	Price       int             `json:"price,omitempty"`        // sats, from monetization or node default
	Demand      int             `json:"demand,omitempty"`       // subscriber + query count (from heartbeat demand map)
}

// handleListTopics handles GET /topics — list all known topics with summary info.
func (s *Server) handleListTopics(w http.ResponseWriter, r *http.Request) {
	if s.envelopeStore == nil {
		writeError(w, http.StatusServiceUnavailable, "envelope store not configured")
		return
	}

	// Unauthenticated callers get PUBLIC-only summaries — private envelopes
	// contribute no count/timestamp and wholly-private topics don't appear, so
	// no private-history metadata leaks even for a topic whose latest envelope
	// is public. Authenticated callers see the full aggregate.
	isAuthed := s.isAuthed(r)
	var topicCounts map[string]int
	var latestTimes map[string]int64
	if isAuthed {
		topicCounts = s.envelopeStore.Topics()
		latestTimes = s.envelopeStore.LatestByTopic()
	} else {
		topicCounts, latestTimes = s.envelopeStore.PublicTopicSummary()
	}

	var topics []TopicInfo
	for topic, count := range topicCounts {
		// Skip internal meta: and identity: topics from the listing —
		// they're metadata, not data topics.
		if strings.HasPrefix(topic, "meta:") || strings.HasPrefix(topic, "identity:") {
			continue
		}

		info := TopicInfo{
			Topic:       topic,
			Count:       count,
			LastUpdated: latestTimes[topic],
		}

		// Enrich with metadata if available (private meta: hidden from unauthed).
		s.enrichTopicInfo(&info, isAuthed)

		topics = append(topics, info)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"topics": topics,
		"count":  len(topics),
	})
}

// handleGetTopic handles GET /topics/{topic} — detailed info about a single topic.
func (s *Server) handleGetTopic(w http.ResponseWriter, r *http.Request) {
	if s.envelopeStore == nil {
		writeError(w, http.StatusServiceUnavailable, "envelope store not configured")
		return
	}

	topic := r.PathValue("topic")
	if topic == "" {
		writeError(w, http.StatusBadRequest, "topic required")
		return
	}

	isAuthed := s.isAuthed(r)

	// Gather the topic's envelopes once (newest-first). For unauthenticated
	// callers, count/last_updated/publisher come from PUBLIC envelopes ONLY, so
	// private history never leaks via count/timestamp/publisher — and a topic
	// with no public envelopes is indistinguishable from a nonexistent one
	// (404). Authenticated callers see the full aggregate.
	envs, _ := s.envelopeStore.QueryByTopic(topic, 0)

	count := 0
	var lastUpdated int64
	latestIdx := -1
	for i, e := range envs {
		if !isAuthed && e.Private {
			continue
		}
		count++
		if e.Timestamp > lastUpdated {
			lastUpdated = e.Timestamp
		}
		if latestIdx == -1 {
			latestIdx = i // newest-first: first visible envelope is the latest
		}
	}
	if count == 0 {
		writeError(w, http.StatusNotFound, "topic not found")
		return
	}

	info := TopicInfo{
		Topic:       topic,
		Count:       count,
		LastUpdated: lastUpdated,
	}

	if latestIdx >= 0 {
		info.Publisher = envs[latestIdx].Pubkey

		// Include price from monetization if present.
		if envs[latestIdx].Monetization != nil {
			info.Price = envs[latestIdx].Monetization.PriceSats
		}
	}

	// Enrich with metadata if available (private meta: hidden from unauthed).
	s.enrichTopicInfo(&info, isAuthed)

	// Include demand from gossip manager.
	if s.gossipMgr != nil {
		info.Demand = s.gossipMgr.TopicDemand(topic)
	}

	// Include publisher identity if available (private identity: hidden from unauthed).
	var identity json.RawMessage
	if info.Publisher != "" {
		if idEnv := s.latestVisibleEnvelope("identity:"+info.Publisher, isAuthed); idEnv != nil {
			raw := json.RawMessage(idEnv.Payload)
			if json.Valid(raw) {
				identity = raw
			}
		}
	}

	result := map[string]interface{}{
		"topic": info,
	}
	if identity != nil {
		result["publisher_identity"] = identity
	}

	writeJSON(w, http.StatusOK, result)
}

// enrichTopicInfo fills metadata from the meta:<topic> envelope if it exists.
// For unauthenticated callers a private meta: envelope is skipped so it can't
// leak (the payload is private data on a meta: topic).
func (s *Server) enrichTopicInfo(info *TopicInfo, isAuthed bool) {
	if env := s.latestVisibleEnvelope("meta:"+info.Topic, isAuthed); env != nil {
		raw := json.RawMessage(env.Payload)
		if json.Valid(raw) {
			info.Metadata = raw
		}
	}
}

// handleGetIdentity handles GET /identity/{pubkey} — returns the identity
// envelope for a publisher if one exists.
func (s *Server) handleGetIdentity(w http.ResponseWriter, r *http.Request) {
	if s.envelopeStore == nil {
		writeError(w, http.StatusServiceUnavailable, "envelope store not configured")
		return
	}

	pubkey := r.PathValue("pubkey")
	if pubkey == "" || len(pubkey) != 66 {
		writeError(w, http.StatusBadRequest, "pubkey must be 66-char compressed hex")
		return
	}

	// A private identity: envelope is hidden from unauthenticated callers
	// (returns the same 404 as no identity).
	env := s.latestVisibleEnvelope("identity:"+pubkey, s.isAuthed(r))
	if env == nil {
		writeError(w, http.StatusNotFound, "no identity published for this pubkey")
		return
	}

	raw := json.RawMessage(env.Payload)
	if !json.Valid(raw) {
		writeError(w, http.StatusInternalServerError, "identity payload is not valid JSON")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"pubkey":   pubkey,
		"identity": raw,
	})
}
