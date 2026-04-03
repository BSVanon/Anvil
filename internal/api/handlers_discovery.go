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

	topicCounts := s.envelopeStore.Topics()
	latestTimes := s.envelopeStore.LatestByTopic()

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

		// Enrich with metadata if available.
		s.enrichTopicInfo(&info)

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

	topicCounts := s.envelopeStore.Topics()
	count, exists := topicCounts[topic]
	if !exists {
		writeError(w, http.StatusNotFound, "topic not found")
		return
	}

	latestTimes := s.envelopeStore.LatestByTopic()

	info := TopicInfo{
		Topic:       topic,
		Count:       count,
		LastUpdated: latestTimes[topic],
	}

	// Get most recent envelope to extract publisher.
	envs, _ := s.envelopeStore.QueryByTopic(topic, 1)
	if len(envs) > 0 {
		info.Publisher = envs[0].Pubkey

		// Include price from monetization if present.
		if envs[0].Monetization != nil {
			info.Price = envs[0].Monetization.PriceSats
		}
	}

	// Enrich with metadata if available.
	s.enrichTopicInfo(&info)

	// Include demand from gossip manager.
	if s.gossipMgr != nil {
		info.Demand = s.gossipMgr.TopicDemand(topic)
	}

	// Include publisher identity if available.
	var identity json.RawMessage
	if info.Publisher != "" {
		idEnvs, _ := s.envelopeStore.QueryByTopic("identity:"+info.Publisher, 1)
		if len(idEnvs) > 0 {
			identity = json.RawMessage(idEnvs[0].Payload)
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
func (s *Server) enrichTopicInfo(info *TopicInfo) {
	metaEnvs, _ := s.envelopeStore.QueryByTopic("meta:"+info.Topic, 1)
	if len(metaEnvs) > 0 {
		info.Metadata = json.RawMessage(metaEnvs[0].Payload)
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

	envs, _ := s.envelopeStore.QueryByTopic("identity:"+pubkey, 1)
	if len(envs) == 0 {
		writeError(w, http.StatusNotFound, "no identity published for this pubkey")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"pubkey":   pubkey,
		"identity": json.RawMessage(envs[0].Payload),
	})
}
