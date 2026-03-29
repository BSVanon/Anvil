package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/BSVanon/Anvil/internal/version"
)

// topicCache caches the expensive envelope store aggregation for /mesh/status.
// Public endpoint + full LevelDB scan = DoS vector without caching.
type topicCache struct {
	mu      sync.Mutex
	counts  map[string]int
	latest  map[string]int64
	updated time.Time
	ttl     time.Duration
}

func newTopicCache(ttl time.Duration) *topicCache {
	return &topicCache{ttl: ttl}
}

func (tc *topicCache) get(countsFn func() map[string]int, latestFn func() map[string]int64) (map[string]int, map[string]int64) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if time.Since(tc.updated) < tc.ttl {
		return tc.counts, tc.latest
	}
	tc.counts = countsFn()
	tc.latest = latestFn()
	tc.updated = time.Now()
	return tc.counts, tc.latest
}

// handleMeshStatus serves GET /mesh/status — a rich, public endpoint showing
// live mesh activity. Designed to make a new node operator immediately see
// that their node is alive, connected, and relaying data.
func (s *Server) handleMeshStatus(w http.ResponseWriter, r *http.Request) {
	tip := s.headerStore.Tip()
	work := s.headerStore.Work()

	result := map[string]interface{}{
		"node":    s.nodeName,
		"version": version.Version,
		"headers": map[string]interface{}{
			"height": tip,
			"work":   work.String(),
		},
	}

	if s.identityPub != "" {
		result["identity"] = s.identityPub
	}

	// Mesh peers with connection details
	if s.gossipMgr != nil {
		peers := s.gossipMgr.PeerList()
		activity := s.gossipMgr.Activity()

		result["mesh"] = map[string]interface{}{
			"peers":       len(peers),
			"peer_list":   peers,
			"started_at":  activity.StartedAt,
			"uptime_secs": activity.UptimeSecs,
		}
		if recent := s.gossipMgr.RecentConnections(10); len(recent) > 0 {
			result["recent_connections"] = recent
		}
		result["activity"] = map[string]interface{}{
			"envelopes_received": activity.EnvsReceived,
			"envelopes_sent":     activity.EnvsSent,
		}
	}

	// Topics with counts and freshness (cached to avoid LevelDB scan per request)
	if s.envelopeStore != nil {
		counts, latest := s.meshTopicCache.get(
			s.envelopeStore.Topics,
			s.envelopeStore.LatestByTopic,
		)

		type topicInfo struct {
			Topic    string `json:"topic"`
			Count    int    `json:"count"`
			LatestAt string `json:"latest_at,omitempty"`
			AgeSecs  int    `json:"age_secs,omitempty"`
		}

		now := time.Now().Unix()
		topics := make([]topicInfo, 0, len(counts))
		for topic, count := range counts {
			ti := topicInfo{Topic: topic, Count: count}
			if ts, ok := latest[topic]; ok && ts > 0 {
				ti.LatestAt = time.Unix(ts, 0).UTC().Format(time.RFC3339)
				ti.AgeSecs = int(now - ts)
			}
			topics = append(topics, ti)
		}
		result["topics"] = topics
	}

	// Overlay SHIP peers
	if s.overlayDir != nil {
		result["overlay"] = map[string]interface{}{
			"ship_count": s.overlayDir.CountSHIP(),
		}
	}

	writeJSON(w, http.StatusOK, result)
}
