package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/BSVanon/Anvil/internal/version"
)

// MeshNode represents a single node in the merged read-model.
// Evidence flags preserve the source of each piece of data.
type MeshNode struct {
	Identity string        `json:"identity"`
	Name     string        `json:"name"`
	Version  string        `json:"version"`
	URL      string        `json:"url"`
	Height   uint32        `json:"height,omitempty"`
	Peers    int           `json:"peers,omitempty"`
	Topics   []string      `json:"topics,omitempty"`
	LastSeen string        `json:"last_seen"`
	Evidence MeshEvidence  `json:"evidence"`
}

// MeshEvidence records which data sources contributed to this node entry.
type MeshEvidence struct {
	Self            bool `json:"self"`
	DirectPeer      bool `json:"direct_peer"`
	Heartbeat       bool `json:"heartbeat"`
	Overlay         bool `json:"overlay"`
	HeartbeatAgeSec *int `json:"heartbeat_age_secs,omitempty"`
	ConnectedSec    *int `json:"connected_secs,omitempty"`
}

// handleMeshNodes serves GET /mesh/nodes — the authoritative merged node list.
//
// Merges three canonical sources:
//   - Overlay directory: identity → URL registration (address book)
//   - Heartbeat envelopes: recent liveness and status
//   - Gossip peer_list: direct adjacency (WebSocket connections)
//
// Each node carries its evidence flags so the client can make rendering
// and switchability decisions without guessing.
func (s *Server) handleMeshNodes(w http.ResponseWriter, r *http.Request) {
	now := time.Now()

	// Keyed by identity pubkey
	type builder struct {
		node MeshNode
	}
	nodes := make(map[string]*builder)

	// 1. Self — always present
	selfNode := &builder{
		node: MeshNode{
			Identity: s.identityPub,
			Name:     s.nodeName,
			Version:  version.Version,
			URL:      s.publicURL,
			Height:   s.headerStore.Tip(),
			LastSeen: now.UTC().Format(time.RFC3339),
			Evidence: MeshEvidence{Self: true},
		},
	}
	if s.envelopeStore != nil {
		topics := s.envelopeStore.Topics()
		names := make([]string, 0, len(topics))
		for t := range topics {
			names = append(names, t)
		}
		selfNode.node.Topics = names
	}
	if s.gossipMgr != nil {
		selfNode.node.Peers = s.gossipMgr.PeerCount()
	}
	nodes[s.identityPub] = selfNode

	// 2. Direct peers from gossip manager
	if s.gossipMgr != nil {
		for _, p := range s.gossipMgr.PeerList() {
			if p.Identity == "" || p.Identity == s.identityPub {
				continue
			}
			b, ok := nodes[p.Identity]
			if !ok {
				b = &builder{node: MeshNode{Identity: p.Identity}}
				nodes[p.Identity] = b
			}
			b.node.Evidence.DirectPeer = true
			if p.Version != "" {
				b.node.Version = p.Version
			}
			if p.ConnectedAt != "" {
				if ct, err := time.Parse(time.RFC3339, p.ConnectedAt); err == nil {
					secs := int(now.Sub(ct).Seconds())
					b.node.Evidence.ConnectedSec = &secs
					// Use connection time as last_seen if nothing better
					if b.node.LastSeen == "" {
						b.node.LastSeen = p.ConnectedAt
					}
				}
			}
		}
	}

	// 3. Heartbeat envelopes — canonical for liveness
	if s.envelopeStore != nil {
		envs, err := s.envelopeStore.QueryByTopic("mesh:heartbeat", 100)
		if err == nil {
			// Dedup: keep newest heartbeat per pubkey
			seen := make(map[string]bool)
			for _, env := range envs {
				if seen[env.Pubkey] {
					continue
				}
				seen[env.Pubkey] = true

				if env.Pubkey == s.identityPub {
					continue // self already handled
				}

				var hb struct {
					Node    string   `json:"node"`
					Version string   `json:"version"`
					Height  uint32   `json:"height"`
					Peers   int      `json:"peers"`
					Topics  []string `json:"topics"`
				}
				if err := json.Unmarshal([]byte(env.Payload), &hb); err != nil {
					continue
				}

				b, ok := nodes[env.Pubkey]
				if !ok {
					b = &builder{node: MeshNode{Identity: env.Pubkey}}
					nodes[env.Pubkey] = b
				}
				b.node.Evidence.Heartbeat = true

				// Heartbeat is canonical for these fields
				if hb.Node != "" {
					b.node.Name = hb.Node
				}
				if hb.Version != "" {
					b.node.Version = hb.Version
				}
				b.node.Height = hb.Height
				b.node.Peers = hb.Peers
				if len(hb.Topics) > 0 {
					b.node.Topics = hb.Topics
				}

				// last_seen from local ReceivedAt (not remote clock)
				ageSecs := int(now.Sub(env.ReceivedAt).Seconds())
				b.node.Evidence.HeartbeatAgeSec = &ageSecs
				receivedStr := env.ReceivedAt.UTC().Format(time.RFC3339)
				b.node.LastSeen = receivedStr
			}
		}
	}

	// 4. Overlay directory — canonical for URL/domain registration
	if s.overlayDir != nil {
		s.overlayDir.ForEachSHIP(func(identity, domain, nodeName, ver, topic string) bool {
			if identity == s.identityPub {
				return true // self already handled
			}
			b, ok := nodes[identity]
			if !ok {
				b = &builder{node: MeshNode{Identity: identity}}
				nodes[identity] = b
			}
			b.node.Evidence.Overlay = true
			// Overlay is canonical for URL
			if domain != "" {
				b.node.URL = domain
			}
			// Overlay name/version only used as fallback
			if b.node.Name == "" && nodeName != "" {
				b.node.Name = nodeName
			}
			if b.node.Version == "" && ver != "" {
				b.node.Version = ver
			}
			return true
		})
	}

	// Build sorted result: self first, then direct peers, then observed, then registered-only
	result := make([]MeshNode, 0, len(nodes))
	for _, b := range nodes {
		// Default name to truncated identity if nothing better
		if b.node.Name == "" && len(b.node.Identity) > 16 {
			b.node.Name = b.node.Identity[:16] + "..."
		}
		result = append(result, b.node)
	}

	sort.Slice(result, func(i, j int) bool {
		ri, rj := sortRank(result[i].Evidence), sortRank(result[j].Evidence)
		if ri != rj {
			return ri < rj
		}
		return result[i].Name < result[j].Name
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"nodes": result,
		"count": len(result),
	})
}

// sortRank returns a sort priority: self=0, direct=1, heartbeat=2, overlay-only=3
func sortRank(e MeshEvidence) int {
	if e.Self {
		return 0
	}
	if e.DirectPeer {
		return 1
	}
	if e.Heartbeat {
		return 2
	}
	return 3
}
