package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func TestMeshNodesEndpoint(t *testing.T) {
	srv := testServer(t)

	req := httptest.NewRequest("GET", "/mesh/nodes", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result struct {
		Nodes []MeshNode `json:"nodes"`
		Count int        `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// With no gossip manager or overlay, should still return self
	if result.Count < 1 {
		t.Fatalf("expected at least 1 node (self), got %d", result.Count)
	}

	self := result.Nodes[0]
	if !self.Evidence.Self {
		t.Error("first node should have evidence.self = true")
	}
	if self.Name == "" {
		t.Error("self node should have a name")
	}
	if self.Version == "" {
		t.Error("self node should have a version")
	}
	if self.LastSeen == "" {
		t.Error("self node should have last_seen")
	}

	// CORS header must be set
	if cors := w.Header().Get("Access-Control-Allow-Origin"); cors != "*" {
		t.Errorf("expected CORS *, got %q", cors)
	}
}

func TestMeshNodesIncludesHeartbeatPeers(t *testing.T) {
	srv := testServer(t)

	// Inject a heartbeat envelope from a "peer" node
	peerKey, _ := ec.NewPrivateKey()
	hbPayload := `{"node":"test-peer","version":"0.5.3","height":100,"peers":1,"topics":["test"],"ts":1234}`
	env := &envelope.Envelope{
		Type:      "data",
		Topic:     "mesh:heartbeat",
		Payload:   hbPayload,
		TTL:       300,
		Timestamp: time.Now().Unix(),
	}
	env.Sign(peerKey)
	srv.envelopeStore.StoreEphemeralDirect(env)

	req := httptest.NewRequest("GET", "/mesh/nodes", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	var result struct {
		Nodes []MeshNode `json:"nodes"`
		Count int        `json:"count"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)

	if result.Count < 2 {
		t.Fatalf("expected at least 2 nodes (self + heartbeat peer), got %d", result.Count)
	}

	// Find the heartbeat peer
	var peer *MeshNode
	for i := range result.Nodes {
		if result.Nodes[i].Name == "test-peer" {
			peer = &result.Nodes[i]
			break
		}
	}
	if peer == nil {
		t.Fatal("heartbeat peer 'test-peer' not found in node list")
	}
	if !peer.Evidence.Heartbeat {
		t.Error("peer should have evidence.heartbeat = true")
	}
	if peer.Evidence.Self {
		t.Error("peer should NOT have evidence.self = true")
	}
	if peer.Version != "0.5.3" {
		t.Errorf("expected version 0.5.3, got %s", peer.Version)
	}
	if peer.Height != 100 {
		t.Errorf("expected height 100, got %d", peer.Height)
	}
}

func TestMeshNodesSortOrder(t *testing.T) {
	srv := testServer(t)

	// Inject two heartbeat peers
	for _, name := range []string{"z-node", "a-node"} {
		key, _ := ec.NewPrivateKey()
		env := &envelope.Envelope{
			Type:      "data",
			Topic:     "mesh:heartbeat",
			Payload:   `{"node":"` + name + `","version":"0.5.3","height":100,"peers":0}`,
			TTL:       300,
			Timestamp: time.Now().Unix(),
		}
		env.Sign(key)
		srv.envelopeStore.StoreEphemeralDirect(env)
	}

	req := httptest.NewRequest("GET", "/mesh/nodes", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	var result struct {
		Nodes []MeshNode `json:"nodes"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)

	if len(result.Nodes) < 3 {
		t.Fatalf("expected at least 3 nodes, got %d", len(result.Nodes))
	}

	// Self should be first
	if !result.Nodes[0].Evidence.Self {
		t.Error("first node should be self")
	}

	// Heartbeat peers should be sorted alphabetically after self
	if result.Nodes[1].Name != "a-node" {
		t.Errorf("expected 'a-node' second, got %q", result.Nodes[1].Name)
	}
	if result.Nodes[2].Name != "z-node" {
		t.Errorf("expected 'z-node' third, got %q", result.Nodes[2].Name)
	}
}
