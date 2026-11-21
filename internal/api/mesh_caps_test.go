package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

type meshStatusTopicsResponse struct {
	Topics []struct {
		Topic    string `json:"topic"`
		Count    int    `json:"count"`
		LatestAt string `json:"latest_at"`
	} `json:"topics"`
	TopicsTotal     int  `json:"topics_total"`
	TopicsTruncated bool `json:"topics_truncated"`
}

const meshCapsTestPubkey = "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66"

type meshNodesCapsResponse struct {
	Nodes     []MeshNode `json:"nodes"`
	Count     int        `json:"count"`
	Total     int        `json:"total"`
	Truncated bool       `json:"truncated"`
}

func getMeshStatusTopics(t *testing.T, srv *Server) meshStatusTopicsResponse {
	t.Helper()
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/mesh/status", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var response meshStatusTopicsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	return response
}

func TestMeshStatusTopicCapAndOrder(t *testing.T) {
	srv := testServer(t)
	base := time.Now().Unix()
	for i := 0; i <= maxMeshStatusTopics; i++ {
		srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{
			Type: "data", Topic: fmt.Sprintf("status:%04d", i), Payload: "{}",
			Pubkey: meshCapsTestPubkey, Timestamp: base + int64(i),
		})
	}

	response := getMeshStatusTopics(t, srv)
	if len(response.Topics) != 1000 {
		t.Fatalf("topics length = %d, want 1000", len(response.Topics))
	}
	if response.TopicsTotal != 1001 || !response.TopicsTruncated {
		t.Fatalf("total/truncated = %d/%t, want 1001/true", response.TopicsTotal, response.TopicsTruncated)
	}
	if response.Topics[0].Topic != "status:1000" || response.Topics[len(response.Topics)-1].Topic != "status:0001" {
		t.Fatalf("topic order = %q ... %q, want newest first", response.Topics[0].Topic, response.Topics[len(response.Topics)-1].Topic)
	}
}

func TestMeshStatusTopicsUnderCap(t *testing.T) {
	srv := testServer(t)
	for _, topic := range []string{"status:z", "status:a"} {
		srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{Type: "data", Topic: topic, Payload: "{}", Pubkey: meshCapsTestPubkey, Timestamp: 100})
	}

	response := getMeshStatusTopics(t, srv)
	if len(response.Topics) != 2 || response.TopicsTotal != 2 || response.TopicsTruncated {
		t.Fatalf("topics/total/truncated = %d/%d/%t, want 2/2/false", len(response.Topics), response.TopicsTotal, response.TopicsTruncated)
	}
	if response.Topics[0].Topic != "status:a" || response.Topics[1].Topic != "status:z" {
		t.Fatalf("same-time topics = %q, %q; want name order", response.Topics[0].Topic, response.Topics[1].Topic)
	}
}

func TestMeshNodesCapsKeepOrder(t *testing.T) {
	srv := testServerWithOverlay(t)
	for i := 0; i <= maxMeshNodes; i++ {
		if err := srv.overlayDir.AddSHIPPeerFromGossip(
			fmt.Sprintf("identity-%03d", i), fmt.Sprintf("node-%03d.example", i),
			fmt.Sprintf("node-%03d", i), "test", "mesh:caps"); err != nil {
			t.Fatalf("add node %d: %v", i, err)
		}
	}

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/mesh/nodes", nil))
	var response meshNodesCapsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode nodes: %v", err)
	}
	if response.Count != 500 || response.Total != 502 || !response.Truncated {
		t.Fatalf("count/total/truncated = %d/%d/%t, want 500/502/true", response.Count, response.Total, response.Truncated)
	}
	if !response.Nodes[0].Evidence.Self || response.Nodes[1].Name != "node-000" || response.Nodes[len(response.Nodes)-1].Name != "node-498" {
		t.Fatalf("capped node order did not retain the sorted prefix")
	}
}

func TestMeshNodesTopicCaps(t *testing.T) {
	srv := testServer(t)
	for i := 0; i <= maxMeshNodeTopics; i++ {
		srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{Type: "data", Topic: fmt.Sprintf("self:%03d", i), Payload: "{}", Pubkey: meshCapsTestPubkey})
	}
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	topics := make([]string, 0, maxMeshNodeTopics+1)
	for i := maxMeshNodeTopics; i >= 0; i-- {
		topics = append(topics, fmt.Sprintf("heartbeat:%03d", i))
	}
	payload, err := json.Marshal(map[string]interface{}{"node": "peer", "topics": topics})
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := &envelope.Envelope{Type: "data", Topic: "mesh:heartbeat", Payload: string(payload), TTL: 300, Timestamp: time.Now().Unix()}
	heartbeat.Sign(key)
	srv.envelopeStore.StoreEphemeralDirect(heartbeat)

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/mesh/nodes", nil))
	var response meshNodesCapsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode nodes: %v", err)
	}
	self := response.Nodes[0]
	if len(self.Topics) != 100 || self.TopicsTotal != 102 || self.Topics[0] != "mesh:heartbeat" || self.Topics[1] != "self:000" || self.Topics[len(self.Topics)-1] != "self:098" {
		t.Fatalf("self topic cap or order is wrong")
	}
	var peer *MeshNode
	for i := range response.Nodes {
		if response.Nodes[i].Name == "peer" {
			peer = &response.Nodes[i]
			break
		}
	}
	if peer == nil || len(peer.Topics) != 100 || peer.TopicsTotal != 101 || peer.Topics[0] != "heartbeat:100" || peer.Topics[len(peer.Topics)-1] != "heartbeat:001" {
		t.Fatalf("heartbeat topic cap did not preserve the supplied prefix")
	}
}

func TestMeshPublicMixedTopic(t *testing.T) {
	srv := testServer(t)
	const publicTime = int64(1700000000)
	srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{Type: "data", Topic: "mixed:topic", Payload: "public", Pubkey: meshCapsTestPubkey, Timestamp: publicTime})
	srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{Type: "data", Topic: "mixed:topic", Payload: "private", Pubkey: meshCapsTestPubkey, Timestamp: publicTime + 100, Private: true})

	status := getMeshStatusTopics(t, srv)
	if status.TopicsTotal != 1 || len(status.Topics) != 1 || status.Topics[0].Count != 1 || status.Topics[0].LatestAt != time.Unix(publicTime, 0).UTC().Format(time.RFC3339) {
		t.Fatalf("mixed topic status did not use only the public envelope: %+v", status)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/mesh/nodes", nil))
	var nodes meshNodesCapsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &nodes); err != nil {
		t.Fatalf("decode nodes: %v", err)
	}
	if len(nodes.Nodes) == 0 || len(nodes.Nodes[0].Topics) != 1 || nodes.Nodes[0].Topics[0] != "mixed:topic" {
		t.Fatalf("mixed public topic missing from self node: %+v", nodes.Nodes)
	}
}

func TestMeshStatusRateLimited(t *testing.T) {
	srv := testServer(t)
	srv.rateLimiter = NewRateLimiter(1, false)
	srv.mux = http.NewServeMux()
	srv.routes()
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodGet, "/mesh/status", nil)
		req.RemoteAddr = "5.5.5.5:9999"
		srv.Handler().ServeHTTP(httptest.NewRecorder(), req)
	}
	req := httptest.NewRequest(http.MethodGet, "/mesh/status", nil)
	req.RemoteAddr = "5.5.5.5:9999"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}
}
