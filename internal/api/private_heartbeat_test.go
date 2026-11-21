package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
)

func TestMeshNodesIgnoresPrivateHeartbeats(t *testing.T) {
	srv := testServer(t)
	const pubkey = "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66"
	now := time.Now()
	srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{
		Type: "data", Topic: "mesh:heartbeat",
		Payload: `{"node":"public-node","topics":["public-topic"]}`,
		Pubkey:  pubkey, Signature: "public", TTL: 60,
		Timestamp: now.Unix() - 1, ReceivedAt: now.Add(-time.Second),
	})
	srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{
		Type: "data", Topic: "mesh:heartbeat",
		Payload: `{"node":"private-node","topics":["private-topic"]}`,
		Pubkey:  pubkey, Signature: "private", TTL: 60,
		Timestamp: now.Unix(), ReceivedAt: now, Private: true,
	})

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/mesh/nodes", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /mesh/nodes = %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, "private-node") || strings.Contains(body, "private-topic") {
		t.Fatalf("private heartbeat reached public response: %s", body)
	}
	if !strings.Contains(body, "public-node") || !strings.Contains(body, "public-topic") {
		t.Fatalf("private heartbeat shadowed public heartbeat: %s", body)
	}
}
