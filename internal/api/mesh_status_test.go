package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BSVanon/Anvil/internal/envelope"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func TestMeshStatusEndpoint(t *testing.T) {
	srv := testServer(t)

	req := httptest.NewRequest("GET", "/mesh/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Must have node, version, headers
	if _, ok := result["node"]; !ok {
		t.Error("missing 'node' field")
	}
	if _, ok := result["version"]; !ok {
		t.Error("missing 'version' field")
	}
	if _, ok := result["headers"]; !ok {
		t.Error("missing 'headers' field")
	}

	// Topics should be present (empty list is fine — envelope store exists)
	if _, ok := result["topics"]; !ok {
		t.Error("missing 'topics' field")
	}

	// CORS header must be set (public endpoint)
	if cors := w.Header().Get("Access-Control-Allow-Origin"); cors != "*" {
		t.Errorf("expected CORS *, got %q", cors)
	}
}

func TestMeshStatusWithEnvelopes(t *testing.T) {
	srv := testServer(t)

	// Inject a signed test envelope into the store
	key, _ := ec.NewPrivateKey()
	env := &envelope.Envelope{
		Type:      "data",
		Topic:     "test:status",
		Payload:   "hello",
		TTL:       300,
		Timestamp: 1711600000,
	}
	env.Sign(key)
	srv.envelopeStore.StoreEphemeralDirect(env)

	req := httptest.NewRequest("GET", "/mesh/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)

	topics, ok := result["topics"].([]interface{})
	if !ok {
		t.Fatal("topics not an array")
	}
	if len(topics) == 0 {
		t.Fatal("expected at least 1 topic")
	}

	found := false
	for _, ti := range topics {
		m := ti.(map[string]interface{})
		if m["topic"] == "test:status" {
			found = true
			if m["count"].(float64) != 1 {
				t.Errorf("expected count=1, got %v", m["count"])
			}
		}
	}
	if !found {
		t.Error("test:status topic not found in response")
	}
}
