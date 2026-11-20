package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// --- Public node-info routes (no discovery/identity endpoint, no x402
// payment involved) never name a private topic or count it into a total
// that lets a caller recover it by subtraction ---
//
// GET /mesh/status, GET /stats, GET /mesh/nodes, GET /.well-known/anvil
// and GET /app/{name} all carry no payment gate at all; several carry no
// auth layer at all either. See private_discovery_test.go for the
// discovery/identity routes (GET /topics, GET /identity/{pubkey}) and the
// x402-specific coverage.

// TestPrivateTopicAbsentFromMeshStatus: GET /mesh/status (no auth layer
// at all, cached via topicCache) never names a private topic — not even to
// the operator, since this route has no authenticated view at all.
func TestPrivateTopicAbsentFromMeshStatus(t *testing.T) {
	srv := testServer(t)
	storePrivate(t, srv, `{"secret":"do-not-leak"}`)
	storePublicTopic(t, srv, "oracle:rates:bsv")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/mesh/status", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "lacriada:household-x") {
		t.Fatalf("GET /mesh/status must not name a private topic: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "oracle:rates:bsv") {
		t.Fatalf("a public topic should still appear in GET /mesh/status: %s", w.Body.String())
	}

	// Even the operator's own bearer token sees no more — this route has no
	// authenticated view at all.
	req := httptest.NewRequest("GET", "/mesh/status", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	wOp := httptest.NewRecorder()
	srv.Handler().ServeHTTP(wOp, req)
	if strings.Contains(wOp.Body.String(), "lacriada:household-x") {
		t.Fatalf("GET /mesh/status must not name a private topic even for the operator (no authenticated view on this route): %s", wOp.Body.String())
	}
}

// TestPrivateTopicAbsentFromStats: GET /stats never names a private
// topic to an anonymous caller or a payer; the operator still sees the full
// aggregate (handlers_status.go).
func TestPrivateTopicAbsentFromStats(t *testing.T) {
	free := testServer(t)
	storePrivate(t, free, `{"secret":"do-not-leak"}`)
	storePublicTopic(t, free, "oracle:rates:bsv")

	wAnon := httptest.NewRecorder()
	free.Handler().ServeHTTP(wAnon, httptest.NewRequest("GET", "/stats", nil))
	if strings.Contains(wAnon.Body.String(), "lacriada:household-x") {
		t.Fatalf("an anonymous caller must not see a private topic via GET /stats: %s", wAnon.Body.String())
	}

	charging := testServerWithPaymentGate(t, 100)
	storePrivate(t, charging, `{"secret":"do-not-leak"}`)
	storePublicTopic(t, charging, "oracle:rates:bsv")

	payer := payerGet(t, charging, "/stats")
	if strings.Contains(payer.Body.String(), "lacriada:household-x") {
		t.Fatalf("a payer must not see a private topic via GET /stats: %s", payer.Body.String())
	}
	if !strings.Contains(payer.Body.String(), "oracle:rates:bsv") {
		t.Fatalf("a public topic should still appear in GET /stats: %s", payer.Body.String())
	}

	req := httptest.NewRequest("GET", "/stats", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	wOp := httptest.NewRecorder()
	charging.Handler().ServeHTTP(wOp, req)
	if !strings.Contains(wOp.Body.String(), "lacriada:household-x") {
		t.Fatalf("the operator should see the private topic via GET /stats: %s", wOp.Body.String())
	}
}

// TestStatsEnvelopeTotalsExcludePrivateFromSubtraction: GET /stats's
// envelopes.ephemeral and envelopes.durable TOTALS, not just the topics
// map, must use the same public-only filter. An unfiltered total next to a
// public-only topic map lets a caller recover the private count by
// subtraction (total minus the sum shown in topics) — just as much a leak
// as naming the private topic directly. The operator still sees the full,
// unfiltered totals. Covers both storage classes: ephemeral (in-memory)
// and durable (LevelDB).
func TestStatsEnvelopeTotalsExcludePrivateFromSubtraction(t *testing.T) {
	srv := testServer(t)
	storePrivate(t, srv, `{"secret":"do-not-leak"}`)          // ephemeral, private
	storePublicTopic(t, srv, "oracle:rates:bsv")              // ephemeral, public
	seedEnvelope(t, srv.envelopeStore, "durable:public", nil) // durable, public

	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	durablePrivate := &envelope.Envelope{
		Type: "data", Topic: "durable:private", Payload: `{"secret":"durable-do-not-leak"}`,
		TTL: 0, Durable: true, Timestamp: time.Now().Unix(), Private: true,
	}
	durablePrivate.Sign(key)
	if err := srv.envelopeStore.Ingest(durablePrivate); err != nil {
		t.Fatalf("seed durable private envelope: %v", err)
	}

	type statsResp struct {
		Envelopes struct {
			Ephemeral int `json:"ephemeral"`
			Durable   int `json:"durable"`
		} `json:"envelopes"`
	}

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/stats", nil))
	var anon statsResp
	if err := json.Unmarshal(w.Body.Bytes(), &anon); err != nil {
		t.Fatalf("decode: %v: %s", err, w.Body.String())
	}
	if anon.Envelopes.Ephemeral != 1 {
		t.Fatalf("an anonymous caller's ephemeral total must count only the public envelope (not subtraction-revealing), got %d", anon.Envelopes.Ephemeral)
	}
	if anon.Envelopes.Durable != 1 {
		t.Fatalf("an anonymous caller's durable total must count only the public envelope (not subtraction-revealing), got %d", anon.Envelopes.Durable)
	}

	req2 := httptest.NewRequest("GET", "/stats", nil)
	req2.Header.Set("Authorization", "Bearer test-token")
	wOp2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(wOp2, req2)
	var op statsResp
	if err := json.Unmarshal(wOp2.Body.Bytes(), &op); err != nil {
		t.Fatalf("decode: %v: %s", err, wOp2.Body.String())
	}
	if op.Envelopes.Ephemeral != 2 {
		t.Fatalf("the operator's ephemeral total should count both envelopes, got %d", op.Envelopes.Ephemeral)
	}
	if op.Envelopes.Durable != 2 {
		t.Fatalf("the operator's durable total should count both envelopes, got %d", op.Envelopes.Durable)
	}
}

// TestPrivateTopicAbsentFromMeshNodes: GET /mesh/nodes (no auth layer
// at all) never names a private topic in this node's own self-entry.
func TestPrivateTopicAbsentFromMeshNodes(t *testing.T) {
	srv := testServer(t)
	storePrivate(t, srv, `{"secret":"do-not-leak"}`)
	storePublicTopic(t, srv, "oracle:rates:bsv")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/mesh/nodes", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "lacriada:household-x") {
		t.Fatalf("GET /mesh/nodes must not name a private topic: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "oracle:rates:bsv") {
		t.Fatalf("a public topic should still appear in GET /mesh/nodes: %s", w.Body.String())
	}
}

// TestPrivateTopicAbsentFromAnvilManifest: GET /.well-known/anvil (no
// auth layer at all — any crawler can fetch it) never names a private topic
// as a capability.
func TestPrivateTopicAbsentFromAnvilManifest(t *testing.T) {
	srv := testServer(t)
	storePrivate(t, srv, `{"secret":"do-not-leak"}`)
	storePublicTopic(t, srv, "oracle:rates:bsv")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/.well-known/anvil", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "lacriada:household-x") {
		t.Fatalf("GET /.well-known/anvil must not advertise a private topic: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "oracle:rates:bsv") {
		t.Fatalf("a public topic should still be advertised in GET /.well-known/anvil: %s", w.Body.String())
	}
}
