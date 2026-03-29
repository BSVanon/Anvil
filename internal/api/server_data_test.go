package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/gossip"
	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"log/slog"
)

// --- SSE subscription tests ---

func TestSSESubscribeReceivesEnvelope(t *testing.T) {
	srv := testServer(t)
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/data/subscribe?topic=test:sse", nil)
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		srv.Handler().ServeHTTP(w, req)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)

	env := &envelope.Envelope{
		Type:      "data",
		Topic:     "test:sse",
		Payload:   `{"msg":"hello"}`,
		Timestamp: time.Now().Unix(),
	}
	env.Sign(key)
	srv.NotifyEnvelope(env)

	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	body := w.Body.String()
	if !strings.Contains(body, "hello") {
		t.Fatalf("expected SSE stream to contain envelope payload, got: %s", body)
	}
	if !strings.Contains(body, "data: ") {
		t.Fatalf("expected SSE data: prefix, got: %s", body)
	}
	if !strings.Contains(body, "id: ") {
		t.Fatalf("expected SSE id: field, got: %s", body)
	}
}

func TestSSESubscribeRequiresTopic(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/data/subscribe", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing topic, got %d", w.Code)
	}
}

func TestSSERedactsPaidPayloads(t *testing.T) {
	srv := testServer(t)
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	// Start unauthenticated SSE subscription
	req := httptest.NewRequest("GET", "/data/subscribe?topic=test:paid", nil)
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		srv.Handler().ServeHTTP(w, req)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)

	// Send a monetized envelope
	env := &envelope.Envelope{
		Type:      "data",
		Topic:     "test:paid",
		Payload:   `{"secret":"premium-data"}`,
		Timestamp: time.Now().Unix(),
		Monetization: &envelope.Monetization{
			PriceSats: 100,
		},
	}
	env.Sign(key)
	srv.NotifyEnvelope(env)

	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	body := w.Body.String()
	if strings.Contains(body, "premium-data") {
		t.Fatal("paid payload was NOT redacted for unauthenticated SSE subscriber")
	}
	if !strings.Contains(body, "paid content") {
		t.Fatal("expected redaction placeholder in SSE stream")
	}
}

// --- DELETE /data tests ---

func TestDeleteDataCORSPreflight(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("OPTIONS", "/data?topic=anvil:catalog&key=x", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for OPTIONS preflight, got %d", w.Code)
	}
	methods := w.Header().Get("Access-Control-Allow-Methods")
	if !strings.Contains(methods, "DELETE") {
		t.Fatalf("expected DELETE in CORS allow-methods, got %q", methods)
	}
}

func TestDeleteDataRequiresAuth(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("DELETE", "/data?topic=anvil:catalog&key=x", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestDeleteDataRemovesEnvelope(t *testing.T) {
	srv := testServer(t)
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	env := &envelope.Envelope{
		Type:      "data",
		Topic:     "anvil:catalog",
		Payload:   `{"name":"demo"}`,
		TTL:       0,
		Durable:   true,
		Timestamp: 1711600000,
	}
	env.Sign(key)
	if err := srv.envelopeStore.Ingest(env); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("DELETE", "/data?topic=anvil:catalog&key="+env.Key(), nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if srv.envelopeStore.CountDurable() != 0 {
		t.Fatal("expected durable envelope to be deleted")
	}
}

// --- Query with since filter ---

func TestQueryDataSinceFilter(t *testing.T) {
	srv := testServer(t)
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	for i, ts := range []int64{1000, 2000, 3000} {
		env := &envelope.Envelope{
			Type:      "data",
			Topic:     "test:since",
			Payload:   fmt.Sprintf(`{"seq":%d}`, i),
			TTL:       0,
			Durable:   true,
			Timestamp: ts,
		}
		env.Sign(key)
		if err := srv.envelopeStore.Ingest(env); err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest("GET", "/data?topic=test:since&since=1500", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Count     int                      `json:"count"`
		Envelopes []map[string]interface{} `json:"envelopes"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Count != 2 {
		t.Fatalf("expected 2 envelopes with since=1500, got %d", resp.Count)
	}

	req2 := httptest.NewRequest("GET", "/data?topic=test:since", nil)
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)
	var resp2 struct {
		Count int `json:"count"`
	}
	json.NewDecoder(w2.Body).Decode(&resp2)
	if resp2.Count != 3 {
		t.Fatalf("expected 3 envelopes without since, got %d", resp2.Count)
	}
}

// --- Data + gossip integration ---

func testServerWithGossip(t *testing.T) (*Server, *gossip.Manager) {
	t.Helper()

	hdir, _ := os.MkdirTemp("", "anvil-api-headers-*")
	t.Cleanup(func() { os.RemoveAll(hdir) })
	hs, _ := headers.NewTestStore(hdir)
	t.Cleanup(func() { hs.Close() })

	pdir, _ := os.MkdirTemp("", "anvil-api-proofs-*")
	t.Cleanup(func() { os.RemoveAll(pdir) })
	ps, _ := spv.NewProofStore(pdir)
	t.Cleanup(func() { ps.Close() })

	edir, _ := os.MkdirTemp("", "anvil-api-envs-*")
	t.Cleanup(func() { os.RemoveAll(edir) })
	es, _ := envelope.NewStore(edir, 3600, 65536)
	t.Cleanup(func() { es.Close() })

	mgr := gossip.NewManager(gossip.ManagerConfig{
		Store:          es,
		LocalInterests: []string{"oracle:"},
		MaxSeen:        100,
	})
	t.Cleanup(func() { mgr.Stop() })

	validator := spv.NewValidator(hs)
	logger := slog.Default()
	mempool := txrelay.NewMempool()
	broadcaster := txrelay.NewBroadcaster(mempool, nil, logger)
	srv := NewServer(ServerConfig{
		HeaderStore: hs, ProofStore: ps, EnvelopeStore: es,
		Validator: validator, Broadcaster: broadcaster, GossipMgr: mgr,
		AuthToken: "test-token", Logger: logger,
	})
	return srv, mgr
}

func TestPostDataBroadcastsToMesh(t *testing.T) {
	srv, _ := testServerWithGossip(t)

	key, _ := ec.NewPrivateKey()
	env := &envelope.Envelope{
		Type:      "data",
		Topic:     "oracle:rates:bsv",
		Payload:   `{"rate":42}`,
		TTL:       60,
		Timestamp: 1700000000,
	}
	env.Sign(key)
	body, _ := json.Marshal(env)

	req := httptest.NewRequest("POST", "/data", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["accepted"] != true {
		t.Fatalf("expected accepted=true, got %v", resp["accepted"])
	}

	req2 := httptest.NewRequest("GET", "/data?topic=oracle:rates:bsv", nil)
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("query: expected 200, got %d", w2.Code)
	}
	var queryResp map[string]interface{}
	json.NewDecoder(w2.Body).Decode(&queryResp)
	if queryResp["count"].(float64) != 1 {
		t.Fatalf("expected 1 envelope, got %v", queryResp["count"])
	}
}
