package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdminStats_NoAuth_401(t *testing.T) {
	h := New(Config{
		NodeName:         "overlay-node",
		AdminBearerToken: "secret-token",
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/admin/stats", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got["status"] != "error" {
		t.Errorf("body.status = %v, want 'error'", got["status"])
	}
}

func TestAdminStats_WrongBearer_401(t *testing.T) {
	h := New(Config{AdminBearerToken: "secret-token"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/stats", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (wrong Bearer token)", rec.Code)
	}
}

func TestAdminStats_NoConfigBearer_AlwaysRejects(t *testing.T) {
	// If AdminBearerToken is empty (admin auth disabled), all requests 401.
	h := New(Config{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/stats", nil)
	req.Header.Set("Authorization", "Bearer any-token")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 when admin disabled", rec.Code)
	}
}

func TestAdminStats_ValidBearer_200WithStats(t *testing.T) {
	h := New(Config{
		NodeName:         "overlay-test-node",
		Network:          "main",
		AdminBearerToken: "test-admin-token-abc123",
		TopicManagerNames: func() []string {
			return []string{"tm_ship", "tm_slap"}
		},
		LookupServiceNames: func() []string {
			return []string{"ls_ship", "ls_slap"}
		},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/stats", nil)
	req.Header.Set("Authorization", "Bearer test-admin-token-abc123")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	var got AdminStatsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse: %v\n%s", err, rec.Body.String())
	}
	if got.Status != "success" {
		t.Errorf("status = %q, want success", got.Status)
	}
	if got.Data.NodeName != "overlay-test-node" {
		t.Errorf("nodeName = %q", got.Data.NodeName)
	}
	if got.Data.Network != "main" {
		t.Errorf("network = %q", got.Data.Network)
	}
	if strings.Join(got.Data.TopicManagers, ",") != "tm_ship,tm_slap" {
		t.Errorf("topicManagers = %v", got.Data.TopicManagers)
	}
	if strings.Join(got.Data.LookupServices, ",") != "ls_ship,ls_slap" {
		t.Errorf("lookupServices = %v", got.Data.LookupServices)
	}
}

func TestArcIngest_HappyPath_200(t *testing.T) {
	h := New(Config{})
	body := []byte(`{"txid":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2","merklePath":"fe8a","blockHeight":813706}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/arc-ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var got ArcIngestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Status != "success" {
		t.Errorf("status = %q, want success", got.Status)
	}
}

func TestArcIngest_MissingTxid_400(t *testing.T) {
	h := New(Config{})
	body := []byte(`{"merklePath":"fe8a","blockHeight":813706}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/arc-ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got["status"] != "error" {
		t.Errorf("body.status = %v, want 'error'", got["status"])
	}
}

func TestArcIngest_MalformedJSON_400(t *testing.T) {
	h := New(Config{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/arc-ingest", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (malformed JSON)", rec.Code)
	}
}

// Codex 9fe46aca regression: arc-ingest must forward to the engine via
// Config.ArcIngest. These tests prove the callback receives the decoded
// request, and that a failed callback surfaces as 500 (so production
// operators see the failure instead of mined notifications dropping silently).

func TestArcIngest_CallbackInvokedWithDecodedBody(t *testing.T) {
	var captured ArcIngestRequest
	var called int
	h := New(Config{
		ArcIngest: func(req ArcIngestRequest) error {
			called++
			captured = req
			return nil
		},
	})
	body := []byte(`{"txid":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2","merklePath":"fe8a","blockHeight":813706}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/arc-ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if called != 1 {
		t.Fatalf("callback invoked %d times, want 1", called)
	}
	if captured.Txid != "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2" {
		t.Errorf("captured.Txid = %q", captured.Txid)
	}
	if captured.MerklePath != "fe8a" {
		t.Errorf("captured.MerklePath = %q", captured.MerklePath)
	}
	if captured.BlockHeight != 813706 {
		t.Errorf("captured.BlockHeight = %d", captured.BlockHeight)
	}
}

func TestArcIngest_CallbackError_500(t *testing.T) {
	h := New(Config{
		ArcIngest: func(req ArcIngestRequest) error {
			return errors.New("engine rejected the proof")
		},
	})
	body := []byte(`{"txid":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2","merklePath":"fe","blockHeight":1}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/arc-ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got["status"] != "error" {
		t.Errorf("body.status = %v, want 'error'", got["status"])
	}
	if got["code"] != "ERR_ARC_INGEST_FAILED" {
		t.Errorf("body.code = %v, want 'ERR_ARC_INGEST_FAILED'", got["code"])
	}
}

func TestArcIngest_NoCallback_StillAcknowledges(t *testing.T) {
	// Conformance-runner case: no callback configured. Handler still returns
	// 200 (vector .17 contract), but the lack of side-effect is the price
	// of running without an engine wired up. Production wiring MUST set
	// the callback per Codex 9fe46aca.
	h := New(Config{})
	body := []byte(`{"txid":"abcd","merklePath":"","blockHeight":0}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/arc-ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (nil-callback path)", rec.Code)
	}
}

func TestArcIngest_CallbackNotInvokedOnMissingTxid(t *testing.T) {
	// Validation runs before the callback: a missing-txid request must
	// 400 without ever invoking ArcIngest. Otherwise we'd notify the
	// engine of garbage.
	called := 0
	h := New(Config{
		ArcIngest: func(req ArcIngestRequest) error {
			called++
			return nil
		},
	})
	body := []byte(`{"merklePath":"fe","blockHeight":1}`) // no txid
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/arc-ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if called != 0 {
		t.Errorf("callback invoked %d times on bad request; expected 0", called)
	}
}
