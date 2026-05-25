package canonical

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealth_HappyPath(t *testing.T) {
	h := New(Config{
		NodeName:           "overlay-node",
		Network:            "main",
		Ready:              func() bool { return true },
		TopicManagerCount:  func() int { return 2 },
		LookupServiceCount: func() int { return 2 },
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got HealthReport
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse body: %v\n%s", err, rec.Body.String())
	}
	if got.Status != "ok" || !got.Live || !got.Ready {
		t.Errorf("unexpected status/live/ready: %+v", got)
	}
	if got.Service.Name != "overlay-node" || got.Service.Network != "main" {
		t.Errorf("unexpected service summary: %+v", got.Service)
	}
	if got.Service.TopicManagerCount != 2 || got.Service.LookupServiceCount != 2 {
		t.Errorf("unexpected counts: %+v", got.Service)
	}
}

func TestHealth_NotReady_503Degraded(t *testing.T) {
	h := New(Config{
		Ready: func() bool { return false },
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/health", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	var got HealthReport
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Status != "degraded" {
		t.Errorf("status = %q, want degraded", got.Status)
	}
	if got.Ready {
		t.Error("expected ready=false")
	}
	if !got.Live {
		t.Error("expected live=true even when not ready")
	}
}

func TestHealth_Live_AlwaysOK(t *testing.T) {
	h := New(Config{Ready: func() bool { return false }})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/health/live", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (liveness is independent of readiness)", rec.Code)
	}
	var got LiveReport
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !got.Live {
		t.Error("expected live=true")
	}
}

func TestHealth_Ready_HappyPath(t *testing.T) {
	h := New(Config{Ready: func() bool { return true }})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/health/ready", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got ReadyReport
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !got.Ready || got.Status != "ok" {
		t.Errorf("unexpected: %+v", got)
	}
}

func TestHealth_NilDefaults(t *testing.T) {
	// All callbacks nil — Config defaults should keep the surface working.
	h := New(Config{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (nil Ready treated as always ready)", rec.Code)
	}
	var got HealthReport
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Service.Network != "main" {
		t.Errorf("default network = %q, want main", got.Service.Network)
	}
	if got.Service.TopicManagerCount != 0 || got.Service.LookupServiceCount != 0 {
		t.Errorf("default counts should be 0, got %+v", got.Service)
	}
}

func TestRegister_AttachesToExternalMux(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /unrelated", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	Register(mux, Config{Ready: func() bool { return true }})

	// The unrelated route still works.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/unrelated", nil))
	if rec.Code != http.StatusTeapot {
		t.Errorf("unrelated route broke: %d", rec.Code)
	}

	// And the canonical /health/live is now reachable on the same mux.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/health/live", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/health/live status = %d, want 200", rec.Code)
	}
}
