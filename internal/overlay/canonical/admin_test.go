package canonical

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminConfig_WithIdentity(t *testing.T) {
	h := New(Config{
		NodeName:         "overlay-test-node",
		AdminIdentityKey: "02a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/admin/config", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	// Parse into raw map to verify adminIdentityKey is a string (not null).
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse: %v\n%s", err, rec.Body.String())
	}
	if got["nodeName"] != "overlay-test-node" {
		t.Errorf("nodeName = %v, want overlay-test-node", got["nodeName"])
	}
	keyVal, ok := got["adminIdentityKey"].(string)
	if !ok || keyVal == "" {
		t.Errorf("adminIdentityKey = %v (%T), want non-empty string", got["adminIdentityKey"], got["adminIdentityKey"])
	}
}

func TestAdminConfig_NoIdentity_JSONNull(t *testing.T) {
	h := New(Config{
		NodeName: "overlay-node",
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/admin/config", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	// Parse into raw map and confirm adminIdentityKey is JSON null, not
	// missing and not empty string. Vector .6 expects: `adminIdentityKey: null`.
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse: %v\n%s", err, rec.Body.String())
	}
	keyVal, present := got["adminIdentityKey"]
	if !present {
		t.Error("adminIdentityKey missing from response body")
	}
	if keyVal != nil {
		t.Errorf("adminIdentityKey = %v (%T), want JSON null", keyVal, keyVal)
	}
	if got["nodeName"] != "overlay-node" {
		t.Errorf("nodeName = %v, want overlay-node", got["nodeName"])
	}
}

func TestAdminConfig_NoAuthRequired(t *testing.T) {
	// Vector overlay.topicmanagement.5 explicitly notes "without auth". The
	// route MUST NOT challenge for credentials even with no auth headers.
	h := New(Config{NodeName: "overlay-node"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/config", nil)
	// No headers set.
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
		t.Fatalf("/admin/config gated by auth (status %d); vector requires no-auth access", rec.Code)
	}
}
