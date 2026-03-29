package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/pkg/brc"
)

func TestOverlayLookupEmpty(t *testing.T) {
	srv := testServerWithOverlay(t)
	req := httptest.NewRequest("GET", "/overlay/lookup?topic=anvil:mainnet", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["count"].(float64) != 0 {
		t.Fatalf("expected 0 peers, got %v", resp["count"])
	}
}

func TestOverlayLookupRequiresTopic(t *testing.T) {
	srv := testServerWithOverlay(t)
	req := httptest.NewRequest("GET", "/overlay/lookup", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestEndToEndRegisterThenLookup(t *testing.T) {
	srv := testServerWithOverlay(t)
	key := overlayTestKey()

	scriptBytes, _, err := brc.BuildSHIPScript(key, "peer.example.com:8333", "anvil:mainnet")
	if err != nil {
		t.Fatal(err)
	}

	body := fmt.Sprintf(`{"script":"%s","txid":"tx123","output_index":0}`, hex.EncodeToString(scriptBytes))
	req := httptest.NewRequest("POST", "/overlay/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("register: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	req2 := httptest.NewRequest("GET", "/overlay/lookup?topic=anvil:mainnet", nil)
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("lookup: expected 200, got %d", w2.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w2.Body).Decode(&resp)
	if resp["count"].(float64) != 1 {
		t.Fatalf("expected 1 peer after registration, got %v", resp["count"])
	}

	peers := resp["peers"].([]interface{})
	peer := peers[0].(map[string]interface{})
	if peer["domain"] != "peer.example.com:8333" {
		t.Fatalf("expected domain peer.example.com:8333, got %v", peer["domain"])
	}
}

func TestOverlayRegisterRejectsInvalid(t *testing.T) {
	srv := testServerWithOverlay(t)
	body := `{"script":"deadbeef","txid":"tx","output_index":0}`
	req := httptest.NewRequest("POST", "/overlay/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEndToEndRegisterThenDeregister(t *testing.T) {
	srv := testServerWithOverlay(t)
	key := overlayTestKey()

	scriptBytes, _, _ := brc.BuildSHIPScript(key, "temp.example.com", "anvil:mainnet")

	body := fmt.Sprintf(`{"script":"%s","txid":"tx999","output_index":0}`, hex.EncodeToString(scriptBytes))
	req := httptest.NewRequest("POST", "/overlay/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("register: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	req2 := httptest.NewRequest("GET", "/overlay/lookup?topic=anvil:mainnet", nil)
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)
	var resp map[string]interface{}
	json.NewDecoder(w2.Body).Decode(&resp)
	if resp["count"].(float64) != 1 {
		t.Fatalf("expected 1 peer, got %v", resp["count"])
	}

	identityPubHex := hex.EncodeToString(key.PubKey().Compressed())
	deregBody := fmt.Sprintf(`{"topic":"anvil:mainnet","identity_pub":"%s"}`, identityPubHex)
	req3 := httptest.NewRequest("POST", "/overlay/deregister", strings.NewReader(deregBody))
	req3.Header.Set("Authorization", "Bearer test-token")
	req3.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("deregister: expected 200, got %d: %s", w3.Code, w3.Body.String())
	}

	req4 := httptest.NewRequest("GET", "/overlay/lookup?topic=anvil:mainnet", nil)
	w4 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w4, req4)
	var resp2 map[string]interface{}
	json.NewDecoder(w4.Body).Decode(&resp2)
	if resp2["count"].(float64) != 0 {
		t.Fatalf("expected 0 peers after deregister, got %v", resp2["count"])
	}
}
