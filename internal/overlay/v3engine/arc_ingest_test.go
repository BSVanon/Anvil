package v3engine

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// TestArcIngestHandler_MissingTxid covers vector
// overlay.topicmanagement.18: missing txid → 400 + canonical envelope.
func TestArcIngestHandler_MissingTxid(t *testing.T) {
	url := newTestServer(t)
	body := []byte(`{"merklePath":"fe8a6a0c","blockHeight":813706}`)
	resp, err := http.Post(url+"/arc-ingest", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400, got %d: %s", resp.StatusCode, raw)
	}
	assertCanonicalErrorEnvelope(t, resp.Body, "txid required")
}

func TestArcIngestHandler_MissingMerklePath(t *testing.T) {
	url := newTestServer(t)
	body := []byte(`{"txid":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2","blockHeight":813706}`)
	resp, err := http.Post(url+"/arc-ingest", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	assertCanonicalErrorEnvelope(t, resp.Body, "merklePath required")
}

func TestArcIngestHandler_InvalidTxid(t *testing.T) {
	url := newTestServer(t)
	body := []byte(`{"txid":"not-hex","merklePath":"fe8a","blockHeight":1}`)
	resp, err := http.Post(url+"/arc-ingest", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	assertCanonicalErrorEnvelope(t, resp.Body, "invalid txid")
}

func TestArcIngestHandler_WrongMethod(t *testing.T) {
	url := newTestServer(t)
	resp, err := http.Get(url + "/arc-ingest")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
	assertCanonicalErrorEnvelope(t, resp.Body, "POST")
}

func TestArcIngestHandler_BadJSON(t *testing.T) {
	url := newTestServer(t)
	resp, err := http.Post(url+"/arc-ingest", "application/json", bytes.NewReader([]byte("{")))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	assertCanonicalErrorEnvelope(t, resp.Body, "invalid arc-ingest body")
}

// TestArcIngestHandler_NoMatchingOutputsIsSuccess: per upstream
// engine.go:1516-1518, HandleNewMerkleProof returns nil (no error)
// when the tx isn't admitted to any topic on this overlay. We surface
// that as a 200 success envelope so ARC callbacks don't retry on
// every block the overlay doesn't care about.
//
// We can't construct a real merkle path that passes
// chaintracker.IsValidRootForHeight against the test header store
// (the store only has the genesis block), so this test instead
// confirms that an INVALID-but-well-formed merkle path produces a
// canonical 400, exercising the "engine returned error" branch. The
// successful no-op branch is exercised implicitly by W-6 conformance
// once real merkle proofs flow through.
func TestArcIngestHandler_InvalidMerklePathReturns400(t *testing.T) {
	url := newTestServer(t)
	// Real-looking merklePath hex that won't parse correctly.
	body, _ := json.Marshal(arcIngestRequest{
		Txid:        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		MerklePath:  "deadbeef",
		BlockHeight: 100,
	})
	resp, err := http.Post(url+"/arc-ingest", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed merkle path, got %d", resp.StatusCode)
	}
	assertCanonicalErrorEnvelope(t, resp.Body, "merklePath")
}
