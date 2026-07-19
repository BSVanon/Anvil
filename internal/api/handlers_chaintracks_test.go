package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fetchChaintracks issues a GET against path and decodes the {status,value,...}
// envelope, returning the HTTP status and the decoded body.
func fetchChaintracks(t *testing.T, srv *Server, path string) (int, map[string]interface{}) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	var resp map[string]interface{}
	if w.Body.Len() > 0 {
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("%s: decode body: %v", path, err)
		}
	}
	return w.Code, resp
}

func TestGetPresentHeightGenesis(t *testing.T) {
	srv := testServer(t)
	code, resp := fetchChaintracks(t, srv, "/getPresentHeight")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if resp["status"] != "success" {
		t.Fatalf("expected status=success, got %v", resp["status"])
	}
	if resp["value"].(float64) != 0 {
		t.Fatalf("expected genesis tip 0, got %v", resp["value"])
	}
}

func TestGetPresentHeightAfterChain(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 10)
	code, resp := fetchChaintracks(t, srv, "/getPresentHeight")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if resp["value"].(float64) != 10 {
		t.Fatalf("expected tip 10, got %v", resp["value"])
	}
}

func TestFindHeaderHexForHeightShape(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 5)

	code, resp := fetchChaintracks(t, srv, "/findHeaderHexForHeight?height=1")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if resp["status"] != "success" {
		t.Fatalf("expected status=success, got %v", resp["status"])
	}
	val := resp["value"].(map[string]interface{})

	if val["height"].(float64) != 1 {
		t.Fatalf("expected height 1, got %v", val["height"])
	}
	if val["version"].(float64) != 1 {
		t.Fatalf("expected version 1, got %v", val["version"])
	}
	if val["bits"].(float64) != float64(0x1d00ffff) {
		t.Fatalf("expected bits 0x1d00ffff, got %v", val["bits"])
	}
	// addServerTestChain sets nonce = i; height 1 is built from i=0.
	if val["nonce"].(float64) != 0 {
		t.Fatalf("expected nonce 0, got %v", val["nonce"])
	}
	if val["time"].(float64) <= 0 {
		t.Fatalf("expected positive time, got %v", val["time"])
	}

	// Display/big-endian assertions — the make-or-break contract detail.
	// addServerTestChain builds every header with this display-hex merkle root
	// (NewHashFromStr parses display hex). A correct wire->display reversal
	// round-trips it back to the same string.
	const wantMerkle = "abcdef0000000000000000000000000000000000000000000000000000000000"
	if val["merkleRoot"] != wantMerkle {
		t.Fatalf("merkleRoot byte order wrong: got %v want %s", val["merkleRoot"], wantMerkle)
	}
	// previousHash of height 1 must equal the genesis block hash in display form.
	genHash, err := srv.headerStore.HashAtHeight(0)
	if err != nil {
		t.Fatal(err)
	}
	if val["previousHash"] != genHash.String() {
		t.Fatalf("previousHash mismatch: got %v want %s", val["previousHash"], genHash.String())
	}
	// hash must match the store's own display hash for height 1.
	h1, err := srv.headerStore.HashAtHeight(1)
	if err != nil {
		t.Fatal(err)
	}
	if val["hash"] != h1.String() {
		t.Fatalf("hash mismatch: got %v want %s", val["hash"], h1.String())
	}
}

// TestFindHeaderHexChainLinkage proves hash and previousHash share the same
// (display) byte order: block N+1's previousHash must equal block N's hash.
func TestFindHeaderHexChainLinkage(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 5)

	_, r1 := fetchChaintracks(t, srv, "/findHeaderHexForHeight?height=1")
	_, r2 := fetchChaintracks(t, srv, "/findHeaderHexForHeight?height=2")
	h1 := r1["value"].(map[string]interface{})["hash"]
	prev2 := r2["value"].(map[string]interface{})["previousHash"]
	if h1 != prev2 {
		t.Fatalf("chain linkage broken in display space: hash(1)=%v prev(2)=%v", h1, prev2)
	}
}

func TestFindHeaderHexForHeightMissing(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 3)

	// Above tip.
	code, resp := fetchChaintracks(t, srv, "/findHeaderHexForHeight?height=999")
	if code != http.StatusNotFound {
		t.Fatalf("expected 404 for above-tip height, got %d", code)
	}
	if resp["status"] != "error" {
		t.Fatalf("expected status=error, got %v", resp["status"])
	}
	if _, ok := resp["value"]; ok {
		t.Fatal("miss must not carry a value (no placeholder header)")
	}
}

func TestFindHeaderHexForHeightBadRequest(t *testing.T) {
	srv := testServer(t)
	for _, path := range []string{
		"/findHeaderHexForHeight",            // missing height
		"/findHeaderHexForHeight?height=abc", // non-integer
		"/findHeaderHexForHeight?height=-1",  // negative (ParseUint rejects)
	} {
		code, resp := fetchChaintracks(t, srv, path)
		if code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d", path, code)
		}
		if resp["status"] != "error" {
			t.Fatalf("%s: expected status=error, got %v", path, resp["status"])
		}
	}
}

// TestChaintracksPublicAndCORS confirms both endpoints need no auth token and
// carry permissive CORS headers (they inherit openRead's public path).
func TestChaintracksPublicAndCORS(t *testing.T) {
	srv := testServerNoAuth(t)
	addServerTestChain(t, srv, 2)
	for _, path := range []string{"/getPresentHeight", "/findHeaderHexForHeight?height=1"} {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: expected 200 without auth, got %d", path, w.Code)
		}
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Fatalf("%s: expected CORS *, got %q", path, got)
		}
	}
}

// TestChaintracksPublicUnderPaymentGate is the regression for the HIGH finding:
// on a node that charges x402 (PriceSats>0), the chaintracks endpoints must
// still serve unauthenticated (200), not answer a browser GET with a 402
// challenge. openPublic must keep them off the payment/token gate that openRead
// applies.
func TestChaintracksPublicUnderPaymentGate(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 3)
	srv.paymentGate = NewPaymentGate(PaymentGateConfig{
		PriceSats:      100,
		PayeeScriptHex: testPayeeScript(t),
		NonceProvider:  &DevNonceProvider{},
	})
	srv.mux = http.NewServeMux()
	srv.routes()

	// Sanity: a normal openRead path IS gated at this price (402), so a 200 on
	// the chaintracks paths proves the gate is active and they bypass it — not
	// that the gate simply wasn't wired.
	req := httptest.NewRequest("GET", "/headers/tip", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("/headers/tip: expected 402 under priced gate, got %d", w.Code)
	}

	for _, path := range []string{"/getPresentHeight", "/findHeaderHexForHeight?height=1"} {
		code, resp := fetchChaintracks(t, srv, path)
		if code != http.StatusOK {
			t.Fatalf("%s: expected 200 under priced payment gate, got %d", path, code)
		}
		if resp["status"] != "success" {
			t.Fatalf("%s: expected status=success, got %v", path, resp["status"])
		}
	}
}

// TestFindHeaderHexForHeightInternalError is the regression for the MEDIUM
// finding: a real header-store failure (not a miss) must surface as 500, not be
// masked as a 404 "unproven". Closing the store makes HeaderAtHeight return a
// non-ErrNotFound error (leveldb.ErrClosed).
func TestFindHeaderHexForHeightInternalError(t *testing.T) {
	srv := testServer(t)
	srv.headerStore.Close() // simulate a store outage; cleanup's second Close is a no-op

	// height 0 (genesis) normally exists — a 404 here would mean the outage was
	// misreported as a miss.
	code, resp := fetchChaintracks(t, srv, "/findHeaderHexForHeight?height=0")
	if code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on store failure, got %d", code)
	}
	if resp["status"] != "error" {
		t.Fatalf("expected status=error, got %v", resp["status"])
	}
}
