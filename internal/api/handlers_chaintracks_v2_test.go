package api

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// fetchBareJSON issues a GET and decodes the body as plain (unwrapped) JSON
// — the bare dialect every /chaintracks/v2 route answers, contrasting with
// handlers_chaintracks_test.go's fetchChaintracks, which decodes the v1
// shim's {status,value,...} envelope.
func fetchBareJSON(t *testing.T, srv *Server, path string) (int, http.Header, map[string]interface{}) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	var body map[string]interface{}
	if w.Body.Len() > 0 {
		if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
			t.Fatalf("%s: decode body: %v (raw: %s)", path, err, w.Body.String())
		}
	}
	return w.Code, w.Header(), body
}

// fetchBareBytes issues a GET and returns the raw response body, for the
// octet-stream routes (/headers and the .bin family).
func fetchBareBytes(t *testing.T, srv *Server, path string) (int, http.Header, []byte) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w.Code, w.Header(), w.Body.Bytes()
}

func TestChaintracksV2Network(t *testing.T) {
	srv := testServer(t)
	code, _, body := fetchBareJSON(t, srv, "/chaintracks/v2/network")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if body["network"] != "main" {
		t.Fatalf("expected bare network=main, got %#v", body)
	}
	if _, ok := body["status"]; ok {
		t.Fatal("bare dialect must not carry a status envelope")
	}
	if _, ok := body["value"]; ok {
		t.Fatal("bare dialect must not carry a value envelope")
	}
}

// TestChaintracksV2Height covers the bcommon Arcade-kind addition: a bare
// {"height":N}, not a canonical route at all, plus the Cache-Control
// canonical sets on it (routes/fiber/routes.go:313-316).
func TestChaintracksV2Height(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 7)

	code, hdr, body := fetchBareJSON(t, srv, "/chaintracks/v2/height")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if body["height"].(float64) != 7 {
		t.Fatalf("expected height 7, got %v", body["height"])
	}
	if got := hdr.Get("Cache-Control"); got != "public, max-age=60" {
		t.Fatalf("Cache-Control = %q, want canonical's public, max-age=60", got)
	}
}

func TestChaintracksV2TipGenesis(t *testing.T) {
	srv := testServer(t)
	code, hdr, body := fetchBareJSON(t, srv, "/chaintracks/v2/tip")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if body["height"].(float64) != 0 {
		t.Fatalf("expected genesis tip height 0, got %v", body["height"])
	}
	genHash, err := srv.headerStore.HashAtHeight(0)
	if err != nil {
		t.Fatal(err)
	}
	if body["hash"] != genHash.String() {
		t.Fatalf("tip hash mismatch: got %v want %s", body["hash"], genHash.String())
	}
	if got := hdr.Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("Cache-Control = %q, want canonical's no-cache", got)
	}
	if got := hdr.Get("X-Block-Height"); got != "0" {
		t.Fatalf("X-Block-Height = %q, want 0", got)
	}
}

func TestChaintracksV2TipAfterChain(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 5)
	code, hdr, body := fetchBareJSON(t, srv, "/chaintracks/v2/tip")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if body["height"].(float64) != 5 {
		t.Fatalf("expected tip height 5, got %v", body["height"])
	}
	h5, err := srv.headerStore.HashAtHeight(5)
	if err != nil {
		t.Fatal(err)
	}
	if body["hash"] != h5.String() {
		t.Fatalf("hash mismatch: got %v want %s", body["hash"], h5.String())
	}
	if got := hdr.Get("X-Block-Height"); got != "5" {
		t.Fatalf("X-Block-Height = %q, want 5", got)
	}
}

func TestChaintracksV2TipInternalError(t *testing.T) {
	srv := testServer(t)
	srv.headerStore.Close() // simulate a store outage

	code, _, body := fetchBareJSON(t, srv, "/chaintracks/v2/tip")
	if code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on store failure, got %d %#v", code, body)
	}
	if body["error"] == nil {
		t.Fatal("expected a bare {\"error\":...} body")
	}
}

// TestChaintracksV2HeaderByHeightShape is the golden-JSON test: every one of
// the 8 fields addServerTestChain pins is checked against its known value.
func TestChaintracksV2HeaderByHeightShape(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 5)

	code, _, body := fetchBareJSON(t, srv, "/chaintracks/v2/header/height/1")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}

	if body["height"].(float64) != 1 {
		t.Fatalf("expected height 1, got %v", body["height"])
	}
	if body["version"].(float64) != 1 {
		t.Fatalf("expected version 1, got %v", body["version"])
	}
	if body["bits"].(float64) != float64(0x1d00ffff) {
		t.Fatalf("expected bits 0x1d00ffff, got %v", body["bits"])
	}
	// addServerTestChain sets nonce = i; height 1 is built from i=0.
	if body["nonce"].(float64) != 0 {
		t.Fatalf("expected nonce 0, got %v", body["nonce"])
	}
	if body["time"].(float64) <= 0 {
		t.Fatalf("expected positive time, got %v", body["time"])
	}

	const wantMerkle = "abcdef0000000000000000000000000000000000000000000000000000000000"
	if body["merkleRoot"] != wantMerkle {
		t.Fatalf("merkleRoot byte order wrong: got %v want %s", body["merkleRoot"], wantMerkle)
	}
	genHash, err := srv.headerStore.HashAtHeight(0)
	if err != nil {
		t.Fatal(err)
	}
	if body["previousHash"] != genHash.String() {
		t.Fatalf("previousHash mismatch: got %v want %s", body["previousHash"], genHash.String())
	}
	h1, err := srv.headerStore.HashAtHeight(1)
	if err != nil {
		t.Fatal(err)
	}
	if body["hash"] != h1.String() {
		t.Fatalf("hash mismatch: got %v want %s", body["hash"], h1.String())
	}
}

// TestChaintracksV2HeaderPoWFieldsReserializeToHash is the PoW
// re-serialize-and-hash test: it reconstructs the 80-byte header from the
// 6 consensus fields the JSON carries and double-SHA256s it independently
// of Anvil's own wire.BlockHeader type (the same check a real consumer —
// e.g. github.com/lightwebinc/bcommon's headers/pow.go check() — performs
// against any header service's answer), and confirms the result matches
// the served "hash" field exactly.
func TestChaintracksV2HeaderPoWFieldsReserializeToHash(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 5)

	for height := uint32(0); height <= 5; height++ {
		_, _, body := fetchBareJSON(t, srv, "/chaintracks/v2/header/height/"+strconv.FormatUint(uint64(height), 10))
		got := reserializeAndHash(t, body)
		if got != body["hash"] {
			t.Fatalf("height %d: reserialized hash %s != served hash %v", height, got, body["hash"])
		}
	}
}

func TestChaintracksV2HeaderByHeightMissing(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 3)

	code, _, body := fetchBareJSON(t, srv, "/chaintracks/v2/header/height/999")
	if code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d %#v", code, body)
	}
	if body["error"] != "Header not found" {
		t.Fatalf("expected canonical error text, got %#v", body)
	}
}

func TestChaintracksV2HeaderByHeightBadRequest(t *testing.T) {
	srv := testServer(t)
	for _, path := range []string{
		"/chaintracks/v2/header/height/abc", // non-integer
		"/chaintracks/v2/header/height/-1",  // negative
	} {
		code, _, body := fetchBareJSON(t, srv, path)
		if code != http.StatusBadRequest || body["error"] != "Invalid height parameter" {
			t.Fatalf("%s: expected 400 with canonical error text, got %d %#v", path, code, body)
		}
	}
}

func TestChaintracksV2HeaderByHashGenesis(t *testing.T) {
	srv := testServer(t)
	const genesis = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
	code, _, body := fetchBareJSON(t, srv, "/chaintracks/v2/header/hash/"+genesis)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if body["height"].(float64) != 0 || body["hash"] != genesis {
		t.Fatalf("unexpected genesis value: %#v", body)
	}
}

// TestChaintracksV2HeaderByHashChainLinkage proves hash and previousHash
// share the same (display) byte order: block N+1's previousHash must equal
// block N's hash — mirrors the v1 shim's TestFindHeaderHexChainLinkage.
func TestChaintracksV2HeaderByHashChainLinkage(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 5)

	_, _, r1 := fetchBareJSON(t, srv, "/chaintracks/v2/header/height/1")
	_, _, r2 := fetchBareJSON(t, srv, "/chaintracks/v2/header/height/2")
	h1 := r1["hash"]
	prev2 := r2["previousHash"]
	if h1 != prev2 {
		t.Fatalf("chain linkage broken in display space: hash(1)=%v prev(2)=%v", h1, prev2)
	}

	_, _, byHash := fetchBareJSON(t, srv, "/chaintracks/v2/header/hash/"+h1.(string))
	if byHash["height"].(float64) != 1 {
		t.Fatalf("header/hash/%v: expected height 1, got %#v", h1, byHash)
	}
}

func TestChaintracksV2HeaderByHashMissing(t *testing.T) {
	srv := testServer(t)
	unknown := strings.Repeat("1", 64)
	code, _, body := fetchBareJSON(t, srv, "/chaintracks/v2/header/hash/"+unknown)
	if code != http.StatusNotFound || body["error"] != "Header not found" {
		t.Fatalf("expected 404 with canonical error text, got %d %#v", code, body)
	}
}

func TestChaintracksV2HeaderByHashBadRequest(t *testing.T) {
	srv := testServer(t)
	code, _, body := fetchBareJSON(t, srv, "/chaintracks/v2/header/hash/bad")
	if code != http.StatusBadRequest || body["error"] != "Invalid hash parameter" {
		t.Fatalf("expected 400 with canonical error text, got %d %#v", code, body)
	}
}

// The /headers range route tests, plus the public/CORS and payment-gate
// sweeps, are in handlers_chaintracks_v2_headers_test.go (split out to keep
// both files under the 400-line bespoke cap).

// --- local test helpers ---

// reserializeAndHash reconstructs the 80-byte Bitcoin header from the 6
// consensus fields of a chaintracks v2 header value and double-SHA256s it,
// entirely independently of Anvil's own wire.BlockHeader type. Returns the
// result as display-order (big-endian) hex.
func reserializeAndHash(t *testing.T, v map[string]interface{}) string {
	t.Helper()
	buf := make([]byte, 80)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(int32(v["version"].(float64))))

	prev, err := hex.DecodeString(v["previousHash"].(string))
	if err != nil || len(prev) != 32 {
		t.Fatalf("previousHash: %v (len %d)", err, len(prev))
	}
	reverseBytes(prev)
	copy(buf[4:36], prev)

	root, err := hex.DecodeString(v["merkleRoot"].(string))
	if err != nil || len(root) != 32 {
		t.Fatalf("merkleRoot: %v (len %d)", err, len(root))
	}
	reverseBytes(root)
	copy(buf[36:68], root)

	binary.LittleEndian.PutUint32(buf[68:72], uint32(v["time"].(float64)))
	binary.LittleEndian.PutUint32(buf[72:76], uint32(v["bits"].(float64)))
	binary.LittleEndian.PutUint32(buf[76:80], uint32(v["nonce"].(float64)))

	first := sha256.Sum256(buf)
	second := sha256.Sum256(first[:])
	reverseBytes(second[:])
	return hex.EncodeToString(second[:])
}

func reverseBytes(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}
