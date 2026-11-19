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

// Reuses testServer, testServerNoAuth, addServerTestChain (server_test.go)
// and fetchChaintracks (handlers_chaintracks_test.go) — the same fixtures
// and {status,value,...} envelope decoder the v1 shim's tests use.

func TestChaintracksV2Network(t *testing.T) {
	srv := testServer(t)
	code, resp := fetchChaintracks(t, srv, "/chaintracks/v2/network")
	if code != http.StatusOK || resp["status"] != "success" {
		t.Fatalf("expected success, got %d %#v", code, resp)
	}
	if resp["value"] != "main" {
		t.Fatalf("expected value=main, got %#v", resp["value"])
	}
	if _, ok := resp["code"]; ok {
		t.Fatal("success envelope must omit code")
	}
	if _, ok := resp["description"]; ok {
		t.Fatal("success envelope must omit description")
	}
}

// TestChaintracksV2Height covers the bcommon Arcade-kind addition: a bare
// {"height":N}, no {status,value} envelope.
func TestChaintracksV2Height(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 7)

	req := httptest.NewRequest("GET", "/chaintracks/v2/height", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["height"].(float64) != 7 {
		t.Fatalf("expected height 7, got %v", body["height"])
	}
	if _, ok := body["status"]; ok {
		t.Fatal("the bare /height route must not carry a {status,value} envelope")
	}
	if _, ok := body["value"]; ok {
		t.Fatal("the bare /height route must not carry a {status,value} envelope")
	}
}

func TestChaintracksV2TipGenesis(t *testing.T) {
	srv := testServer(t)
	code, resp := fetchChaintracks(t, srv, "/chaintracks/v2/tip")
	if code != http.StatusOK || resp["status"] != "success" {
		t.Fatalf("expected success, got %d %#v", code, resp)
	}
	val := resp["value"].(map[string]interface{})
	if val["height"].(float64) != 0 {
		t.Fatalf("expected genesis tip height 0, got %v", val["height"])
	}
	genHash, err := srv.headerStore.HashAtHeight(0)
	if err != nil {
		t.Fatal(err)
	}
	if val["hash"] != genHash.String() {
		t.Fatalf("tip hash mismatch: got %v want %s", val["hash"], genHash.String())
	}
}

func TestChaintracksV2TipAfterChain(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 5)
	code, resp := fetchChaintracks(t, srv, "/chaintracks/v2/tip")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	val := resp["value"].(map[string]interface{})
	if val["height"].(float64) != 5 {
		t.Fatalf("expected tip height 5, got %v", val["height"])
	}
	h5, err := srv.headerStore.HashAtHeight(5)
	if err != nil {
		t.Fatal(err)
	}
	if val["hash"] != h5.String() {
		t.Fatalf("hash mismatch: got %v want %s", val["hash"], h5.String())
	}
}

func TestChaintracksV2TipInternalError(t *testing.T) {
	srv := testServer(t)
	srv.headerStore.Close() // simulate a store outage

	code, resp := fetchChaintracks(t, srv, "/chaintracks/v2/tip")
	if code != http.StatusInternalServerError || resp["code"] != "ERR_INTERNAL" {
		t.Fatalf("expected 500 ERR_INTERNAL on store failure, got %d %#v", code, resp)
	}
}

// TestChaintracksV2HeaderByHeightShape is the golden-JSON test: every one of
// the 8 fields addServerTestChain pins is checked against its known value.
func TestChaintracksV2HeaderByHeightShape(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 5)

	code, resp := fetchChaintracks(t, srv, "/chaintracks/v2/header/height/1")
	if code != http.StatusOK || resp["status"] != "success" {
		t.Fatalf("expected success, got %d %#v", code, resp)
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

	const wantMerkle = "abcdef0000000000000000000000000000000000000000000000000000000000"
	if val["merkleRoot"] != wantMerkle {
		t.Fatalf("merkleRoot byte order wrong: got %v want %s", val["merkleRoot"], wantMerkle)
	}
	genHash, err := srv.headerStore.HashAtHeight(0)
	if err != nil {
		t.Fatal(err)
	}
	if val["previousHash"] != genHash.String() {
		t.Fatalf("previousHash mismatch: got %v want %s", val["previousHash"], genHash.String())
	}
	h1, err := srv.headerStore.HashAtHeight(1)
	if err != nil {
		t.Fatal(err)
	}
	if val["hash"] != h1.String() {
		t.Fatalf("hash mismatch: got %v want %s", val["hash"], h1.String())
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
		_, resp := fetchChaintracks(t, srv, "/chaintracks/v2/header/height/"+strconv.FormatUint(uint64(height), 10))
		val := resp["value"].(map[string]interface{})
		got := reserializeAndHash(t, val)
		if got != val["hash"] {
			t.Fatalf("height %d: reserialized hash %s != served hash %v", height, got, val["hash"])
		}
	}
}

func TestChaintracksV2HeaderByHeightMissing(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 3)

	code, resp := fetchChaintracks(t, srv, "/chaintracks/v2/header/height/999")
	if code != http.StatusNotFound || resp["code"] != "ERR_NOT_FOUND" {
		t.Fatalf("expected 404 ERR_NOT_FOUND for above-tip height, got %d %#v", code, resp)
	}
	if _, ok := resp["value"]; ok {
		t.Fatal("miss must not carry a value")
	}
}

func TestChaintracksV2HeaderByHeightBadRequest(t *testing.T) {
	srv := testServer(t)
	for _, path := range []string{
		"/chaintracks/v2/header/height/abc", // non-integer
		"/chaintracks/v2/header/height/-1",  // negative
	} {
		code, resp := fetchChaintracks(t, srv, path)
		if code != http.StatusBadRequest || resp["code"] != "ERR_INVALID_PARAMS" {
			t.Fatalf("%s: expected 400 ERR_INVALID_PARAMS, got %d %#v", path, code, resp)
		}
	}
}

func TestChaintracksV2HeaderByHashGenesis(t *testing.T) {
	srv := testServer(t)
	const genesis = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
	code, resp := fetchChaintracks(t, srv, "/chaintracks/v2/header/hash/"+genesis)
	if code != http.StatusOK || resp["status"] != "success" {
		t.Fatalf("expected success, got %d %#v", code, resp)
	}
	val := resp["value"].(map[string]interface{})
	if val["height"].(float64) != 0 || val["hash"] != genesis {
		t.Fatalf("unexpected genesis value: %#v", val)
	}
}

// TestChaintracksV2HeaderByHashChainLinkage proves hash and previousHash
// share the same (display) byte order: block N+1's previousHash must equal
// block N's hash — mirrors the v1 shim's TestFindHeaderHexChainLinkage.
func TestChaintracksV2HeaderByHashChainLinkage(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 5)

	_, r1 := fetchChaintracks(t, srv, "/chaintracks/v2/header/height/1")
	_, r2 := fetchChaintracks(t, srv, "/chaintracks/v2/header/height/2")
	h1 := r1["value"].(map[string]interface{})["hash"]
	prev2 := r2["value"].(map[string]interface{})["previousHash"]
	if h1 != prev2 {
		t.Fatalf("chain linkage broken in display space: hash(1)=%v prev(2)=%v", h1, prev2)
	}

	_, byHash := fetchChaintracks(t, srv, "/chaintracks/v2/header/hash/"+h1.(string))
	if byHash["value"].(map[string]interface{})["height"].(float64) != 1 {
		t.Fatalf("header/hash/%v: expected height 1, got %#v", h1, byHash["value"])
	}
}

func TestChaintracksV2HeaderByHashMissing(t *testing.T) {
	srv := testServer(t)
	unknown := strings.Repeat("1", 64)
	code, resp := fetchChaintracks(t, srv, "/chaintracks/v2/header/hash/"+unknown)
	if code != http.StatusNotFound || resp["code"] != "ERR_NOT_FOUND" {
		t.Fatalf("expected 404 ERR_NOT_FOUND for unknown hash, got %d %#v", code, resp)
	}
}

func TestChaintracksV2HeaderByHashBadRequest(t *testing.T) {
	srv := testServer(t)
	code, resp := fetchChaintracks(t, srv, "/chaintracks/v2/header/hash/bad")
	if code != http.StatusBadRequest || resp["code"] != "ERR_INVALID_PARAMS" {
		t.Fatalf("expected 400 ERR_INVALID_PARAMS for malformed hash, got %d %#v", code, resp)
	}
}

func TestChaintracksV2HeadersRangeShape(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 10)

	code, resp := fetchChaintracks(t, srv, "/chaintracks/v2/headers?height=2&count=3")
	if code != http.StatusOK || resp["status"] != "success" {
		t.Fatalf("expected success, got %d %#v", code, resp)
	}
	values := resp["value"].([]interface{})
	if len(values) != 3 {
		t.Fatalf("expected 3 headers, got %d", len(values))
	}
	for i, v := range values {
		h := v.(map[string]interface{})
		wantHeight := float64(2 + i)
		if h["height"].(float64) != wantHeight {
			t.Fatalf("header %d: expected height %v, got %v", i, wantHeight, h["height"])
		}
	}
	// Chain-linkage within the range, same check as the single-header test.
	h0 := values[0].(map[string]interface{})
	h1 := values[1].(map[string]interface{})
	if h0["hash"] != h1["previousHash"] {
		t.Fatalf("range linkage broken: hash[0]=%v previousHash[1]=%v", h0["hash"], h1["previousHash"])
	}
}

func TestChaintracksV2HeadersRangeExceedsTip(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 5)

	code, resp := fetchChaintracks(t, srv, "/chaintracks/v2/headers?height=3&count=10")
	if code != http.StatusBadRequest || resp["code"] != "ERR_INVALID_PARAMS" {
		t.Fatalf("expected 400 ERR_INVALID_PARAMS when range exceeds tip, got %d %#v", code, resp)
	}
}

func TestChaintracksV2HeadersRangeExceedsCap(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 5)

	code, resp := fetchChaintracks(t, srv, "/chaintracks/v2/headers?height=0&count="+strconv.Itoa(MaxHeadersRange+1))
	if code != http.StatusBadRequest || resp["code"] != "ERR_INVALID_PARAMS" {
		t.Fatalf("expected 400 ERR_INVALID_PARAMS above MaxHeadersRange, got %d %#v", code, resp)
	}
}

func TestChaintracksV2HeadersRangeBadRequest(t *testing.T) {
	srv := testServer(t)
	for _, path := range []string{
		"/chaintracks/v2/headers",                  // missing both
		"/chaintracks/v2/headers?height=0",         // missing count
		"/chaintracks/v2/headers?height=0&count=0", // count must be >= 1
		"/chaintracks/v2/headers?height=abc&count=1",
	} {
		code, resp := fetchChaintracks(t, srv, path)
		if code != http.StatusBadRequest || resp["code"] != "ERR_INVALID_PARAMS" {
			t.Fatalf("%s: expected 400 ERR_INVALID_PARAMS, got %d %#v", path, code, resp)
		}
	}
}

// TestChaintracksV2PublicAndCORS confirms every v2 route needs no auth token
// and carries permissive CORS, mirroring the v1 shim's
// TestChaintracksPublicAndCORS.
func TestChaintracksV2PublicAndCORS(t *testing.T) {
	srv := testServerNoAuth(t)
	addServerTestChain(t, srv, 2)
	paths := []string{
		"/chaintracks/v2/network",
		"/chaintracks/v2/height",
		"/chaintracks/v2/tip",
		"/chaintracks/v2/header/height/1",
		"/chaintracks/v2/header/hash/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
		"/chaintracks/v2/headers?height=0&count=2",
	}
	for _, path := range paths {
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

// TestChaintracksV2UnderPaymentGate proves openPublic keeps v2 routes off the
// x402 payment gate on a node that charges for reads, mirroring the v1
// shim's TestChaintracksPublicUnderPaymentGate.
func TestChaintracksV2UnderPaymentGate(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 3)
	srv.paymentGate = NewPaymentGate(PaymentGateConfig{
		PriceSats:      100,
		PayeeScriptHex: testPayeeScript(t),
		NonceProvider:  &DevNonceProvider{},
	})
	srv.mux = http.NewServeMux()
	srv.routes()

	// Sanity: a normal openRead path IS gated at this price.
	req := httptest.NewRequest("GET", "/headers/tip", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("/headers/tip: expected 402 under priced gate, got %d", w.Code)
	}

	for _, path := range []string{"/chaintracks/v2/network", "/chaintracks/v2/tip", "/chaintracks/v2/header/height/1"} {
		code, resp := fetchChaintracks(t, srv, path)
		if code != http.StatusOK || resp["status"] != "success" {
			t.Fatalf("%s: expected 200 success under priced payment gate, got %d %#v", path, code, resp)
		}
	}
}

// --- local test helpers (kept separate from the v1 shim's fetchChaintracks,
// which this file also reuses as-is) ---

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
