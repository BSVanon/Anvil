package api

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// Split out of handlers_chaintracks_v2_test.go to keep both files under the
// 400-line bespoke cap: the /headers range route, plus the two cross-cutting
// sweeps (public/CORS, payment-gate exemption) that touch every v2 route
// including /headers.

// TestChaintracksV2HeadersRangeBytes proves /headers now matches canonical's
// raw-binary shape exactly (routes/fiber/routes.go:522-544), not the JSON
// array the pre-fix build served.
func TestChaintracksV2HeadersRangeBytes(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 10)

	code, hdr, data := fetchBareBytes(t, srv, "/chaintracks/v2/headers?height=2&count=3")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if got := hdr.Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("Content-Type = %q, want application/octet-stream", got)
	}
	if len(data) != 3*80 {
		t.Fatalf("expected 240 raw bytes (3*80), got %d", len(data))
	}

	hdr1, err := decodeWireHeaderV2(data[0:80])
	if err != nil {
		t.Fatal(err)
	}
	hdr2, err := decodeWireHeaderV2(data[80:160])
	if err != nil {
		t.Fatal(err)
	}
	// Chain-linkage within the range, same check as the single-header test.
	h1 := hdr1.BlockHash()
	if h1 != hdr2.PrevBlock {
		t.Fatalf("range linkage broken: hash[0]=%s previousHash[1]=%s", h1.String(), hdr2.PrevBlock.String())
	}
}

// TestChaintracksV2HeadersTruncatesNearTip proves a range reaching past the
// tip is truncated to what exists, not rejected — canonical's collectHeaders
// (routes/fiber/routes.go:458-469) simply stops at the first missing height
// and still answers 200 with whatever it collected. Replaces the pre-fix
// behavior (a hard 400 once the request ran past tip, inherited from the
// native /headers/range route's stricter contract).
func TestChaintracksV2HeadersTruncatesNearTip(t *testing.T) {
	srv := testServer(t)
	tip := addServerTestChain(t, srv, 10)

	// height=5, count=20 would run to height 24, but the chain only goes to
	// 10 — expect exactly heights 5..10 (6 headers), not an error.
	code, _, data := fetchBareBytes(t, srv, "/chaintracks/v2/headers?height=5&count=20")
	if code != http.StatusOK {
		t.Fatalf("truncation near tip: expected 200, got %d", code)
	}
	wantCount := int(tip) - 5 + 1
	if len(data) != wantCount*80 {
		t.Fatalf("expected %d truncated headers (%d bytes), got %d bytes", wantCount, wantCount*80, len(data))
	}
	lastHdr, err := decodeWireHeaderV2(data[len(data)-80:])
	if err != nil {
		t.Fatal(err)
	}
	wantHash, err := srv.headerStore.HashAtHeight(tip)
	if err != nil {
		t.Fatal(err)
	}
	if got := lastHdr.BlockHash(); got != *wantHash {
		t.Fatalf("last truncated header hash = %s, want tip hash %s", got, wantHash)
	}
}

// TestChaintracksV2HeadersPastTipIsEmptyOK proves a height already past the
// local tip answers 200 with zero headers, matching canonical exactly:
// collectHeaders' very first GetHeaderByHeight call fails immediately, the
// loop breaks before collecting anything, and handleGetHeaders still
// answers c.Send(data) on that empty data — 200, never 400 or 404.
func TestChaintracksV2HeadersPastTipIsEmptyOK(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 5) // tip = 5

	code, hdr, data := fetchBareBytes(t, srv, "/chaintracks/v2/headers?height=10&count=5")
	if code != http.StatusOK {
		t.Fatalf("height past tip: expected 200, got %d", code)
	}
	if len(data) != 0 {
		t.Fatalf("height past tip: expected 0 bytes, got %d", len(data))
	}
	if got := hdr.Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("Content-Type = %q, want application/octet-stream even for an empty body", got)
	}
}

// TestChaintracksV2HeadersCountClampedNotRejected covers the task's three
// named count values: 51 (above the native /headers/range route's
// MaxHeadersRange=50, but this route has its own, higher bound and must not
// reuse that one), 2000 (exactly at chaintracksV2MaxHeadersRange), and 5000
// (above it, clamped down to chaintracksV2MaxHeadersRange, never rejected).
// Canonical's own ParseHeightAndCount has no upper bound at all
// (chaintracks/parse.go:9-22); this route keeps a bound for memory safety,
// but enforces it by clamping, not erroring.
func TestChaintracksV2HeadersCountClampedNotRejected(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, chaintracksV2MaxHeadersRange+500)

	tests := []struct {
		name      string
		count     int
		wantCount int
	}{
		{name: "count=51 above the native route's 50-cap", count: 51, wantCount: 51},
		{name: "count=2000 exactly at this route's cap", count: 2000, wantCount: chaintracksV2MaxHeadersRange},
		{name: "count=5000 clamped to this route's cap", count: 5000, wantCount: chaintracksV2MaxHeadersRange},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := "/chaintracks/v2/headers?height=0&count=" + strconv.Itoa(tc.count)
			code, _, data := fetchBareBytes(t, srv, path)
			if code != http.StatusOK {
				t.Fatalf("expected 200, got %d", code)
			}
			if len(data) != tc.wantCount*80 {
				t.Fatalf("expected %d headers (%d bytes), got %d bytes", tc.wantCount, tc.wantCount*80, len(data))
			}
		})
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
		code, _, body := fetchBareJSON(t, srv, path)
		if code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d %#v", path, code, body)
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
		"/chaintracks/v2/tip.bin",
		"/chaintracks/v2/header/height/1",
		"/chaintracks/v2/header/height/1.bin",
		"/chaintracks/v2/header/hash/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
		"/chaintracks/v2/header/hash/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f.bin",
		"/chaintracks/v2/headers?height=0&count=2",
		"/chaintracks/v2/headers.bin?height=0&count=2",
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
		code, _, body := fetchBareJSON(t, srv, path)
		if code != http.StatusOK {
			t.Fatalf("%s: expected 200 under priced payment gate, got %d %#v", path, code, body)
		}
	}
}
