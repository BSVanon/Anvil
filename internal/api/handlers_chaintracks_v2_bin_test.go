package api

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// TestChaintracksV2TipBinary cross-checks /tip.bin's raw 80 bytes against the
// JSON /tip route's own fields, and against canonical's handleGetTipBinary
// (routes/fiber/routes.go:548-560) header/status contract.
func TestChaintracksV2TipBinary(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 4)

	code, hdr, data := fetchBareBytes(t, srv, "/chaintracks/v2/tip.bin")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if len(data) != 80 {
		t.Fatalf("expected 80 raw bytes, got %d", len(data))
	}
	if got := hdr.Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("Content-Type = %q, want application/octet-stream", got)
	}
	if got := hdr.Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("Cache-Control = %q, want no-cache (tip can still reorg)", got)
	}
	if got := hdr.Get("X-Block-Height"); got != "4" {
		t.Fatalf("X-Block-Height = %q, want 4", got)
	}

	decoded, err := decodeWireHeaderV2(data)
	if err != nil {
		t.Fatalf("decode raw tip.bin bytes: %v", err)
	}
	_, _, jsonBody := fetchBareJSON(t, srv, "/chaintracks/v2/tip")
	gotHash := decoded.BlockHash()
	if gotHash.String() != jsonBody["hash"] {
		t.Fatalf("tip.bin hash %s != tip JSON hash %v", gotHash.String(), jsonBody["hash"])
	}
}

// TestChaintracksV2HeaderByHeightBinary proves the raw bytes at a height
// equal exactly what the store holds, and that the ".bin" suffix-sniff
// (handlers_chaintracks_v2.go:172-177) reaches
// handleChaintracksV2HeaderByHeightBinary (handlers_chaintracks_v2_bin.go
// :48-70, canonical: routes/fiber/routes.go:562-581).
func TestChaintracksV2HeaderByHeightBinary(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 5)

	want, err := srv.headerStore.HeaderAtHeight(2)
	if err != nil {
		t.Fatal(err)
	}

	code, hdr, data := fetchBareBytes(t, srv, "/chaintracks/v2/header/height/2.bin")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if string(data) != string(want) {
		t.Fatal("header/height/2.bin bytes do not match the store's raw bytes")
	}
	if got := hdr.Get("X-Block-Height"); got != "2" {
		t.Fatalf("X-Block-Height = %q, want 2", got)
	}
	if got := hdr.Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("Content-Type = %q, want application/octet-stream", got)
	}
}

// TestChaintracksV2HeaderByHeightBinaryCacheControl exercises both branches
// of setCacheControlV2 (handlers_chaintracks_v2.go:109-116) through the
// binary route: far-below-tip is cacheable, near-tip is not — canonical:
// routes/fiber/routes.go:447-455 setCacheControl.
func TestChaintracksV2HeaderByHeightBinaryCacheControl(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 150)

	_, farHdr, _ := fetchBareBytes(t, srv, "/chaintracks/v2/header/height/10.bin")
	if got := farHdr.Get("Cache-Control"); got != "public, max-age=3600" {
		t.Fatalf("height 10 (tip-140): Cache-Control = %q, want public, max-age=3600", got)
	}

	_, nearHdr, _ := fetchBareBytes(t, srv, "/chaintracks/v2/header/height/145.bin")
	if got := nearHdr.Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("height 145 (tip-5): Cache-Control = %q, want no-cache", got)
	}
}

// TestChaintracksV2HeaderByHeightBinaryErrors proves error paths on the
// binary route stay bare JSON, not raw bytes — canonical's binary handlers
// still call c.JSON(fiber.Map{"error":...}) on failure.
func TestChaintracksV2HeaderByHeightBinaryErrors(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 3)

	code, hdr, body := fetchBareJSON(t, srv, "/chaintracks/v2/header/height/999.bin")
	if code != http.StatusNotFound || body["error"] != "Header not found" {
		t.Fatalf("missing height: expected 404 bare JSON, got %d %#v", code, body)
	}
	if got := hdr.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("error body Content-Type = %q, want application/json", got)
	}

	code, _, body = fetchBareJSON(t, srv, "/chaintracks/v2/header/height/abc.bin")
	if code != http.StatusBadRequest || body["error"] != "Invalid height parameter" {
		t.Fatalf("bad height: expected 400 bare JSON, got %d %#v", code, body)
	}
}

// TestChaintracksV2HeaderByHashBinary mirrors the height variant for the
// hash route (handlers_chaintracks_v2_bin.go:76-121, canonical: routes.go
// :584-602).
func TestChaintracksV2HeaderByHashBinary(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 5)

	h3, err := srv.headerStore.HashAtHeight(3)
	if err != nil {
		t.Fatal(err)
	}
	want, err := srv.headerStore.HeaderAtHeight(3)
	if err != nil {
		t.Fatal(err)
	}

	code, hdr, data := fetchBareBytes(t, srv, "/chaintracks/v2/header/hash/"+h3.String()+".bin")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if string(data) != string(want) {
		t.Fatal("header/hash/{h}.bin bytes do not match the store's raw bytes")
	}
	if got := hdr.Get("X-Block-Height"); got != "3" {
		t.Fatalf("X-Block-Height = %q, want 3", got)
	}
}

func TestChaintracksV2HeaderByHashBinaryErrors(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 3)

	unknown := strings.Repeat("1", 64)
	code, _, body := fetchBareJSON(t, srv, "/chaintracks/v2/header/hash/"+unknown+".bin")
	if code != http.StatusNotFound || body["error"] != "Header not found" {
		t.Fatalf("missing hash: expected 404 bare JSON, got %d %#v", code, body)
	}

	code, _, body = fetchBareJSON(t, srv, "/chaintracks/v2/header/hash/bad.bin")
	if code != http.StatusBadRequest || body["error"] != "Invalid hash parameter" {
		t.Fatalf("bad hash: expected 400 bare JSON, got %d %#v", code, body)
	}
}

// TestChaintracksV2HeadersBinary proves headers.bin's body is byte-identical
// to plain /headers for the same range, plus the two extra headers canonical
// sets (routes.go:604-620 handleGetHeadersBinary).
func TestChaintracksV2HeadersBinary(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 10)

	_, _, plain := fetchBareBytes(t, srv, "/chaintracks/v2/headers?height=1&count=4")
	code, hdr, binData := fetchBareBytes(t, srv, "/chaintracks/v2/headers.bin?height=1&count=4")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if string(binData) != string(plain) {
		t.Fatal("headers.bin body differs from plain /headers for the same range")
	}
	if got := hdr.Get("X-Start-Height"); got != "1" {
		t.Fatalf("X-Start-Height = %q, want 1", got)
	}
	if got := hdr.Get("X-Header-Count"); got != "4" {
		t.Fatalf("X-Header-Count = %q, want 4", got)
	}
}

// TestChaintracksV2HeadersBinaryTruncatesAndClamps proves headers.bin shares
// chaintracksV2RawHeaders' truncate/clamp-not-reject behavior with plain
// /headers (same underlying helper, see handlers_chaintracks_v2_headers_test.go
// for the dedicated coverage of that helper), and that its extra
// X-Header-Count header reports the actual (possibly truncated/clamped)
// count, not the originally requested one.
func TestChaintracksV2HeadersBinaryTruncatesAndClamps(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 5) // chain is heights 0..5, tip=5

	// height=3,count=10 would run past tip — truncated to heights 3,4,5 (3
	// headers), not rejected.
	code, hdr, data := fetchBareBytes(t, srv, "/chaintracks/v2/headers.bin?height=3&count=10")
	if code != http.StatusOK {
		t.Fatalf("range exceeding tip: expected 200, got %d", code)
	}
	const wantNearTip = 3
	if len(data) != wantNearTip*80 {
		t.Fatalf("range exceeding tip: expected %d headers (%d bytes), got %d bytes", wantNearTip, wantNearTip*80, len(data))
	}
	if got := hdr.Get("X-Header-Count"); got != strconv.Itoa(wantNearTip) {
		t.Fatalf("X-Header-Count = %q, want %q (the truncated count, not the requested 10)", got, strconv.Itoa(wantNearTip))
	}

	// count above this route's own cap is clamped, not rejected; on this
	// 6-header chain the tip truncation also applies, confirming the two
	// bounds compose (neither one masks the other).
	code, hdr, data = fetchBareBytes(t, srv, "/chaintracks/v2/headers.bin?height=0&count="+strconv.Itoa(chaintracksV2MaxHeadersRange+1))
	if code != http.StatusOK {
		t.Fatalf("range above cap: expected 200, got %d", code)
	}
	const wantWholeChain = 6
	if len(data) != wantWholeChain*80 {
		t.Fatalf("range above cap: expected %d headers (%d bytes), got %d bytes", wantWholeChain, wantWholeChain*80, len(data))
	}
	if got := hdr.Get("X-Header-Count"); got != strconv.Itoa(wantWholeChain) {
		t.Fatalf("X-Header-Count = %q, want %q", got, strconv.Itoa(wantWholeChain))
	}
}

// TestChaintracksV2BinaryRoutesPublicNoAuth confirms the .bin routes need no
// token, same as their JSON counterparts.
func TestChaintracksV2BinaryRoutesPublicNoAuth(t *testing.T) {
	srv := testServerNoAuth(t)
	addServerTestChain(t, srv, 2)
	for _, path := range []string{
		"/chaintracks/v2/tip.bin",
		"/chaintracks/v2/header/height/1.bin",
		"/chaintracks/v2/headers.bin?height=0&count=2",
	} {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: expected 200 without auth, got %d", path, w.Code)
		}
	}
}
