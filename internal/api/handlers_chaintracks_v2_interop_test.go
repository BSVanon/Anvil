package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/block"
)

// --- Chaintracks v2 interop tests ---
//
// These port the decode paths of the canonical bsv-blockchain/go-chaintracks
// Go client (client.go) against Anvil's own /chaintracks/v2 routes, run
// through a real httptest.Server so each request takes the genuine HTTP
// round trip. interopGetHeaders specifically decodes with go-sdk's own
// block.NewHeaderFromBytes (go-sdk is already an Anvil dependency; nothing
// new added to go.mod/go.sum) rather than Anvil's internal
// decodeWireHeaderV2, so the chain-linkage and PoW checks below are proven
// against an independent decoder, not Anvil testing itself.
//
// Operators: clients of this Arcade-embedded chaintracks v2 dialect point
// at https://<node>, or at https://<node>/chaintracks for the
// go-chaintracks client (whose own per-call paths already add "/v2").

// interopBlockHeader mirrors the 8-field shape the canonical client decodes
// a header response into (chaintracks/types.go:10-17's BlockHeader, which
// embeds *block.Header plus Height/Hash) — declared independently of
// chaintracksV2Header (handlers_chaintracks_v2.go) so this file checks its
// own, separately-stated expectation of the wire shape rather than reusing
// the production type under test.
type interopBlockHeader struct {
	Version      int32  `json:"version"`
	PreviousHash string `json:"previousHash"`
	MerkleRoot   string `json:"merkleRoot"`
	Time         uint32 `json:"time"`
	Bits         uint32 `json:"bits"`
	Nonce        uint32 `json:"nonce"`
	Height       uint32 `json:"height"`
	Hash         string `json:"hash"`
}

// interopFetchHeader ports client.go:487-500 fetchHeader: GET url, decode
// the bare JSON body straight into the header struct (no envelope-unwrap).
func interopFetchHeader(t *testing.T, ts *httptest.Server, path string) interopBlockHeader {
	t.Helper()
	resp, err := http.Get(ts.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", path, resp.StatusCode)
	}
	var hdr interopBlockHeader
	if err := json.NewDecoder(resp.Body).Decode(&hdr); err != nil {
		t.Fatalf("GET %s: decode: %v", path, err)
	}
	return hdr
}

// interopGetNetwork ports client.go:517-546 GetNetwork: GET /network,
// decode bare {"network":"..."}. Canonically an empty network string is
// itself an error (ErrServerReturnedError) distinct from a transport
// failure, so this checks for that explicitly rather than just decoding.
func interopGetNetwork(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	resp, err := http.Get(ts.URL + "/chaintracks/v2/network")
	if err != nil {
		t.Fatalf("GetNetwork: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetNetwork: status %d", resp.StatusCode)
	}
	var body struct {
		Network string `json:"network"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("GetNetwork: decode: %v", err)
	}
	if body.Network == "" {
		t.Fatal("GetNetwork: empty network is itself a canonical client error")
	}
	return body.Network
}

// interopGetHeight decodes GET /height's bare {"height":N}. Note this is
// NOT a route the canonical client itself calls — its own GetHeight
// (client.go:406-412) derives the height from GetTip()/fetchTip
// (client.go:415-417) instead. /height exists for the other, non-canonical
// "bcommon Arcade kind" consumer the canon decision identified; it is still
// exercised directly here since Anvil serves it for that consumer.
func interopGetHeight(t *testing.T, ts *httptest.Server) uint32 {
	t.Helper()
	resp, err := http.Get(ts.URL + "/chaintracks/v2/height")
	if err != nil {
		t.Fatalf("height: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("height: status %d", resp.StatusCode)
	}
	var body struct {
		Height uint32 `json:"height"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("height: decode: %v", err)
	}
	return body.Height
}

// interopGetHeaders ports client.go:452-484 GetHeaders exactly: GET
// /headers?height=N&count=M, io.ReadAll the raw body, require its length is
// a multiple of 80 (client.go:465-467's own check), then parse each 80-byte
// chunk with go-sdk's block.NewHeaderFromBytes — the same decode a real
// go-sdk-based consumer uses, not Anvil's internal wire.BlockHeader.
func interopGetHeaders(t *testing.T, ts *httptest.Server, height, count uint32) []*block.Header {
	t.Helper()
	path := fmt.Sprintf("/chaintracks/v2/headers?height=%d&count=%d", height, count)
	resp, err := http.Get(ts.URL + path)
	if err != nil {
		t.Fatalf("GetHeaders: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetHeaders: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("GetHeaders: read body: %v", err)
	}
	if len(data)%80 != 0 {
		t.Fatalf("GetHeaders: response length %d not a multiple of 80", len(data))
	}
	var out []*block.Header
	for i := 0; i < len(data); i += 80 {
		h, err := block.NewHeaderFromBytes(data[i : i+80])
		if err != nil {
			t.Fatalf("GetHeaders: parse header at offset %d: %v", i, err)
		}
		out = append(out, h)
	}
	return out
}

// TestInteropFetchHeaderByHeightAndHash proves the ported fetchHeader path
// round-trips through tip, header/height and header/hash consistently.
func TestInteropFetchHeaderByHeightAndHash(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 5)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	tip := interopFetchHeader(t, ts, "/chaintracks/v2/tip")
	if tip.Height != 5 {
		t.Fatalf("tip height = %d, want 5", tip.Height)
	}

	byHeight := interopFetchHeader(t, ts, "/chaintracks/v2/header/height/3")
	if byHeight.Height != 3 {
		t.Fatalf("header/height/3: height = %d, want 3", byHeight.Height)
	}

	byHash := interopFetchHeader(t, ts, "/chaintracks/v2/header/hash/"+byHeight.Hash)
	if byHash.Height != 3 || byHash.Hash != byHeight.Hash {
		t.Fatalf("header/hash round-trip mismatch: %#v vs %#v", byHash, byHeight)
	}
}

func TestInteropGetNetworkAndHeight(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 4)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	if got := interopGetNetwork(t, ts); got != "main" {
		t.Fatalf("GetNetwork = %q, want main", got)
	}
	if got := interopGetHeight(t, ts); got != 4 {
		t.Fatalf("height = %d, want 4", got)
	}
}

// TestInteropGetHeaders80ByteChunksViaGoSDK proves the raw /headers bytes
// parse correctly under an independent decoder (go-sdk's block package),
// that chain linkage holds across the parsed chunks, and that the resulting
// hash agrees with the JSON route's own view of the same height — a PoW
// cross-check distinct from TestChaintracksV2HeaderPoWFieldsReserializeToHash
// (handlers_chaintracks_v2_test.go), which reserializes by hand instead of
// via go-sdk.
func TestInteropGetHeaders80ByteChunksViaGoSDK(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 10)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	hdrs := interopGetHeaders(t, ts, 2, 3)
	if len(hdrs) != 3 {
		t.Fatalf("expected 3 headers, got %d", len(hdrs))
	}

	h0 := hdrs[0].Hash()
	if h0 != hdrs[1].PrevHash {
		t.Fatalf("linkage broken: hash[0]=%s prevHash[1]=%s", h0.String(), hdrs[1].PrevHash.String())
	}
	h1 := hdrs[1].Hash()
	if h1 != hdrs[2].PrevHash {
		t.Fatalf("linkage broken: hash[1]=%s prevHash[2]=%s", h1.String(), hdrs[2].PrevHash.String())
	}

	jsonHdr := interopFetchHeader(t, ts, "/chaintracks/v2/header/height/2")
	if h0.String() != jsonHdr.Hash {
		t.Fatalf("go-sdk-decoded hash %s != JSON route hash %s", h0.String(), jsonHdr.Hash)
	}
}

// TestChaintracksV2HeaderByHeightGoldenBytes pins the exact response body
// bytes for the one header value that is fully deterministic across every
// test run — the real BSV mainnet genesis header (internal/headers/store.go
// genesisHeaderBytes) at height 0, not a synthetic addServerTestChain
// fixture — catching any regression in the bare dialect's exact wire format
// (field order, casing, a reintroduced envelope, stray whitespace) that a
// field-by-field map assertion could miss.
func TestChaintracksV2HeaderByHeightGoldenBytes(t *testing.T) {
	srv := testServer(t)

	want, err := json.Marshal(chaintracksV2Header{
		Version:      1,
		PreviousHash: strings.Repeat("0", 64),
		MerkleRoot:   "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
		Time:         1231006505,
		Bits:         0x1d00ffff,
		Nonce:        2083236893,
		Height:       0,
		Hash:         "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
	})
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n') // writeJSON uses json.NewEncoder, which newline-terminates.

	req := httptest.NewRequest("GET", "/chaintracks/v2/header/height/0", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !bytes.Equal(w.Body.Bytes(), want) {
		t.Fatalf("golden byte mismatch:\n got  %s\n want %s", w.Body.String(), want)
	}
}
