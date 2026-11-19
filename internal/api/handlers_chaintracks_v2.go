package api

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
	"github.com/syndtr/goleveldb/leveldb"
)

// --- Chaintracks v2: the canonical bsv-blockchain/go-chaintracks HTTP API ---
//
// Distinct from the v1 shim above (handlers_chaintracks.go), which speaks the
// TS SDK's ChaintracksServiceClient dialect (findHeaderHexForHeight, etc.).
// These routes instead match the canonical go-chaintracks server's own wire
// shape — network/tip/header-by-height/header-by-hash/headers — for any
// consumer written against that server directly.
//
// Source of truth (read directly, commit cited for every field/route
// decision): github.com/bsv-blockchain/go-stack, commit
// 3d847bfd461fb2b3f0a5d79cf72d52e977326790, infra/go-chaintracks/cmd/server/api.go
// (routes + Response envelope + error codes) and
// infra/go-chaintracks/chaintracks/types.go (BlockHeader value shape).
// Cross-checked against a real downstream consumer, github.com/lightwebinc/
// bcommon (branch main, commit 34eee57597ccd6ca6a21e2d12bf5e8b07741848a),
// headers/pow.go's wireHeader struct and fullHeader's Chaintracks-kind
// decode (env.Value unwrapped from the envelope before parsing into the
// flat header) — which confirms the server really does send the enveloped
// shape below, resolving an apparent discrepancy where go-chaintracks'
// OWN client package (fetchHeader, both in the v1.2.6 module-cache build
// and the local mirror's current source) decodes the bare HTTP body
// straight into a flat header with no envelope-unwrapping at all: that
// client-side code appears to be a latent bug in the upstream project,
// not evidence the server is unenveloped. bcommon writes its own HTTP
// decode logic rather than relying on it, which is the version this file
// follows.
//
// Two deliberate, cited deviations from the canonical server:
//
//  1. network is hardcoded to "main": Anvil has no testnet config today
//     (cmd/anvil/main.go:1003-1004, "the BRC-100 ecosystem is mainnet-only")
//     and its header store always seeds BSV mainnet genesis
//     (internal/headers/store.go genesisHeaderBytes).
//  2. GET .../headers answers a JSON array of the same enveloped header
//     value, not canonical's raw-binary application/octet-stream
//     (cmd/server/api.go:331-346 HandleGetHeaders + the confirmed binary
//     parsing in both the module-cache and local-mirror client GetHeaders).
//     This spec's own framing groups "headers/bounded range" with the
//     other "JSON field encodings," and every other Anvil route in this
//     file (plus the existing v1 shim and the native /headers/range route)
//     is JSON; serving one route in this family as raw bytes while its
//     siblings are JSON would be a wire-format trap for any client that
//     assumes one convention per path prefix. The .bin suffix routes below
//     serve the canonical raw-binary shape instead, for a consumer that
//     wants it.
//
// range is bounded by MaxHeadersRange (handlers_status.go), the same cap
// the existing native /headers/range route already enforces — canonical's
// own ParseHeightAndCount applies no upper bound at all
// (chaintracks/parse.go:9-22), relying on collectHeaders' natural
// stop-at-tip behavior instead.
//
// SSE (tip/stream, reorg/stream) is NOT implemented: it would need a new
// publish hook into the header-sync loop that does not exist today, which
// is not a small addition.
//
// One addition beyond the canonical route table: GET .../height, a bare
// {"height":N} with no envelope — not canonical's own route, but one a
// real consumer (bcommon's Arcade kind) calls, which the canonical server
// lacks entirely. See handleChaintracksV2Height's doc comment.

// chaintracksV2Header is the 8-field header value the canonical server
// answers: block.Header's six consensus fields plus the height and hash it
// computed. previousHash, merkleRoot and hash are display (big-endian) hex —
// chainhash.Hash.String() performs the wire->display reversal, the same
// convention the v1 shim's chaintracksHeaderFor uses
// (handlers_chaintracks.go:127-139). Kept separate from v1's chaintracksHeader
// type (identical shape today) so the two protocol surfaces can diverge
// independently; they are not the same wire contract.
type chaintracksV2Header struct {
	Version      int32  `json:"version"`
	PreviousHash string `json:"previousHash"`
	MerkleRoot   string `json:"merkleRoot"`
	Time         uint32 `json:"time"`
	Bits         uint32 `json:"bits"`
	Nonce        uint32 `json:"nonce"`
	Height       uint32 `json:"height"`
	Hash         string `json:"hash"`
}

// chaintracksV2Network is the network this node serves (see the deviation
// note above).
const chaintracksV2Network = "main"

// chaintracksV2Response mirrors the canonical server's Response envelope
// exactly (cmd/server/api.go:172-177): status is always present, value is
// omitted on error, code/description are omitted on success.
type chaintracksV2Response struct {
	Status      string `json:"status"`
	Value       any    `json:"value,omitempty"`
	Code        string `json:"code,omitempty"`
	Description string `json:"description,omitempty"`
}

func writeChaintracksV2Value(w http.ResponseWriter, value any) {
	writeJSON(w, http.StatusOK, chaintracksV2Response{Status: "success", Value: value})
}

func writeChaintracksV2Error(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, chaintracksV2Response{Status: "error", Code: code, Description: description})
}

// decodeWireHeaderV2 deserializes a raw 80-byte header, as
// internal/headers.Store returns from HeaderAtHeight/RangeHeaders.
func decodeWireHeaderV2(raw []byte) (wire.BlockHeader, error) {
	var hdr wire.BlockHeader
	if err := hdr.Deserialize(bytes.NewReader(raw)); err != nil {
		return wire.BlockHeader{}, err
	}
	return hdr, nil
}

// chaintracksV2HeaderFor converts hdr into the wire value, exactly as
// chaintracksHeaderFor does for the v1 shim (handlers_chaintracks.go:127-139)
// — the same wire->display reversal, parameterized by the height the store
// placed it at rather than one carried on hdr itself.
func chaintracksV2HeaderFor(hdr wire.BlockHeader, height uint32) chaintracksV2Header {
	hash := hdr.BlockHash()
	return chaintracksV2Header{
		Version:      hdr.Version,
		PreviousHash: hdr.PrevBlock.String(),
		MerkleRoot:   hdr.MerkleRoot.String(),
		Time:         uint32(hdr.Timestamp.Unix()),
		Bits:         hdr.Bits,
		Nonce:        hdr.Nonce,
		Height:       height,
		Hash:         hash.String(),
	}
}

// handleChaintracksV2Height serves GET /chaintracks/v2/height: a bare
// {"height":N}, with NO {status,value} envelope. This route is not part of
// the canonical go-chaintracks server's own route table (cmd/server/api.go
// has no /height at all) — it exists because a real downstream consumer,
// github.com/lightwebinc/bcommon's Arcade kind, calls exactly this path and
// shape under /chaintracks/v2 (headers/source.go's Kind doc comment: "GET
// /height and GET /header/height/{h}, each answering the value bare rather
// than in a status envelope"; headers/chaintracker.go:313-336 CurrentHeight,
// Arcade case, decodes the body straight into
// `struct{ Height *uint32 "json:\"height\"" }` with no envelope-unwrapping).
// header/height/{h} itself keeps the enveloped shape above, matching the
// canonical server, which does define that route.
func (s *Server) handleChaintracksV2Height(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"height": s.headerStore.Tip()})
}

// handleChaintracksV2Network serves GET /chaintracks/v2/network.
// Canonical: cmd/server/api.go:194-204 HandleGetNetwork.
func (s *Server) handleChaintracksV2Network(w http.ResponseWriter, _ *http.Request) {
	writeChaintracksV2Value(w, chaintracksV2Network)
}

// handleChaintracksV2Tip serves GET /chaintracks/v2/tip: the current chain
// tip header. Canonical: cmd/server/api.go:209-224 HandleGetTip.
//
// Unlike canonical (whose ct.GetTip() can return nil before anything has
// synced), Anvil's header store always holds at least genesis
// (internal/headers/store.go writeGenesis), so a lookup failure here is a
// genuine store fault, not "no tip yet" — reported as ERR_INTERNAL rather
// than canonical's ERR_NO_TIP, which would misdescribe the cause.
func (s *Server) handleChaintracksV2Tip(w http.ResponseWriter, _ *http.Request) {
	height := s.headerStore.Tip()
	raw, err := s.headerStore.HeaderAtHeight(height)
	if err != nil {
		writeChaintracksV2Error(w, http.StatusInternalServerError, "ERR_INTERNAL", "chain tip header read failed")
		return
	}
	hdr, err := decodeWireHeaderV2(raw)
	if err != nil {
		writeChaintracksV2Error(w, http.StatusInternalServerError, "ERR_INTERNAL", "header decode failed")
		return
	}
	writeChaintracksV2Value(w, chaintracksV2HeaderFor(hdr, height))
}

// handleChaintracksV2HeaderByHeight serves GET
// /chaintracks/v2/header/height/{height}. Canonical:
// cmd/server/api.go:275-289 HandleGetHeaderByHeight.
func (s *Server) handleChaintracksV2HeaderByHeight(w http.ResponseWriter, r *http.Request) {
	heightStr := r.PathValue("height")
	height64, err := strconv.ParseUint(heightStr, 10, 32)
	if err != nil {
		writeChaintracksV2Error(w, http.StatusBadRequest, "ERR_INVALID_PARAMS", "invalid parameter: height")
		return
	}
	height := uint32(height64)

	raw, err := s.headerStore.HeaderAtHeight(height)
	if errors.Is(err, leveldb.ErrNotFound) {
		writeChaintracksV2Error(w, http.StatusNotFound, "ERR_NOT_FOUND", "Header not found at height "+heightStr)
		return
	}
	if err != nil {
		writeChaintracksV2Error(w, http.StatusInternalServerError, "ERR_INTERNAL", "header store read failed")
		return
	}
	hdr, err := decodeWireHeaderV2(raw)
	if err != nil {
		writeChaintracksV2Error(w, http.StatusInternalServerError, "ERR_INTERNAL", "header decode failed")
		return
	}
	writeChaintracksV2Value(w, chaintracksV2HeaderFor(hdr, height))
}

// handleChaintracksV2HeaderByHash serves GET
// /chaintracks/v2/header/hash/{hash} (display-order hex). Canonical:
// cmd/server/api.go:303-318 HandleGetHeaderByHash.
func (s *Server) handleChaintracksV2HeaderByHash(w http.ResponseWriter, r *http.Request) {
	hashStr := r.PathValue("hash")
	// NewHashFromStr alone is not a sufficient length check (confirmed by a
	// failing test against "bad": it does not reject a too-short string the
	// way the v1 shim's explicit precondition does) — same guard as
	// handlers_chaintracks.go:88-91.
	if len(hashStr) != 64 {
		writeChaintracksV2Error(w, http.StatusBadRequest, "ERR_INVALID_PARAMS", "invalid parameter: hash")
		return
	}
	hash, err := chainhash.NewHashFromStr(hashStr)
	if err != nil {
		writeChaintracksV2Error(w, http.StatusBadRequest, "ERR_INVALID_PARAMS", "invalid parameter: hash")
		return
	}

	height, err := s.headerStore.HeightForHash(hash)
	if errors.Is(err, leveldb.ErrNotFound) {
		writeChaintracksV2Error(w, http.StatusNotFound, "ERR_NOT_FOUND", "Header not found for hash "+hashStr)
		return
	}
	if err != nil {
		writeChaintracksV2Error(w, http.StatusInternalServerError, "ERR_INTERNAL", "header store read failed")
		return
	}
	raw, err := s.headerStore.HeaderAtHeight(height)
	if errors.Is(err, leveldb.ErrNotFound) {
		writeChaintracksV2Error(w, http.StatusNotFound, "ERR_NOT_FOUND", "Header not found for hash "+hashStr)
		return
	}
	if err != nil {
		writeChaintracksV2Error(w, http.StatusInternalServerError, "ERR_INTERNAL", "header store read failed")
		return
	}
	hdr, err := decodeWireHeaderV2(raw)
	if err != nil {
		writeChaintracksV2Error(w, http.StatusInternalServerError, "ERR_INTERNAL", "header decode failed")
		return
	}
	if hdr.BlockHash() != *hash {
		// The hash index can lag an active-chain reorg — same race the v1
		// shim's handleFindHeaderHexForBlockHash guards against
		// (handlers_chaintracks.go:120-123).
		writeChaintracksV2Error(w, http.StatusNotFound, "ERR_NOT_FOUND", "Header not found for hash "+hashStr)
		return
	}
	writeChaintracksV2Value(w, chaintracksV2HeaderFor(hdr, height))
}

// handleChaintracksV2Headers serves GET
// /chaintracks/v2/headers?height=N&count=M: count consecutive headers from
// height, as a JSON array (see the deviation note above). Canonical:
// cmd/server/api.go:330-346 HandleGetHeaders (there, raw-binary).
func (s *Server) handleChaintracksV2Headers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	heightStr, countStr := q.Get("height"), q.Get("count")
	if heightStr == "" || countStr == "" {
		writeChaintracksV2Error(w, http.StatusBadRequest, "ERR_INVALID_PARAMS", "missing parameter: height or count")
		return
	}
	height64, err := strconv.ParseUint(heightStr, 10, 32)
	if err != nil {
		writeChaintracksV2Error(w, http.StatusBadRequest, "ERR_INVALID_PARAMS", "invalid parameter: height")
		return
	}
	count64, err := strconv.ParseUint(countStr, 10, 32)
	if err != nil {
		writeChaintracksV2Error(w, http.StatusBadRequest, "ERR_INVALID_PARAMS", "invalid parameter: count")
		return
	}
	height, count := uint32(height64), uint32(count64)
	if count < 1 {
		writeChaintracksV2Error(w, http.StatusBadRequest, "ERR_INVALID_PARAMS", "count must be >= 1")
		return
	}
	if count > MaxHeadersRange {
		writeChaintracksV2Error(w, http.StatusBadRequest, "ERR_INVALID_PARAMS", fmt.Sprintf("count must be <= %d", MaxHeadersRange))
		return
	}

	raws, tip, err := s.headerStore.RangeHeaders(height, count)
	if errors.Is(err, headers.ErrRangeExceedsTip) {
		writeChaintracksV2Error(w, http.StatusBadRequest, "ERR_INVALID_PARAMS",
			fmt.Sprintf("range exceeds local tip %d", tip))
		return
	}
	if err != nil {
		writeChaintracksV2Error(w, http.StatusInternalServerError, "ERR_INTERNAL", "header read failed")
		return
	}

	values := make([]chaintracksV2Header, len(raws))
	for i, raw := range raws {
		hdr, err := decodeWireHeaderV2(raw)
		if err != nil {
			writeChaintracksV2Error(w, http.StatusInternalServerError, "ERR_INTERNAL", "header decode failed")
			return
		}
		values[i] = chaintracksV2HeaderFor(hdr, height+uint32(i))
	}
	writeChaintracksV2Value(w, values)
}
