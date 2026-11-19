package api

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
	"github.com/syndtr/goleveldb/leveldb"
)

// --- Chaintracks v2: the canonical bsv-blockchain/go-chaintracks HTTP API ---
//
// Distinct from the v1 shim above (handlers_chaintracks.go), which speaks the
// TS SDK's ChaintracksServiceClient dialect (findHeaderHexForHeight, etc.).
//
// Canon decision: go-chaintracks ships TWO v2 dialects. The standalone
// server (cmd/server/api.go, mounted at /v2) wraps every value in a
// {status,value,code,description} envelope. The embeddable route set
// (routes/fiber/routes.go) — what an Arcade installation mounts at
// /chaintracks/v2, the exact path Anvil uses — answers BARE values, with
// errors as a plain {"error":"..."}. Anvil mounts at /chaintracks/v2, so
// routes/fiber/routes.go is the authority for every route in this file and
// its _bin.go / _sse.go siblings — NOT cmd/server/api.go. (The response
// VALUES are the same 8-field BlockHeader JSON either way; only the wrapper
// differs.)
//
// Source of truth (read directly, commit cited for every field/route
// decision): github.com/bsv-blockchain/go-stack, commit
// 3d847bfd461fb2b3f0a5d79cf72d52e977326790, local mirror at
// infra/go-chaintracks/routes/fiber/routes.go. Every handler below cites its
// canonical line range.
//
// Field encodings carried over unchanged from the v1 shim and the prior
// enveloped build of this file: previousHash/merkleRoot/hash are display
// (big-endian) hex via chainhash.Hash.String()'s wire->display reversal.
//
// One deliberate, cited deviation from canonical: /headers is bounded by
// Anvil's existing MaxHeadersRange (50) and hard-errors past the local tip,
// instead of canonical's unbounded ParseHeightAndCount (chaintracks/parse.go
// :9-22, no upper bound) + collectHeaders' silent stop-at-tip truncation
// (routes.go:458-469). This matches the existing native /headers/range route
// and is a stricter, not looser, contract — kept per the spec's allowance to
// keep Anvil's stricter caps.
//
// network is hardcoded to "main": Anvil has no testnet config today
// (cmd/anvil/main.go, "the BRC-100 ecosystem is mainnet-only") and its header
// store always seeds BSV mainnet genesis (internal/headers/store.go
// genesisHeaderBytes).

// chaintracksV2Header is the 8-field header value every JSON-bodied route
// answers: block.Header's six consensus fields plus the height and hash the
// store computed. previousHash, merkleRoot and hash are display (big-endian)
// hex. Canonical shape: routes/fiber/routes.go's c.JSON(header) on a
// chaintracks.BlockHeader (chaintracks/types.go:10-17), whose embedded
// *block.Header + Height + Hash fields serialize to exactly these 8 JSON
// keys.
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

// setCacheControlV2 mirrors canonical's setCacheControl (routes.go:448-455):
// a header more than 100 blocks below the tip is immutable (cacheable an
// hour); anything newer can still be reorged out, so it is never cached.
func (s *Server) setCacheControlV2(w http.ResponseWriter, height uint32) {
	tip := s.headerStore.Tip()
	if tip > 100 && height < tip-100 {
		w.Header().Set("Cache-Control", "public, max-age=3600")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
}

// handleChaintracksV2Network serves GET /chaintracks/v2/network, bare.
// Canonical: routes/fiber/routes.go:290-304 handleGetNetwork.
func (s *Server) handleChaintracksV2Network(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"network": chaintracksV2Network})
}

// handleChaintracksV2Height serves GET /chaintracks/v2/height, bare, with
// the same Cache-Control canonical sets. Canonical:
// routes/fiber/routes.go:306-316 handleGetHeight.
func (s *Server) handleChaintracksV2Height(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=60")
	writeJSON(w, http.StatusOK, map[string]any{"height": s.headerStore.Tip()})
}

// handleChaintracksV2Tip serves GET /chaintracks/v2/tip: the current chain
// tip header, bare, with X-Block-Height set. Canonical:
// routes/fiber/routes.go:318-334 handleGetTip.
//
// Unlike canonical (whose GetTip() can return nil before anything has
// synced), Anvil's header store always holds at least genesis
// (internal/headers/store.go writeGenesis), so a lookup failure here is a
// genuine store fault, reported as 500 rather than canonical's 404 "Chain
// tip not found" (which would misdescribe an Anvil store fault as "nothing
// synced yet"). The 404 shape is kept reachable in principle: a bare
// {"error":"Chain tip not found"} would match routes.go:328-331 exactly.
func (s *Server) handleChaintracksV2Tip(w http.ResponseWriter, _ *http.Request) {
	height := s.headerStore.Tip()
	raw, err := s.headerStore.HeaderAtHeight(height)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "chain tip header read failed")
		return
	}
	hdr, err := decodeWireHeaderV2(raw)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "header decode failed")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Block-Height", strconv.FormatUint(uint64(height), 10))
	writeJSON(w, http.StatusOK, chaintracksV2HeaderFor(hdr, height))
}

// handleChaintracksV2HeaderByHeight serves GET
// /chaintracks/v2/header/height/{height}, bare. Canonical:
// routes/fiber/routes.go:471-494 handleGetHeaderByHeight.
//
// Also the entry point for GET .../header/height/{height}.bin
// (routes.go:562-581 handleGetHeaderByHeightBinary): net/http.ServeMux
// wildcards must span a whole path segment, so a literal ".bin" suffix on
// the same segment cannot be a second, separately-registered pattern the
// way Fiber's router allows canonically. This handler is the one registered
// for the segment either way and parses the ".bin" suffix itself (see
// handlers_chaintracks_v2_bin.go), matching the spec's own note that Go's
// mux needs suffix-sniffing inside the wildcard handler.
func (s *Server) handleChaintracksV2HeaderByHeight(w http.ResponseWriter, r *http.Request) {
	heightStr := r.PathValue("height")
	if trimmed, isBin := strings.CutSuffix(heightStr, ".bin"); isBin {
		s.handleChaintracksV2HeaderByHeightBinary(w, trimmed)
		return
	}
	height64, err := strconv.ParseUint(heightStr, 10, 32)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid height parameter")
		return
	}
	height := uint32(height64)

	s.setCacheControlV2(w, height)

	raw, err := s.headerStore.HeaderAtHeight(height)
	if errors.Is(err, leveldb.ErrNotFound) {
		writeError(w, http.StatusNotFound, "Header not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "header store read failed")
		return
	}
	hdr, err := decodeWireHeaderV2(raw)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "header decode failed")
		return
	}
	writeJSON(w, http.StatusOK, chaintracksV2HeaderFor(hdr, height))
}

// handleChaintracksV2HeaderByHash serves GET
// /chaintracks/v2/header/hash/{hash} (display-order hex), bare. Canonical:
// routes/fiber/routes.go:496-520 handleGetHeaderByHash.
//
// Also the entry point for GET .../header/hash/{hash}.bin — same
// suffix-sniffing reason as handleChaintracksV2HeaderByHeight above.
// Canonical: routes.go:584-602 handleGetHeaderByHashBinary.
func (s *Server) handleChaintracksV2HeaderByHash(w http.ResponseWriter, r *http.Request) {
	hashStr := r.PathValue("hash")
	if trimmed, isBin := strings.CutSuffix(hashStr, ".bin"); isBin {
		s.handleChaintracksV2HeaderByHashBinary(w, trimmed)
		return
	}
	// chainhash.NewHashFromStr alone is not a sufficient length check
	// (confirmed by a failing test against "bad": it does not reject a
	// too-short string the way this guard does) — same precondition as the
	// v1 shim, handlers_chaintracks.go:88-91.
	if len(hashStr) != 64 {
		writeError(w, http.StatusBadRequest, "Invalid hash parameter")
		return
	}
	hash, err := chainhash.NewHashFromStr(hashStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid hash parameter")
		return
	}

	height, err := s.headerStore.HeightForHash(hash)
	if errors.Is(err, leveldb.ErrNotFound) {
		writeError(w, http.StatusNotFound, "Header not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "header store read failed")
		return
	}
	raw, err := s.headerStore.HeaderAtHeight(height)
	if errors.Is(err, leveldb.ErrNotFound) {
		writeError(w, http.StatusNotFound, "Header not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "header store read failed")
		return
	}
	hdr, err := decodeWireHeaderV2(raw)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "header decode failed")
		return
	}
	if hdr.BlockHash() != *hash {
		// The hash index can lag an active-chain reorg — same race the v1
		// shim's handleFindHeaderHexForBlockHash guards against
		// (handlers_chaintracks.go:120-123).
		writeError(w, http.StatusNotFound, "Header not found")
		return
	}
	s.setCacheControlV2(w, height)
	writeJSON(w, http.StatusOK, chaintracksV2HeaderFor(hdr, height))
}

// chaintracksV2RawHeaders parses height/count, bounds them, and returns the
// concatenated raw 80-byte headers plus the start height for a Cache-Control
// decision — the shared body for /headers and /headers.bin (handlers_
// chaintracks_v2_bin.go), which differ only in the extra X-Start-Height /
// X-Header-Count headers .bin sets. Canonical: routes/fiber/routes.go's
// ParseHeightAndCount (chaintracks/parse.go:9-22) + collectHeaders
// (routes.go:458-469), reusing Anvil's existing bounded RangeHeaders instead
// — see the file-level deviation note above.
func (s *Server) chaintracksV2RawHeaders(w http.ResponseWriter, r *http.Request) (data []byte, height uint32, ok bool) {
	q := r.URL.Query()
	heightStr, countStr := q.Get("height"), q.Get("count")
	if heightStr == "" || countStr == "" {
		writeError(w, http.StatusBadRequest, "missing parameter: height or count")
		return nil, 0, false
	}
	height64, err := strconv.ParseUint(heightStr, 10, 32)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid parameter: height")
		return nil, 0, false
	}
	count64, err := strconv.ParseUint(countStr, 10, 32)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid parameter: count")
		return nil, 0, false
	}
	height, count := uint32(height64), uint32(count64)
	if count < 1 {
		writeError(w, http.StatusBadRequest, "count must be >= 1")
		return nil, 0, false
	}
	if count > MaxHeadersRange {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("count must be <= %d", MaxHeadersRange))
		return nil, 0, false
	}

	raws, tip, err := s.headerStore.RangeHeaders(height, count)
	if errors.Is(err, headers.ErrRangeExceedsTip) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("range exceeds local tip %d", tip))
		return nil, 0, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "header read failed")
		return nil, 0, false
	}

	data = make([]byte, 0, len(raws)*80)
	for _, raw := range raws {
		data = append(data, raw...)
	}
	return data, height, true
}

// handleChaintracksV2Headers serves GET
// /chaintracks/v2/headers?height=N&count=M: count consecutive raw 80-byte
// headers, concatenated, application/octet-stream. Canonical:
// routes/fiber/routes.go:522-544 handleGetHeaders.
func (s *Server) handleChaintracksV2Headers(w http.ResponseWriter, r *http.Request) {
	data, height, ok := s.chaintracksV2RawHeaders(w, r)
	if !ok {
		return
	}
	s.setCacheControlV2(w, height)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
