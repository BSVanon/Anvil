package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/syndtr/goleveldb/leveldb"
)

// --- Chaintracks v2 binary routes ---
//
// 80-byte raw headers, application/octet-stream, X-Block-Height (single
// header) or X-Start-Height/X-Header-Count (range) set. Error bodies stay
// JSON {"error":"..."} even on these routes — canonical does the same
// (routes/fiber/routes.go's binary handlers all call c.JSON(fiber.Map{...})
// on every error path; only the success body is raw bytes).
//
// tip.bin and headers.bin are fully literal paths (no path parameter), so
// they are registered directly in server.go. header/height/{h}.bin and
// header/hash/{hash}.bin are NOT separately registered — see
// handlers_chaintracks_v2.go's handleChaintracksV2HeaderByHeight/
// HeaderByHash, which detect the ".bin" suffix themselves and call the two
// unexported-signature functions below.

// handleChaintracksV2TipBinary serves GET /chaintracks/v2/tip.bin: the
// current tip header as raw 80 bytes. Canonical: routes/fiber/routes.go
// :548-560 handleGetTipBinary.
func (s *Server) handleChaintracksV2TipBinary(w http.ResponseWriter, _ *http.Request) {
	height := s.headerStore.Tip()
	raw, err := s.headerStore.HeaderAtHeight(height)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "chain tip header read failed")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Block-Height", strconv.FormatUint(uint64(height), 10))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// handleChaintracksV2HeaderByHeightBinary serves the ".bin" shape of GET
// /chaintracks/v2/header/height/{height}: raw 80 bytes. heightStr has
// already had its ".bin" suffix trimmed by the caller. Canonical:
// routes/fiber/routes.go:562-581 handleGetHeaderByHeightBinary.
func (s *Server) handleChaintracksV2HeaderByHeightBinary(w http.ResponseWriter, heightStr string) {
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
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Block-Height", strconv.FormatUint(uint64(height), 10))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// handleChaintracksV2HeaderByHashBinary serves the ".bin" shape of GET
// /chaintracks/v2/header/hash/{hash}: raw 80 bytes. hashStr has already had
// its ".bin" suffix trimmed by the caller. Canonical:
// routes/fiber/routes.go:584-602 handleGetHeaderByHashBinary.
func (s *Server) handleChaintracksV2HeaderByHashBinary(w http.ResponseWriter, hashStr string) {
	// Same length precondition as the JSON route — see its comment.
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
		// Hash index can lag an active-chain reorg — same guard as the JSON route.
		writeError(w, http.StatusNotFound, "Header not found")
		return
	}
	s.setCacheControlV2(w, height)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Block-Height", strconv.FormatUint(uint64(height), 10))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// handleChaintracksV2HeadersBinary serves GET /chaintracks/v2/headers.bin:
// count consecutive raw 80-byte headers, concatenated, with
// X-Start-Height/X-Header-Count set (the only difference from plain
// /headers, which shares chaintracksV2RawHeaders). Canonical:
// routes/fiber/routes.go:604-620 handleGetHeadersBinary.
func (s *Server) handleChaintracksV2HeadersBinary(w http.ResponseWriter, r *http.Request) {
	data, height, ok := s.chaintracksV2RawHeaders(w, r)
	if !ok {
		return
	}
	s.setCacheControlV2(w, height)
	headerCount := uint32(len(data) / 80) //nolint:gosec // bounded by MaxHeadersRange, cannot overflow uint32
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Start-Height", strconv.FormatUint(uint64(height), 10))
	w.Header().Set("X-Header-Count", strconv.FormatUint(uint64(headerCount), 10))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
