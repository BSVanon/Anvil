package api

import (
	"bytes"
	"errors"
	"net/http"
	"strconv"

	"github.com/libsv/go-p2p/wire"
	"github.com/syndtr/goleveldb/leveldb"
)

// --- Chaintracks-compatible SPV header source ---
//
// The SendBSV wallet's unmodified canonical @bsv/wallet-toolbox-client
// ChaintracksServiceClient uses exactly two endpoints as its SPV header
// source. Pointing that client's baseURL at an Anvil node (fronted by a CDN)
// lets the wallet retire its self-hosted chaintracks worker and verify SPV
// proofs against Anvil's P2P + proof-of-work header chain instead of a
// WhatsOnChain-trusting service. These handlers emit the client's
// {status,value} envelope directly (Anvil's writeJSON is otherwise
// envelope-free) and are mounted at root via openPublic => CORS + rate-limit
// with NO payment/token gate, so they stay unauthenticated even on a node with
// x402 pricing enabled. See docs ANVIL_TO_WALLET_CHAINTRACKS_SHIM.md.

// chaintracksHeader is the header shape the canonical client parses out of the
// {status,value} envelope. previousHash, merkleRoot, and hash are display
// (big-endian) hex: the client compares merkleRoot against a locally computed
// root, so wire (little-endian) byte order would invalidate every SPV proof.
// chainhash.Hash.String() performs the wire->display reversal.
type chaintracksHeader struct {
	Version      int32  `json:"version"`
	PreviousHash string `json:"previousHash"`
	MerkleRoot   string `json:"merkleRoot"`
	Time         uint32 `json:"time"`
	Bits         uint32 `json:"bits"`
	Nonce        uint32 `json:"nonce"`
	Height       uint32 `json:"height"`
	Hash         string `json:"hash"`
}

// handleFindHeaderHexForHeight serves GET /findHeaderHexForHeight?height=N.
// It returns the parsed block header at the requested height inside the
// canonical client's {status,value} envelope. A missing height yields
// {status:error} with HTTP 404 (never a placeholder header); the wallet maps
// that to "unable to verify -> unproven", which is SPV-safe.
func (s *Server) handleFindHeaderHexForHeight(w http.ResponseWriter, r *http.Request) {
	heightStr := r.URL.Query().Get("height")
	if heightStr == "" {
		writeChaintracksError(w, http.StatusBadRequest, "height is required")
		return
	}
	height64, err := strconv.ParseUint(heightStr, 10, 32)
	if err != nil {
		writeChaintracksError(w, http.StatusBadRequest, "height must be a non-negative integer")
		return
	}
	height := uint32(height64)

	raw, err := s.headerStore.HeaderAtHeight(height)
	if errors.Is(err, leveldb.ErrNotFound) {
		// Genuine miss: the node has no header at this height. Do not invent a
		// placeholder — the wallet maps this to "unable to verify -> unproven",
		// which is SPV-safe.
		writeChaintracksError(w, http.StatusNotFound, "no header at height")
		return
	}
	if err != nil {
		// Corruption / IO / closed-store: a real outage, not a miss. Report 500
		// so it is not silently hidden behind an 'unproven' wallet result.
		writeChaintracksError(w, http.StatusInternalServerError, "header store read failed")
		return
	}
	var hdr wire.BlockHeader
	if err := hdr.Deserialize(bytes.NewReader(raw)); err != nil {
		writeChaintracksError(w, http.StatusInternalServerError, "header decode failed")
		return
	}
	hash := hdr.BlockHash()

	writeChaintracksValue(w, chaintracksHeader{
		Version:      hdr.Version,
		PreviousHash: hdr.PrevBlock.String(),  // wire->display reversal
		MerkleRoot:   hdr.MerkleRoot.String(), // wire->display reversal
		Time:         uint32(hdr.Timestamp.Unix()),
		Bits:         hdr.Bits,
		Nonce:        hdr.Nonce,
		Height:       height,
		Hash:         hash.String(), // wire->display reversal
	})
}

// handleGetPresentHeight serves GET /getPresentHeight, returning the node's
// verified-synced tip height (the height it can actually serve/verify to, not
// an optimistic network tip) inside the canonical client's {status,value}
// envelope.
func (s *Server) handleGetPresentHeight(w http.ResponseWriter, r *http.Request) {
	writeChaintracksValue(w, s.headerStore.Tip())
}

// writeChaintracksValue writes a {"status":"success","value":...} envelope,
// the shape the canonical client's getJsonOrUndefined parses.
func writeChaintracksValue(w http.ResponseWriter, value interface{}) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success",
		"value":  value,
	})
}

// writeChaintracksError writes a {"status":"error",...} envelope with the given
// HTTP status. The canonical client maps a non-success envelope (or any
// non-2xx) to "unable to verify".
func writeChaintracksError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]interface{}{
		"status": "error",
		"error":  msg,
	})
}
