package api

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/version"
	"github.com/libsv/go-p2p/wire"
)

// MaxHeadersRange is the maximum number of headers returnable from
// /headers/range in a single request (50 × 80 B = 4 KB body cap).
const MaxHeadersRange = 50

// --- Status & Headers ---

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	headersInfo, warnings := s.buildHeaderStatus()
	resp := map[string]interface{}{
		"node":    s.nodeName,
		"version": version.Version,
		"headers": headersInfo,
	}
	if spvInfo, spvWarnings := s.buildSPVStatus(); len(spvInfo) > 0 {
		resp["spv"] = spvInfo
		warnings = append(warnings, spvWarnings...)
	}
	if s.gossipMgr != nil {
		mesh := map[string]interface{}{
			"peers": s.gossipMgr.PeerCount(),
		}
		if recent := s.gossipMgr.RecentConnections(5); len(recent) > 0 {
			mesh["recent_connections"] = recent
		}
		resp["mesh"] = mesh
		if s.gossipMgr.PeerCount() == 0 {
			warnings = append(warnings, "mesh has zero connected peers")
		}
	}
	// Run all registered subsystem health checks
	for _, hc := range s.healthChecks {
		if msg := hc.Check(); msg != "" {
			warnings = append(warnings, msg)
		}
	}
	if len(warnings) > 0 {
		resp["warnings"] = warnings
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	headersInfo, warnings := s.buildHeaderStatus()
	stats := map[string]interface{}{
		"node":    s.nodeName,
		"version": version.Version,
		"headers": headersInfo,
	}

	if s.envelopeStore != nil {
		stats["envelopes"] = map[string]interface{}{
			"ephemeral": s.envelopeStore.CountEphemeral(),
			"durable":   s.envelopeStore.CountDurable(),
			"topics":    s.envelopeStore.Topics(),
		}
	}

	if s.gossipMgr != nil {
		mesh := map[string]interface{}{
			"peers":     s.gossipMgr.PeerCount(),
			"peer_list": s.gossipMgr.PeerList(),
		}
		if recent := s.gossipMgr.RecentConnections(10); len(recent) > 0 {
			mesh["recent_connections"] = recent
		}
		stats["mesh"] = mesh
		if s.gossipMgr.PeerCount() == 0 {
			warnings = append(warnings, "mesh has zero connected peers")
		}
	}

	if s.overlayDir != nil {
		stats["overlay"] = map[string]interface{}{
			"ship_count": s.overlayDir.CountSHIP(),
		}
	}

	if s.bondChecker != nil && s.bondChecker.Required() {
		stats["bond"] = map[string]interface{}{
			"required": true,
			"min_sats": s.bondChecker.MinSats(),
		}
	}

	if s.gossipMgr != nil {
		warnings := s.gossipMgr.SlashWarnings()
		if len(warnings) > 0 {
			stats["slash_warnings"] = warnings
		}
	}

	if spvInfo, spvWarnings := s.buildSPVStatus(); len(spvInfo) > 0 {
		stats["spv"] = spvInfo
		warnings = append(warnings, spvWarnings...)
	}

	if len(warnings) > 0 {
		stats["warnings"] = warnings
	}

	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleHeadersTip(w http.ResponseWriter, r *http.Request) {
	tip := s.headerStore.Tip()
	hash, err := s.headerStore.HashAtHeight(tip)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get tip hash")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"height": tip,
		"hash":   hash.String(),
	})
}

// handleHeadersRange returns N consecutive raw 80-byte block headers as JSON
// (default) or concatenated bytes (Accept: application/octet-stream). Used by
// SPV-proof builders that need raw headers to verify a Merkle path on-chain.
func (s *Server) handleHeadersRange(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	fromStr := q.Get("from")
	countStr := q.Get("count")
	if fromStr == "" || countStr == "" {
		writeError(w, http.StatusBadRequest, "from and count are required")
		return
	}
	from, err := strconv.ParseUint(fromStr, 10, 32)
	if err != nil {
		writeError(w, http.StatusBadRequest, "from must be a non-negative integer")
		return
	}
	count, err := strconv.ParseUint(countStr, 10, 32)
	if err != nil {
		writeError(w, http.StatusBadRequest, "count must be a positive integer")
		return
	}
	if count < 1 {
		writeError(w, http.StatusBadRequest, "count must be >= 1")
		return
	}
	if count > MaxHeadersRange {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("count must be <= %d", MaxHeadersRange))
		return
	}

	hdrs, tip, err := s.headerStore.RangeHeaders(uint32(from), uint32(count))
	if errors.Is(err, headers.ErrRangeExceedsTip) {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":     "range exceeds local tip",
			"tipHeight": tip,
			"from":      from,
			"count":     count,
		})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "header read failed: "+err.Error())
		return
	}

	if strings.Contains(r.Header.Get("Accept"), "application/octet-stream") {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		for _, h := range hdrs {
			_, _ = w.Write(h)
		}
		return
	}

	hexHeaders := make([]string, len(hdrs))
	for i, h := range hdrs {
		hexHeaders[i] = hex.EncodeToString(h)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"from":      from,
		"count":     count,
		"tipHeight": tip,
		"headers":   hexHeaders,
	})
}

func (s *Server) buildHeaderStatus() (map[string]interface{}, []string) {
	tip := s.headerStore.Tip()
	work := s.headerStore.Work()
	info := map[string]interface{}{
		"height": tip,
		"work":   work.String(),
	}
	var warnings []string

	if hash, err := s.headerStore.HashAtHeight(tip); err == nil && hash != nil {
		info["hash"] = hash.String()
	}
	if raw, err := s.headerStore.HeaderAtHeight(tip); err == nil {
		var header wire.BlockHeader
		if err := header.Deserialize(bytes.NewReader(raw)); err == nil {
			tipTime := header.Timestamp.UTC()
			lag := int(time.Since(header.Timestamp).Seconds())
			if lag < 0 {
				lag = 0
			}
			info["tip_time"] = tipTime.Format(time.RFC3339)
			info["sync_lag_secs"] = lag
			if lag > 1800 {
				warnings = append(warnings, fmt.Sprintf("headers are stale (sync lag %ds)", lag))
			}
		}
	}
	if s.headerSyncStatus != nil {
		sync := s.headerSyncStatus()
		info["sync"] = sync
		if sync.LastError != "" {
			warnings = append(warnings, "latest header sync failed: "+sync.LastError)
		}
	}
	return info, warnings
}

func (s *Server) buildSPVStatus() (map[string]interface{}, []string) {
	info := map[string]interface{}{}
	var warnings []string

	if s.spvProofSource != "" {
		info["proof_source"] = s.spvProofSource
	}
	if s.proofStore != nil {
		info["proofs_stored"] = s.proofStore.Count()
	}
	if s.validator != nil {
		stats := s.validator.Stats()
		info["validations"] = stats
		if stats.Invalid > 0 {
			warnings = append(warnings, fmt.Sprintf("SPV validation failures observed (%d invalid)", stats.Invalid))
		}
	}

	if len(info) == 0 {
		return nil, warnings
	}
	return info, warnings
}
