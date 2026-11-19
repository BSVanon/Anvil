package api

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/BSVanon/Anvil/internal/spv"
)

// --- BEEF ---

// handleGetBEEF serves a complete BEEF envelope, fetching it on cache misses.
func (s *Server) handleGetBEEF(w http.ResponseWriter, r *http.Request) {
	txid := r.PathValue("txid")
	if len(txid) != 64 {
		writeError(w, http.StatusBadRequest, "txid must be 64 hex characters")
		return
	}

	// 1. Cache hit — periodically refresh an unproven subject.
	source := spv.BEEFSourceCached
	beefBytes, err := s.proofStore.GetBEEF(txid)
	if err == nil {
		cachedTx, parseErr := safeParseBEEF(beefBytes)
		subjectProven := parseErr == nil && cachedTx.MerklePath != nil
		if !subjectProven {
			beefBytes, source, subjectProven = s.refreshCachedBEEF(txid, beefBytes)
		}
		serveBEEF(w, r, txid, beefBytes, source, subjectProven, s.validator)
		return
	} else if s.proofFetcher != nil {
		// 2. Cache miss — fetch on demand; fetcher returns which upstream
		// supplied the proof so the caller can distinguish overlay-cached
		// data from passthrough from an external indexer.
		fetched, fetchedSource, fetchErr := s.proofFetcher.FetchBEEF(txid)
		if fetchErr != nil {
			s.logger.Debug("BEEF fetch failed", "txid", txid, "error", fetchErr)
			writeError(w, http.StatusNotFound, "no BEEF available: "+fetchErr.Error())
			return
		}
		if !beefSubjectMatches(fetched, txid) {
			writeError(w, http.StatusNotFound, "fetched proof subject does not match txid")
			return
		}

		// 3. Validate against local headers before caching; what is cached
		// and served is the BEEF validated, normalized.
		fetched, validationErr := s.fetchedBEEFVerified(r.Context(), fetched)
		if validationErr != nil {
			writeError(w, http.StatusNotFound, beefValidationErrorMessage(validationErr))
			return
		}

		// 4. Cache for future requests
		if _, storeErr := s.cacheBEEF(fetched); storeErr != nil {
			s.logger.Warn("failed to cache fetched BEEF", "txid", txid, "error", storeErr)
			// Non-fatal — still serve the response
		}

		beefBytes = fetched
		source = fetchedSource
	} else if err != nil {
		// No fetcher configured — plain cache miss
		writeError(w, http.StatusNotFound, "no BEEF envelope found for this txid")
		return
	}

	serveBEEF(w, r, txid, beefBytes, source, beefSubjectProven(beefBytes), s.validator)
}

func serveBEEF(w http.ResponseWriter, r *http.Request, txid string, beefBytes []byte, source string, subjectProven bool, validator *spv.Validator) {
	// Serve as binary if requested — source is surfaced via header since the
	// body is pure BEEF bytes with no room for metadata.
	if strings.Contains(r.Header.Get("Accept"), "application/octet-stream") {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-BEEF-Source", source)
		w.Header().Set("X-BEEF-Subject-Proven", fmt.Sprintf("%t", subjectProven))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(beefBytes) // error is client-side disconnect, nothing to do
		return
	}

	// confidence stays "" (omitted below) when validator is nil, the call
	// errors, or result.Refused: a BEEF this node already stored and now
	// re-validates under a stricter rule than it was accepted under
	// (beefnorm.ErrRefused, spv.Result.Refused) must not come back as
	// "confidence":"invalid" -- that word means a fresh submission is being
	// refused right now, not that an already-served historical payment was
	// bad (cold review round 4's NITs, C4.3).
	confidence := ""
	if validator != nil {
		result, err := validator.ValidateBEEF(r.Context(), beefBytes)
		if err == nil && !result.Refused {
			confidence = result.Confidence
		}
	}

	resp := map[string]interface{}{
		"txid":   txid,
		"beef":   hex.EncodeToString(beefBytes),
		"source": source,
	}
	if confidence != "" {
		resp["confidence"] = confidence
	}
	w.Header().Set("X-BEEF-Subject-Proven", fmt.Sprintf("%t", subjectProven))
	writeJSON(w, http.StatusOK, resp)
}
