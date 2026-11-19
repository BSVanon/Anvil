package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/BSVanon/Anvil/internal/beefscan"
	"github.com/BSVanon/Anvil/internal/refusallog"
	"github.com/BSVanon/Anvil/internal/spv"
)

// --- Broadcast ---

// Consumer-friendly derived status values for POST /broadcast responses.
// Wallets and DEX consumers use this single field for failover decisions
// without having to read the individual ARC state bits.
const (
	BroadcastStatusPropagated    = "propagated"     // reached miners (SEEN_ON_NETWORK or MINED)
	BroadcastStatusQueued        = "queued"         // ARC has it, pre-SEEN state — will propagate
	BroadcastStatusValidatedOnly = "validated-only" // BEEF valid, no miner submission performed
	BroadcastStatusRejected      = "rejected"       // BEEF invalid OR ARC rejected
)

// BroadcastResponse is the structured response from POST /broadcast.
type BroadcastResponse struct {
	TxID       string     `json:"txid"`
	Status     string     `json:"status"` // derived summary: see BroadcastStatus* constants
	Confidence string     `json:"confidence"`
	Stored     bool       `json:"stored"`
	Mempool    bool       `json:"mempool"`
	ARC        *ARCStatus `json:"arc,omitempty"`
	Message    string     `json:"message,omitempty"`
}

// ARCStatus is the structured ARC submission result.
type ARCStatus struct {
	Submitted bool   `json:"submitted"`
	TxStatus  string `json:"tx_status,omitempty"`
	Error     string `json:"error,omitempty"`
}

// deriveBroadcastStatus maps the full response state to the consumer-facing
// status summary. See ANVIL_NODE_HANDOFF.md for the derivation table.
func deriveBroadcastStatus(confidence string, arc *ARCStatus) string {
	if confidence == spv.ConfidenceInvalid {
		return BroadcastStatusRejected
	}
	if arc != nil && arc.Submitted {
		switch arc.TxStatus {
		case "REJECTED", "DOUBLE_SPEND_ATTEMPTED":
			return BroadcastStatusRejected
		case "SEEN_ON_NETWORK", "MINED":
			return BroadcastStatusPropagated
		default:
			// Any other ARC state (RECEIVED, STORED, ANNOUNCED_TO_NETWORK,
			// ACCEPTED_BY_NETWORK, SENT_TO_NETWORK, etc.) means ARC has the
			// tx and will propagate — wallet should treat as queued, not
			// as a failure.
			return BroadcastStatusQueued
		}
	}
	return BroadcastStatusValidatedOnly
}

func (s *Server) handleBroadcast(w http.ResponseWriter, r *http.Request) {
	beefBytes, err := readBEEF(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	result, err := s.validator.ValidateBEEF(context.Background(), beefBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("validation error: %v", err))
		return
	}

	// /broadcast is SPV-validation-first: a BEEF Anvil cannot verify against its
	// local header chain is rejected. Clients must send a proof-carrying BEEF
	// (the SPV contract) — a bare transaction has no ancestry to validate and is
	// refused here rather than relayed blind.
	if result.Confidence == spv.ConfidenceInvalid {
		if strings.HasPrefix(result.Message, beefscan.Code+":") {
			refusallog.Log(r, http.StatusUnprocessableEntity, refusallog.ReasonBroadcastTooComplex)
		}
		writeJSON(w, http.StatusUnprocessableEntity, BroadcastResponse{
			TxID:       result.TxID,
			Status:     deriveBroadcastStatus(result.Confidence, nil),
			Confidence: result.Confidence,
			Message:    result.Message,
		})
		return
	}

	resp := BroadcastResponse{
		TxID:       result.TxID,
		Confidence: result.Confidence,
		Message:    result.Message,
	}
	// What is stored and relayed is the BEEF validated: the subject and the
	// ancestry its verification read, with one canonical BUMP per block,
	// never transactions or proofs the validation dropped.
	beefBytes = result.BEEF

	if result.Confidence == spv.ConfidenceSPVVerified || result.Confidence == spv.ConfidencePartiallyVerified {
		// A skipped write still means a copy is cached: an existing proven one is kept.
		if _, err := s.cacheBEEF(beefBytes); err != nil {
			s.logger.Error("failed to store BEEF", "txid", result.TxID, "error", err)
		} else {
			resp.Stored = true
		}
	}

	if s.broadcaster != nil {
		if _, err := s.broadcaster.BroadcastBEEF(beefBytes); err != nil {
			s.logger.Error("mempool add failed", "txid", result.TxID, "error", err)
		} else {
			resp.Mempool = true
		}

		if r.URL.Query().Get("arc") == "true" {
			arcStatus := &ARCStatus{}
			// Hand ARC the tx parsed from the (already-validated) BEEF so it goes
			// out as extended format — the input ancestry travels with it and ARC
			// needn't fetch parents (avoids ARC's "460 Missing input scripts" on a
			// 0-conf parent). The BEEF validated above, so this parse is safe.
			tx, perr := safeParseBEEF(beefBytes)
			if perr != nil {
				arcStatus.Error = fmt.Sprintf("parse tx for ARC: %v", perr)
			} else {
				arcResult, aerr := s.broadcaster.BroadcastToARCTx(tx)
				if aerr != nil {
					// Configuration error (e.g. ARC not wired). Submitted stays false.
					arcStatus.Error = aerr.Error()
				} else if arcResult.Status == "error" {
					// Transport failure — BroadcastToARCTx swallows the HTTP error
					// into a result with Status="error". We don't know whether the tx
					// reached ARC, so "Submitted=false" is the honest answer and
					// deriveBroadcastStatus lands on "validated-only" (wallet should
					// retry via a different upstream).
					arcStatus.Submitted = false
					arcStatus.Error = arcResult.Message
				} else {
					arcStatus.Submitted = true
					arcStatus.TxStatus = arcResult.Status
				}
			}
			resp.ARC = arcStatus
		}
	}

	resp.Status = deriveBroadcastStatus(resp.Confidence, resp.ARC)
	writeJSON(w, http.StatusOK, resp)
}
