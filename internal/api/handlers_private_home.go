package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/BSVanon/Anvil/internal/messaging"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware"
)

const maxPrivateHomeBody = 16 << 10

func (s *Server) handlePrivateHome(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.privateHomeCaller(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		s.getPrivateHome(w, identity)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	admissionOutpoint := ""
	if s.certificateGate.Gate != nil {
		var admitted bool
		admissionOutpoint, admitted = s.certificateGate.Gate.AdmissionOutpoint(r.Context(), identity)
		if !admitted {
			writeCodedError(w, http.StatusForbidden, "ERR_CERTIFICATE_REQUIRED", "A valid certificate is required.")
			return
		}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxPrivateHomeBody+1))
	if err != nil || len(body) > maxPrivateHomeBody {
		writeCodedError(w, http.StatusBadRequest, "ERR_INVALID_CLAIM", "Invalid private home claim.")
		return
	}
	var input struct {
		Claim messaging.PrivateHomeRecord `json:"claim"`
	}
	if json.Unmarshal(body, &input) != nil {
		writeCodedError(w, http.StatusBadRequest, "ERR_INVALID_CLAIM", "Invalid private home claim.")
		return
	}
	if input.Claim.Member != identity {
		writeCodedError(w, http.StatusForbidden, "ERR_CLAIM_MEMBER_MISMATCH", "The claim member must match the authenticated identity.")
		return
	}
	var priorAdmission messaging.PrivateHomeAdmission
	var hadPriorAdmission, pinned bool
	if s.certificateGate.Gate != nil && input.Claim.Kind == messaging.PrivateHomeClaim {
		priorAdmission, hadPriorAdmission, err = s.messagingPolicy.PrivateHomes.Admission(identity)
		if err != nil {
			writeCodedError(w, http.StatusInternalServerError, "ERR_CLAIM_STORE", "The private home claim could not be stored.")
			return
		}
		if _, err = s.certificateGate.Gate.PinAdmission(identity, admissionOutpoint); err != nil {
			writeCodedError(w, http.StatusServiceUnavailable, "ERR_CERTIFICATE_WATCH_UNAVAILABLE", "The certificate revocation watch is unavailable.")
			return
		}
		pinned = true
	}
	restorePin := func() {
		if !pinned || s.certificateGate.Gate == nil {
			return
		}
		if hadPriorAdmission {
			_, _ = s.certificateGate.Gate.PinAdmission(identity, priorAdmission.Outpoint)
		} else {
			s.certificateGate.Gate.UnpinAdmission(identity)
		}
	}
	var admissionBinding *string
	if s.certificateGate.Gate != nil {
		admissionBinding = &admissionOutpoint
	}
	err = s.messagingPolicy.PrivateHomes.ApplyLocal(r.Context(), input.Claim, admissionBinding, s.messagingPolicy.PrivateHomeCompatible)
	if err != nil {
		restorePin()
	}
	switch {
	case errors.Is(err, messaging.ErrPrivateHomeStale):
		writeCodedError(w, http.StatusConflict, "ERR_CLAIM_STALE", "A newer private home record is already stored.")
		return
	case errors.Is(err, messaging.ErrPrivateHomeLimit):
		writeCodedError(w, http.StatusForbidden, "ERR_CLAIM_LIMIT", "The private home member limit has been reached.")
		return
	case errors.Is(err, messaging.ErrPrivateHomeIncompatible):
		writeCodedError(w, http.StatusConflict, "ERR_HOME_INCOMPATIBLE", "A connected named home does not support private homes.")
		return
	case errors.Is(err, messaging.ErrPrivateHomeInvalid):
		writeCodedError(w, http.StatusBadRequest, "ERR_INVALID_CLAIM", "Invalid private home claim.")
		return
	case err != nil:
		s.logger.Error("private home claim store failed", "error", err)
		writeCodedError(w, http.StatusInternalServerError, "ERR_CLAIM_STORE", "The private home claim could not be stored.")
		return
	}
	if s.certificateGate.Gate != nil && input.Claim.Kind == messaging.PrivateHomeClaim &&
		!s.certificateGate.Gate.AdmissionMatches(identity, admissionOutpoint) {
		before, changed, revokeErr := s.messagingPolicy.PrivateHomes.RevokeMember(identity)
		if revokeErr != nil {
			s.logger.Error("private home admission race cleanup failed", "error", revokeErr)
			writeCodedError(w, http.StatusInternalServerError, "ERR_CLAIM_STORE", "The private home claim could not be stored.")
			return
		}
		if changed && s.gossipMgr != nil {
			s.gossipMgr.BroadcastHomeRevoke(identity, before)
		}
		writeCodedError(w, http.StatusForbidden, "ERR_CERTIFICATE_REQUIRED", "A valid certificate is required.")
		return
	}
	if s.gossipMgr != nil {
		s.gossipMgr.BroadcastHomeRecord(input.Claim)
	}
	if input.Claim.Kind == messaging.PrivateHomeRelease {
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "success", "released": true})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success", "homes": input.Claim.Homes, "expiresAt": input.Claim.ExpiresAt,
	})
}

func (s *Server) wirePrivateHomeRevocations() {
	if s.messagingPolicy.PrivateHomes == nil || s.certificateGate.Gate == nil {
		return
	}
	s.messagingPolicy.PrivateHomes.SetOnAdmissionRemoved(s.certificateGate.Gate.UnpinAdmission)
	s.certificateGate.Gate.OnRevoke("private_homes", func(identity string) {
		before, changed, err := s.messagingPolicy.PrivateHomes.RevokeMember(identity)
		if err != nil {
			s.logger.Error("private home revocation failed", "error", err)
			return
		}
		if changed && s.gossipMgr != nil {
			s.gossipMgr.BroadcastHomeRevoke(identity, before)
		}
	})
	s.reconcilePrivateHomeAdmissions()
}

func (s *Server) privateHomeCaller(w http.ResponseWriter, r *http.Request) (string, bool) {
	if s.messageboxBRC31 {
		if identity, err := middleware.ShouldGetAuthenticatedIdentity(r.Context()); err == nil && identity != nil {
			return hex.EncodeToString(identity.Compressed()), true
		}
	}
	writeCodedError(w, http.StatusUnauthorized, "ERR_BRC31_REQUIRED", "BRC-31 authentication is required.")
	return "", false
}

func (s *Server) getPrivateHome(w http.ResponseWriter, identity string) {
	claim, ok, err := s.messagingPolicy.PrivateHomes.Current(identity)
	if err != nil {
		writeCodedError(w, http.StatusInternalServerError, "ERR_CLAIM_STORE", "The private home claim could not be read.")
		return
	}
	if !ok {
		writeCodedError(w, http.StatusNotFound, "ERR_NO_CLAIM", "No current private home claim exists.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "success", "claim": claim})
}
