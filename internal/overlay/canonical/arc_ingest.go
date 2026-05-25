package canonical

import (
	"encoding/json"
	"net/http"
)

// ArcIngestRequest is the JSON body of POST /arc-ingest. Shape fixed by
// conformance vectors overlay.topicmanagement.17 (happy path) and .18
// (missing txid → 400).
type ArcIngestRequest struct {
	Txid        string `json:"txid"`
	MerklePath  string `json:"merklePath"`
	BlockHeight uint32 `json:"blockHeight"`
}

// ArcIngestResponse is the success body of POST /arc-ingest.
type ArcIngestResponse struct {
	Status string `json:"status"` // "success"
}

func registerArcIngest(mux *http.ServeMux, cfg Config) {
	mux.HandleFunc("POST /arc-ingest", func(w http.ResponseWriter, r *http.Request) {
		handleArcIngest(w, r, cfg)
	})
}

func handleArcIngest(w http.ResponseWriter, r *http.Request, cfg Config) {
	var body ArcIngestRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeStructuredError(w, http.StatusBadRequest, "ERR_BAD_REQUEST")
		return
	}
	// Vector .18: missing txid → 400.
	if body.Txid == "" {
		writeStructuredError(w, http.StatusBadRequest, "ERR_MISSING_TXID")
		return
	}

	// Forward to the engine if a hook is configured. Production deployments
	// MUST set cfg.ArcIngest; a nil hook acknowledges (200) without engine
	// notification — fine for the conformance runner, dangerous in prod.
	if cfg.ArcIngest != nil {
		if err := cfg.ArcIngest(body); err != nil {
			writeStructuredError(w, http.StatusInternalServerError, "ERR_ARC_INGEST_FAILED")
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(ArcIngestResponse{Status: "success"})
}
