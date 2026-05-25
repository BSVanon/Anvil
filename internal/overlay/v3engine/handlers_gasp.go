package v3engine

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/gasp"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// GASP federation HTTP routes.
//
// Wire format is the canonical BRC-88 / overlay-services contract:
//
//   POST /requestSyncResponse
//     X-BSV-Topic: <topic>
//     Body: gasp.InitialRequest JSON  ({version, since, limit?})
//     200:  gasp.InitialResponse JSON ({UTXOList:[{txid,outputIndex,score}], since})
//
//   POST /requestForeignGASPNode
//     X-BSV-Topic: <topic>
//     Body: gasp.NodeRequest JSON     ({graphID, txid, outputIndex, metadata})
//     200:  gasp.Node JSON
//
// Both routes use the canonical gasp.* types from
// bsv-blockchain/go-overlay-services/pkg/core/gasp directly — the
// upstream OverlayGASPRemote client (pkg/core/engine/gasp-remote.go)
// marshals / unmarshals the same types end-to-end, so consuming them
// here keeps Anvil's GASP wire surface bit-identical with the canonical
// reference implementation. Anvil-bespoke wrapper DTOs would only
// invite drift.

// RequestSyncResponse handles POST /requestSyncResponse. A federation
// peer asks us for our state of a topic so it can run its half of a
// GASP sync. We respond with the list of currently-known UTXOs on that
// topic plus a "since" timestamp the peer can use to incrementally sync
// next time.
//
// Topic is delivered via X-BSV-Topic header per canonical OpenAPI spec.
// Returns 400 on malformed body, 400 on missing topic, 500 on engine
// errors.
func (h *Handlers) RequestSyncResponse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	topic := r.Header.Get("X-BSV-Topic")
	if topic == "" {
		writeError(w, http.StatusBadRequest, "X-BSV-Topic header required")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxBody()))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var req gasp.InitialRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	resp, err := h.Engine.ProvideForeignSyncResponse(r.Context(), &req, topic)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Canonical: gasp.InitialResponse has UTXOList []*gasp.Output and
	// Since float64 — both JSON-marshal exactly per the upstream wire
	// contract. Initialize UTXOList to an empty slice (not nil) so the
	// JSON encodes as "[]" not "null", matching the canonical
	// OverlayGASPRemote.GetInitialResponse decoder expectations.
	if resp == nil {
		resp = &gasp.InitialResponse{}
	}
	if resp.UTXOList == nil {
		resp.UTXOList = []*gasp.Output{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// RequestForeignGASPNode handles POST /requestForeignGASPNode. A
// federation peer asks us for a specific GASP graph node — the raw
// transaction plus optional proof and metadata — so it can backfill a
// UTXO it learned about via /requestSyncResponse. Returns the node if
// we have it; 404 if we don't.
//
// Topic via X-BSV-Topic header. Request body is gasp.NodeRequest.
// Returns 400 on malformed body, 400 on missing topic, 404 on missing
// output (engine.ErrMissingOutput | engine.ErrNotFound), 500 on other
// engine errors.
func (h *Handlers) RequestForeignGASPNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	topic := r.Header.Get("X-BSV-Topic")
	if topic == "" {
		writeError(w, http.StatusBadRequest, "X-BSV-Topic header required")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxBody()))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var req gasp.NodeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.GraphID == nil {
		writeError(w, http.StatusBadRequest, "graphID required")
		return
	}
	if req.Txid == nil {
		writeError(w, http.StatusBadRequest, "txid required")
		return
	}
	outpoint := &transaction.Outpoint{Txid: *req.Txid, Index: req.OutputIndex}
	node, err := h.Engine.ProvideForeignGASPNode(r.Context(), req.GraphID, outpoint, topic)
	if err != nil {
		// Canonical contract: missing-output / not-found is a 404, not
		// a 500. Two upstream sentinels can surface here:
		//   - engine.ErrMissingOutput ("missing-output") returned by
		//     ProvideForeignGASPNode at engine.go:1273/1297/1309 when
		//     the output is nil or the hydrator hits its depth limit.
		//   - engine.ErrNotFound ("not-found") returned by the storage
		//     layer (Anvil's anvilstorage.FindOutput, upstream
		//     engine.go:1259) when the outpoint isn't present at all.
		// Both mean "this node doesn't have it" → 404.
		// Codex review 24358e121cfe3e64 caught the original
		// implementation reporting missing nodes as 500.
		if errors.Is(err, engine.ErrMissingOutput) || errors.Is(err, engine.ErrNotFound) {
			writeError(w, http.StatusNotFound, "node not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if node == nil {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(node)
}
