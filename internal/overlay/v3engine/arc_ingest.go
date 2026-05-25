package v3engine

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// arcIngestRequest is the canonical /arc-ingest body shape per pinned
// vector overlay.topicmanagement.17:
//
//	{ "txid": "...", "merklePath": "...", "blockHeight": 813706 }
//
// The merklePath hex already carries a block-height field; the
// top-level blockHeight in the body is a redundant sanity check. We
// reject the request if they disagree.
type arcIngestRequest struct {
	Txid        string `json:"txid"`
	MerklePath  string `json:"merklePath"`
	BlockHeight uint32 `json:"blockHeight"`
}

// arcIngestSuccess is the canonical success body per vector
// overlay.topicmanagement.17 (`{"status":"success"}`).
type arcIngestSuccess struct {
	Status string `json:"status"`
}

// ArcIngest handles POST /arc-ingest. ARC (Anvil's broadcast facade in
// production, or any external publisher) calls this endpoint when a
// transaction it knows about gets mined, supplying the merkle proof so
// the overlay engine can transition any admitted outputs from Unmined
// to Validated state.
//
// Canonical contract is JSON-bodied (vector overlay.topicmanagement.17),
// in contrast to /submit which is octet-stream BEEF. Errors return the
// canonical `{status:"error", message:string}` envelope at 400.
func (h *Handlers) ArcIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxBody()))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var req arcIngestRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid arc-ingest body: "+err.Error())
		return
	}
	if req.Txid == "" {
		writeError(w, http.StatusBadRequest, "txid required")
		return
	}
	if req.MerklePath == "" {
		writeError(w, http.StatusBadRequest, "merklePath required")
		return
	}
	txid, err := chainhash.NewHashFromHex(req.Txid)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid txid: "+err.Error())
		return
	}
	proof, err := transaction.NewMerklePathFromHex(req.MerklePath)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid merklePath: "+err.Error())
		return
	}
	// Cross-check the redundant blockHeight in the body matches the
	// height encoded in the proof. The vector contract requires both
	// fields; treat a mismatch as caller error rather than silently
	// trusting one side.
	if req.BlockHeight != 0 && proof.BlockHeight != req.BlockHeight {
		writeError(w, http.StatusBadRequest, "blockHeight mismatch between body and merklePath")
		return
	}
	if err := h.Engine.HandleNewMerkleProof(r.Context(), txid, proof); err != nil {
		// Upstream silently no-ops if the tx isn't known to this
		// overlay (engine.go:1517), so any non-nil err here is a real
		// validation or storage failure — return 400 with the
		// canonical envelope.
		writeError(w, http.StatusBadRequest, "arc-ingest failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, arcIngestSuccess{Status: "success"})
}
