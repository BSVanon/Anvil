package v3engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/BSVanon/Anvil/internal/overlay/gaspstatus"
	"github.com/BSVanon/Anvil/internal/overlay/lookupguard"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
)

// Handlers exposes the canonical overlay HTTP surface (POST /submit,
// POST /lookup, GET /listTopicManagers, GET /listLookupServiceProviders)
// as net/http handlers backed by a single engine.Engine. Anvil's
// existing api.Server mounts these under the canonical route group in
// canonical route group.
//
// MaxBodyBytes, when positive, lowers every route's body cap to it. Zero
// keeps routeguard's caps: routeguard.MaxBEEFBody for /submit and
// routeguard.MaxJSONBody for the JSON routes.
type Handlers struct {
	Engine       *engine.Engine
	MaxBodyBytes int64

	// Guard bounds the heap, verification CPU and connection time the
	// routes may take. Nil uses routeguard.Default, which every overlay
	// route in the process shares.
	Guard *routeguard.Guard

	// SubmitTimeout caps each POST /submit; past it the route answers 504.
	// Zero or less uses DefaultSubmitTimeout (see submit_deadline.go).
	SubmitTimeout time.Duration

	// SyncStatus, if set, supplies this node's GASP federation-sync state,
	// which POST /lookup stamps as X-Overlay-Gasp-* response headers. It lets
	// a caller judge how settled and complete this node's view is when
	// weighing an answer — an empty result from a not-yet-synced node is not
	// the same as one from a fully-synced node. Anvil reports the state; what
	// a caller does with it is the caller's policy. Nil disables the headers.
	// The legacy /overlay/query path carries the identical headers.
	SyncStatus func() gaspstatus.Snapshot
}

// NewHandlers wraps an engine with default settings.
func NewHandlers(eng *engine.Engine) *Handlers {
	return &Handlers{Engine: eng}
}

// writeSyncHeaders stamps the GASP federation-sync readiness headers on a
// /lookup response. Identical contract + values to the legacy
// /overlay/query shim (internal/overlay/legacyshim), so a caller reading
// either endpoint sees the same X-Overlay-Gasp-* fields. Nil SyncStatus
// (unwired, or single-node builds) emits nothing. The four header names
// are already in the api server's Access-Control-Expose-Headers, so
// browser JS can read them cross-origin.
func (h *Handlers) writeSyncHeaders(w http.ResponseWriter) {
	if h.SyncStatus == nil {
		return
	}
	st := h.SyncStatus()
	hdr := w.Header()
	hdr.Set("X-Overlay-Gasp-Enabled", strconv.FormatBool(st.Enabled))
	hdr.Set("X-Overlay-Gasp-Initial-Sync-Done", strconv.FormatBool(st.InitialSyncDone))
	hdr.Set("X-Overlay-Gasp-Interval-Secs", strconv.Itoa(st.IntervalSecs))
	if st.LastSyncUnix > 0 {
		hdr.Set("X-Overlay-Gasp-Last-Sync-Unix", strconv.FormatInt(st.LastSyncUnix, 10))
	}
}

// Submit handles POST /submit. The canonical contract (per pinned
// conformance vector overlay.submit.* in
// docs/internal/conformance-vectors/overlay/submit.json):
//
//   - Request body: raw BEEF bytes. With x-includes-off-chain-values:
//     true, body is `varint(BEEF length) + BEEF + offChainValues`.
//   - x-topics header: a comma-separated topic list, with the earlier JSON
//     array form accepted during transition.
//   - Response: 200 + STEAK JSON on success; 400 with a canonical
//     error envelope `{status:"error",message:string}` otherwise
//     (vector overlay.submit.7 + overlay.lookup.10), or 504 with the
//     same envelope when SubmitTimeout cuts the engine short before
//     propagation; a submit that reaches propagation answers 200, up
//     to 15 s past it (see DefaultSubmitTimeout).
func (h *Handlers) Submit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	if err := requireOctetStream(r.Header.Get("Content-Type")); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	topics, err := parseTopicsHeader(r.Header.Get("x-topics"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid x-topics: "+err.Error())
		return
	}
	if len(topics) == 0 {
		writeError(w, http.StatusBadRequest, "x-topics required")
		return
	}
	h.submitBEEF(w, r, topics)
}

// topicAdmittance is one topic's entry in the canonical STEAK wire form:
// camelCase keys and empty arrays (never null). The raw go-sdk
// overlay.AdmittanceInstructions carries no JSON tags, so marshalling a
// overlay.Steak directly emits PascalCase keys with null for empty slices —
// a shape a canonical overlay client (e.g. @bsv/sdk) cannot parse. An empty
// OutputsToAdmit is a valid 200 (nothing on the tx matched this topic — for a
// single-purpose submit that usually means the token failed the topic
// manager's admission validation), not an error, per engine.Submit.
type topicAdmittance struct {
	OutputsToAdmit []uint32 `json:"outputsToAdmit"`
	CoinsToRetain  []uint32 `json:"coinsToRetain"`
	CoinsRemoved   []uint32 `json:"coinsRemoved"`
	AncillaryTxIDs []string `json:"ancillaryTxIDs"`
}

// canonicalSteak reshapes a go-sdk overlay.Steak into the canonical STEAK wire
// form (camelCase keys, [] never null) so canonical clients can parse it.
func canonicalSteak(steak overlay.Steak) map[string]topicAdmittance {
	out := make(map[string]topicAdmittance, len(steak))
	for topic, ai := range steak {
		ta := topicAdmittance{
			OutputsToAdmit: []uint32{},
			CoinsToRetain:  []uint32{},
			CoinsRemoved:   []uint32{},
			AncillaryTxIDs: []string{},
		}
		if ai != nil {
			if len(ai.OutputsToAdmit) > 0 {
				ta.OutputsToAdmit = ai.OutputsToAdmit
			}
			if len(ai.CoinsToRetain) > 0 {
				ta.CoinsToRetain = ai.CoinsToRetain
			}
			if len(ai.CoinsRemoved) > 0 {
				ta.CoinsRemoved = ai.CoinsRemoved
			}
			for _, hh := range ai.AncillaryTxids {
				if hh != nil {
					ta.AncillaryTxIDs = append(ta.AncillaryTxIDs, hh.String())
				}
			}
		}
		out[topic] = ta
	}
	return out
}

// Lookup handles POST /lookup. Body is the canonical LookupQuestion
// JSON shape `{service, query}`. Both fields are required per pinned
// vector overlay.lookup.5; missing query → 400.
//
// When `x-aggregation: yes` the response is a binary
// application/octet-stream aggregated payload per vector
// overlay.lookup.3:
//
//	varint(numOutpoints) +
//	foreach[ txid(32 bytes LE) + varint(outputIndex) +
//	         varint(contextLen) + context ] +
//	BEEF bytes (a single BEEF carrying every output's tx)
//
// `context` is a TS-only extension (the Go lookup.OutputListItem has
// no Context field), so the Go canonical impl writes varint(0) for
// each entry. Documented divergence; tracked as a parity item.
//
// Unknown service maps to 400 per overlay.lookup.6 status_oneof.
// Error envelope is the canonical `{status:"error",message:string}`
// shape (vector overlay.lookup.10).
func (h *Handlers) Lookup(w http.ResponseWriter, r *http.Request) {
	// Stamp the GASP readiness headers before the status line, so the answer
	// and the node's sync-state are bound atomically (matches the legacy
	// /overlay/query behavior). They ride on every response — 200 and 4xx —
	// so a caller can bind freshness to the exact answer regardless of outcome.
	h.writeSyncHeaders(w)
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	t, body, ok := h.readJSON(w, r, routeguard.LookupRoute)
	if !ok {
		return
	}
	defer t.Close()
	var raw struct {
		Service string          `json:"service"`
		Query   json.RawMessage `json:"query"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		writeError(w, http.StatusBadRequest, "invalid lookup question: "+err.Error())
		return
	}
	if raw.Service == "" {
		writeError(w, http.StatusBadRequest, "service required")
		return
	}
	if len(raw.Query) == 0 || string(raw.Query) == "null" {
		writeError(w, http.StatusBadRequest, "query required")
		return
	}
	cursor, err := lookupguard.ParseCursor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := boundedLookupForWire(r, h.Engine, &lookup.LookupQuestion{
		Service: raw.Service,
		Query:   raw.Query,
	}, cursor, r.Header.Get("x-aggregation") == "yes")
	if err != nil {
		if errors.Is(err, engine.ErrUnknownTopic) {
			writeError(w, http.StatusBadRequest, "unknown lookup service: "+raw.Service)
			return
		}
		writeError(w, http.StatusBadRequest, "lookup failed: "+err.Error())
		return
	}
	if r.Header.Get("x-aggregation") == "yes" {
		result, err = capAggregatedAnswer(result, cursor)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "aggregate: "+err.Error())
			return
		}
	}
	lookupguard.WriteHeaders(w, result)
	answer := result.Answer
	if r.Header.Get("x-aggregation") == "yes" {
		t.Close()
		if err := writeAggregatedAnswer(w, answer); err != nil {
			writeError(w, http.StatusInternalServerError, "aggregate: "+err.Error())
		}
		return
	}
	encoded, err := json.Marshal(answer)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode answer: "+err.Error())
		return
	}
	// The answer is fully serialized now: only the network write is left,
	// which this also bounds (boundAnswerWrite) as a backstop. Release t's
	// JSON slot before that write rather than at the deferred Close above,
	// so a client that opens the connection and never reads its answer no
	// longer holds that slot for as long as it keeps the connection open —
	// only for as long as everything up to this point took. Close is
	// idempotent, so the deferred call above still safely covers every
	// return before this one.
	t.Close()
	boundAnswerWrite(w, len(encoded))
	writeJSONBytes(w, http.StatusOK, encoded)
}

// ListTopicManagers handles GET /listTopicManagers. Returns a JSON
// object mapping topic name to metadata.
func (h *Handlers) ListTopicManagers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	writeJSON(w, http.StatusOK, h.Engine.ListTopicManagers())
}

// ListLookupServiceProviders handles GET /listLookupServiceProviders.
func (h *Handlers) ListLookupServiceProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	writeJSON(w, http.StatusOK, h.Engine.ListLookupServiceProviders())
}

// Middleware is the canonical http.HandlerFunc wrapper signature used
// by Anvil's api.Server.CorsWrap (internal/api/server.go). Mirrors the
// legacyshim.Middleware type so the same boot-time wrap function plugs
// into both the canonical and legacy route registrations.
type Middleware func(http.HandlerFunc) http.HandlerFunc

// Register mounts every canonical route on the given mux, wrapping each
// handler with the supplied middleware. Pass nil for no wrapping (tests
// use that path). Production boot MUST pass api.Server.CorsWrap so
// browser callers get the required Access-Control-* headers when they migrate
// to canonical routes. Mounting handlers raw would fail cross-origin requests.
//
// Routes are registered with bare patterns so the handler bodies keep
// emitting the canonical {status,message} error envelope on
// wrong-method requests (vector overlay.lookup.10 contract). OPTIONS
// is mounted separately with method-prefixed patterns (Go 1.22+ mux
// gives those priority) so preflight reaches preflight() — which is a
// no-op handler whose 200 body lets the wrap middleware emit the
// Access-Control-Allow-* headers.
func (h *Handlers) Register(mux *http.ServeMux, wrap Middleware) {
	wrap = orIdentity(wrap)
	mux.HandleFunc("/submit", wrap(h.Submit))
	mux.HandleFunc("/lookup", wrap(h.Lookup))
	mux.HandleFunc("/listTopicManagers", wrap(h.ListTopicManagers))
	mux.HandleFunc("/listLookupServiceProviders", wrap(h.ListLookupServiceProviders))
	mux.HandleFunc("/arc-ingest", wrap(h.ArcIngest))
	// Canonical GASP federation routes are always registered — the
	// engine guards on missing federation state internally (returns
	// empty/zero responses if no peers, no SyncConfiguration). Operators
	// who want single-node mode set cfg.Overlay.EnableGASPSync=false
	// which skips the outbound StartGASPSync goroutine; inbound requests
	// still get served (returning whatever the local store knows).
	mux.HandleFunc("/requestSyncResponse", wrap(h.RequestSyncResponse))
	mux.HandleFunc("/requestForeignGASPNode", wrap(h.RequestForeignGASPNode))
	mux.HandleFunc("OPTIONS /submit", wrap(h.preflight))
	mux.HandleFunc("OPTIONS /lookup", wrap(h.preflight))
	mux.HandleFunc("OPTIONS /arc-ingest", wrap(h.preflight))
	mux.HandleFunc("OPTIONS /requestSyncResponse", wrap(h.preflight))
	mux.HandleFunc("OPTIONS /requestForeignGASPNode", wrap(h.preflight))
}

// orIdentity returns wrap when non-nil, or a pass-through wrapper that
// invokes the handler as-is. Keeps the call sites in Register concise.
// Identical pattern to legacyshim.orIdentity.
func orIdentity(wrap Middleware) Middleware {
	if wrap != nil {
		return wrap
	}
	return func(h http.HandlerFunc) http.HandlerFunc { return h }
}

// preflight is the canned CORS preflight responder. The actual
// Access-Control-Allow-* headers are written by the wrap middleware;
// this handler just yields a 200 so the response stream completes.
func (h *Handlers) preflight(w http.ResponseWriter, r *http.Request) {}

// --- helpers ---------------------------------------------------------------

// writeJSON writes the JSON-marshalled value with the given status. If
// marshalling fails we silently drop the body — the status header is
// already on the wire so a partial response is the best we can do.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(body)
}

// errorEnvelope is the canonical ErrorResponse shape pinned by vector
// overlay.lookup.10: `{ status: "error", message: string, code?: string }`.
// Submit error vectors use the same shape.
type errorEnvelope struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}

// writeError writes the canonical error envelope at the given status.
// Replaces the earlier `{"error": msg}` shape which diverged from the
// pinned vectors.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorEnvelope{Status: "error", Message: msg})
}

// requireOctetStream enforces the canonical POST /submit Content-Type
// per vector overlay.submit.11 (`Content-Type: application/json`
// instead of `application/octet-stream` → 400). We accept the header
// being absent (some clients omit it) but reject any explicit value
// that doesn't normalise to application/octet-stream. The media-type
// parser strips parameters like charset/boundary so values such as
// "application/octet-stream; charset=binary" still pass.
func requireOctetStream(header string) error {
	if header == "" {
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(header)
	if err != nil {
		return fmt.Errorf("invalid Content-Type %q: %w", header, err)
	}
	if !strings.EqualFold(mediaType, "application/octet-stream") {
		return fmt.Errorf("Content-Type must be application/octet-stream, got %q", mediaType)
	}
	return nil
}
