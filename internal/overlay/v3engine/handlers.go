package v3engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
)

// Handlers exposes the canonical overlay HTTP surface (POST /submit,
// POST /lookup, GET /listTopicManagers, GET /listLookupServiceProviders)
// as net/http handlers backed by a single engine.Engine. Anvil's
// existing api.Server mounts these under the canonical route group in
// W-5 phase B.
//
// MaxBodyBytes caps the request body length to prevent unbounded
// memory growth on submit (BEEF bodies can be large but should never
// be unbounded). Zero means "default" which is 64 MiB — enough for
// reasonable UHRP payloads plus headroom.
type Handlers struct {
	Engine       *engine.Engine
	MaxBodyBytes int64
}

const defaultMaxBodyBytes = 64 << 20 // 64 MiB

// NewHandlers wraps an engine with default settings.
func NewHandlers(eng *engine.Engine) *Handlers {
	return &Handlers{Engine: eng}
}

func (h *Handlers) maxBody() int64 {
	if h.MaxBodyBytes <= 0 {
		return defaultMaxBodyBytes
	}
	return h.MaxBodyBytes
}

// Submit handles POST /submit. The canonical contract (per pinned
// conformance vector overlay.submit.* in
// docs/internal/conformance-vectors/overlay/submit.json):
//
//   - Request body: raw BEEF bytes. With x-includes-off-chain-values:
//     true, body is `varint(len) + offChainValues + BEEF` — len is the
//     off-chain prefix length encoded as a BSV varint (1/3/5/9 bytes).
//     The vector body_hex `04 deadbeef 0100beef...` codifies this
//     order. (Q2 in UPSTREAM_QUESTIONS notes a possible SDK-vs-vector
//     parse discrepancy; we follow the vector because that's what we
//     can actually test against.)
//   - x-topics header: JSON array of topic names, e.g. ["tm_uhrp"].
//   - Response: 200 + STEAK JSON on success; 400 with a canonical
//     error envelope `{status:"error",message:string}` otherwise
//     (vector overlay.submit.7 + overlay.lookup.10).
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
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxBody()))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	if len(body) == 0 {
		writeError(w, http.StatusBadRequest, "empty body (BEEF required)")
		return
	}
	beefBytes, offChain, err := splitOffChainValues(body, r.Header.Get("x-includes-off-chain-values"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid off-chain values prefix: "+err.Error())
		return
	}
	tagged := overlay.TaggedBEEF{
		Beef:           beefBytes,
		Topics:         topics,
		OffChainValues: offChain,
	}
	steak, err := h.Engine.Submit(r.Context(), tagged, engine.SubmitModeCurrent, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, "submit failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, steak)
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
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxBody()))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
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
	answer, err := h.Engine.Lookup(r.Context(), &lookup.LookupQuestion{
		Service: raw.Service,
		Query:   raw.Query,
	})
	if err != nil {
		if errors.Is(err, engine.ErrUnknownTopic) {
			writeError(w, http.StatusBadRequest, "unknown lookup service: "+raw.Service)
			return
		}
		writeError(w, http.StatusBadRequest, "lookup failed: "+err.Error())
		return
	}
	if r.Header.Get("x-aggregation") == "yes" {
		if err := writeAggregatedAnswer(w, answer); err != nil {
			writeError(w, http.StatusInternalServerError, "aggregate: "+err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, answer)
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
// browser callers (Anvil-Swap UI, SendBSV-Foundry) get the required
// Access-Control-* headers when they migrate to canonical routes —
// Codex review fe9707876f5618ca caught the original implementation
// mounting handlers raw and noted browser callers would fail
// cross-origin as soon as app migrations begin.
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
	// W-10.3: canonical GASP federation routes. Always registered — the
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

// parseTopicsHeader decodes the x-topics request header (JSON array of
// strings). Returns an empty slice on empty header, an error on
// malformed JSON.
func parseTopicsHeader(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	var topics []string
	if err := json.Unmarshal([]byte(raw), &topics); err != nil {
		return nil, err
	}
	return topics, nil
}

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
// pinned vectors (caught by Codex review 93c0fe5a44610be1).
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorEnvelope{Status: "error", Message: msg})
}

// splitOffChainValues separates the `varint(len) + offChainValues +
// BEEF` body shape when `x-includes-off-chain-values: true`. When the
// header is absent or any value other than "true", the whole body is
// the BEEF and OffChainValues is nil. Vector body_hex
// `04 deadbeef 0100beef...` (overlay.submit.8) is the canonical
// reference for this order.
func splitOffChainValues(body []byte, header string) (beef, offChain []byte, err error) {
	if header != "true" {
		return body, nil, nil
	}
	if len(body) == 0 {
		return nil, nil, errors.New("empty body")
	}
	n, advance, err := readVarInt(body)
	if err != nil {
		return nil, nil, fmt.Errorf("read varint: %w", err)
	}
	rest := body[advance:]
	if uint64(len(rest)) < n {
		return nil, nil, fmt.Errorf("off-chain prefix declares %d bytes but only %d available", n, len(rest))
	}
	offChain = rest[:n]
	beef = rest[n:]
	if len(beef) == 0 {
		return nil, nil, errors.New("empty BEEF after off-chain prefix")
	}
	return beef, offChain, nil
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

// readVarInt decodes a Bitcoin-flavored variable-length integer from
// the beginning of buf. Returns the decoded value and the number of
// bytes consumed. Spec: <0xfd → 1 byte; 0xfd → next 2 bytes; 0xfe →
// next 4 bytes; 0xff → next 8 bytes (all little-endian).
func readVarInt(buf []byte) (uint64, int, error) {
	if len(buf) == 0 {
		return 0, 0, errors.New("empty buffer")
	}
	first := buf[0]
	switch {
	case first < 0xfd:
		return uint64(first), 1, nil
	case first == 0xfd:
		if len(buf) < 3 {
			return 0, 0, errors.New("truncated varint (0xfd)")
		}
		return uint64(buf[1]) | uint64(buf[2])<<8, 3, nil
	case first == 0xfe:
		if len(buf) < 5 {
			return 0, 0, errors.New("truncated varint (0xfe)")
		}
		return uint64(buf[1]) | uint64(buf[2])<<8 | uint64(buf[3])<<16 | uint64(buf[4])<<24, 5, nil
	default: // 0xff
		if len(buf) < 9 {
			return 0, 0, errors.New("truncated varint (0xff)")
		}
		v := uint64(buf[1]) | uint64(buf[2])<<8 | uint64(buf[3])<<16 | uint64(buf[4])<<24 |
			uint64(buf[5])<<32 | uint64(buf[6])<<40 | uint64(buf[7])<<48 | uint64(buf[8])<<56
		return v, 9, nil
	}
}
