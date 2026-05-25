package legacyshim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// --- legacy wire types (kept structurally identical to the existing
// shapes in internal/overlay/engine.go so the shim is byte-for-byte
// drop-in for legacy callers) -------------------------------------------

// legacyTaggedBEEF is the JSON body shape POST /overlay/submit accepts
// (matches the existing overlay.TaggedBEEF type at
// internal/overlay/engine.go:78).
type legacyTaggedBEEF struct {
	BEEF   []byte   `json:"beef"`
	Topics []string `json:"topics"`
}

// legacyAdmittanceInstructions mirrors internal/overlay/engine.go:58
// for the legacy submit response. The canonical Steak shape carries
// uint32 indices and an AncillaryTxids field that Anvil legacy apps
// never expected; we drop AncillaryTxids and widen-cast to int.
type legacyAdmittanceInstructions struct {
	OutputsToAdmit []int `json:"outputsToAdmit"`
	CoinsToRetain  []int `json:"coinsToRetain"`
	CoinsRemoved   []int `json:"coinsRemoved,omitempty"`
}

type legacySteak map[string]*legacyAdmittanceInstructions

// legacyLookupQuestion has the same shape as both canonical
// lookup.LookupQuestion and Anvil's existing LookupQuestion at
// internal/overlay/engine.go:96 — identical JSON, kept locally so the
// shim has no compile-time dependency on Anvil's legacy overlay package.
type legacyLookupQuestion struct {
	Service string          `json:"service"`
	Query   json.RawMessage `json:"query"`
}

// legacyAdmittedOutput is the per-result shape the legacy LookupAnswer
// returned (internal/overlay/engine.go:84). The shim populates these
// fields by parsing each canonical OutputListItem's BEEF + invoking the
// per-service ScriptParser to recover Metadata.
type legacyAdmittedOutput struct {
	Txid         string          `json:"txid"`
	Vout         int             `json:"vout"`
	Topic        string          `json:"topic"`
	OutputScript []byte          `json:"outputScript,omitempty"`
	Satoshis     uint64          `json:"satoshis,omitempty"`
	Metadata     json.RawMessage `json:"metadata,omitempty"`
	Spent        bool            `json:"spent,omitempty"`
}

// legacyLookupAnswer mirrors internal/overlay/engine.go:102.
type legacyLookupAnswer struct {
	Type    string                 `json:"type"`
	Outputs []legacyAdmittedOutput `json:"outputs,omitempty"`
	Result  interface{}            `json:"result,omitempty"`
}

// legacyListEntry is the per-entry shape /overlay/topics and
// /overlay/services returned (internal/overlay/handlers.go:120-128 +
// :135-143). Documentation is a string + Metadata is a free-form map
// that Anvil's legacy handlers always populated from
// TopicManager.GetMetadata(). Canonical engine.MetaData is a typed
// struct — we serialise its fields under "metadata" so the legacy
// callers see something structurally similar.
//
// Topics is populated only on /overlay/services responses (matches
// legacy behaviour where lookup-service entries carried their
// indexed-topic list). Empty/nil for /overlay/topics entries.
type legacyListEntry struct {
	Documentation string         `json:"documentation"`
	Metadata      map[string]any `json:"metadata,omitempty"`
	Topics        []string       `json:"topics,omitempty"`
}

// --- registration ---------------------------------------------------------

// Middleware is the canonical http.HandlerFunc wrapper signature used
// by Anvil's api.Server.CorsWrap and the inline cors() helper at
// internal/api/server.go:270. Accepting an optional middleware on
// Register lets the boot code pass api.Server.CorsWrap so browser
// callers (Foundry, the DEX UI) get the same CORS behaviour they had
// against the pre-shim handlers (cmd/anvil/main.go:717).
type Middleware func(http.HandlerFunc) http.HandlerFunc

// Register mounts every legacy /overlay/* protocol route on the given
// mux, wrapping each handler with the supplied middleware. Pass nil
// for no wrapping (tests use that path). Production boot MUST pass
// api.Server.CorsWrap so browser POSTs and preflight OPTIONS get the
// correct Access-Control-* headers.
//
// Mesh routes (/overlay/lookup, /overlay/register, /overlay/deregister)
// are NOT touched — they stay registered by internal/api/server.go.
//
// Idempotent: registering twice on the same mux is a programmer error
// and net/http will panic on the second call. The mux owner is
// expected to invoke Register exactly once at boot.
func (s *Shim) Register(mux *http.ServeMux, wrap Middleware) {
	wrap = orIdentity(wrap)
	mux.HandleFunc("POST /overlay/submit", wrap(s.Submit))
	mux.HandleFunc("POST /overlay/query", wrap(s.Query))
	mux.HandleFunc("GET /overlay/topics", wrap(s.ListTopics))
	mux.HandleFunc("GET /overlay/services", wrap(s.ListServices))
	mux.HandleFunc("OPTIONS /overlay/submit", wrap(s.optionsOK))
	mux.HandleFunc("OPTIONS /overlay/query", wrap(s.optionsOK))
}

// orIdentity returns wrap when non-nil, or a pass-through wrapper that
// invokes the handler as-is. Keeps the call sites in Register concise.
func orIdentity(wrap Middleware) Middleware {
	if wrap != nil {
		return wrap
	}
	return func(h http.HandlerFunc) http.HandlerFunc { return h }
}

// optionsOK is the canned CORS preflight responder kept identical to
// the existing one in internal/overlay/handlers.go:22-23. The actual
// Access-Control-* headers are written by the CorsWrap middleware
// wrapping this handler; we just need a 200 body.
func (s *Shim) optionsOK(w http.ResponseWriter, r *http.Request) {}

// --- POST /overlay/submit ------------------------------------------------

// Submit accepts the legacy submit body in either of two shapes the
// existing internal/overlay/handlers.go:33-87 supported:
//
//  1. JSON: { "beef": <bytes>, "topics": ["tm_uhrp", ...] }
//  2. Binary: application/octet-stream body + X-Topics header
//
// Translates into overlay.TaggedBEEF and calls the canonical
// engine.Submit with SubmitModeCurrent. Returns the canonical Steak
// reshaped into the legacy AdmittanceInstructions JSON so apps don't
// notice the swap.
//
// Error envelope matches the existing legacy `{"error": msg}` shape —
// NOT the canonical `{status, message}` envelope — because legacy
// callers parse the error field directly. This is the cost of Lens 2 =
// 2c indefinite compat.
func (s *Shim) Submit(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.maxBody()))
	if err != nil {
		writeLegacyError(w, http.StatusBadRequest, "failed to read body")
		return
	}

	var beefBytes []byte
	var topicList []string

	if r.Header.Get("Content-Type") == "application/octet-stream" {
		beefBytes = body
		hdr := r.Header.Get("X-Topics")
		if hdr != "" {
			if err := json.Unmarshal([]byte(hdr), &topicList); err != nil {
				writeLegacyError(w, http.StatusBadRequest, "invalid X-Topics header")
				return
			}
		}
	} else {
		var tagged legacyTaggedBEEF
		if err := json.Unmarshal(body, &tagged); err != nil {
			writeLegacyError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		beefBytes = tagged.BEEF
		topicList = tagged.Topics
	}

	if len(beefBytes) == 0 {
		writeLegacyError(w, http.StatusBadRequest, "empty transaction data")
		return
	}
	if len(topicList) == 0 {
		writeLegacyError(w, http.StatusBadRequest, "no topics specified")
		return
	}

	canonicalSteak, err := s.Engine.Submit(r.Context(), overlay.TaggedBEEF{
		Beef:   beefBytes,
		Topics: topicList,
	}, engine.SubmitModeCurrent, nil)
	if err != nil {
		writeLegacyError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, canonicalToLegacySteak(canonicalSteak))
}

// canonicalToLegacySteak narrows the canonical overlay.Steak (uint32 +
// AncillaryTxids) into the legacy shape (int, no AncillaryTxids).
func canonicalToLegacySteak(s overlay.Steak) legacySteak {
	if s == nil {
		return nil
	}
	out := make(legacySteak, len(s))
	for topic, inst := range s {
		if inst == nil {
			out[topic] = nil
			continue
		}
		out[topic] = &legacyAdmittanceInstructions{
			OutputsToAdmit: uint32SliceToInt(inst.OutputsToAdmit),
			CoinsToRetain:  uint32SliceToInt(inst.CoinsToRetain),
			CoinsRemoved:   uint32SliceToInt(inst.CoinsRemoved),
		}
	}
	return out
}

func uint32SliceToInt(in []uint32) []int {
	if len(in) == 0 {
		return nil
	}
	out := make([]int, len(in))
	for i, v := range in {
		out[i] = int(v)
	}
	return out
}

// --- POST /overlay/query -------------------------------------------------

// Query translates a legacy lookup body into the canonical
// lookup.LookupQuestion, calls engine.Lookup, then rebuilds the legacy
// LookupAnswer shape — including the Metadata field on each output,
// reconstructed from the BEEF the canonical engine hydrated, via the
// per-service ScriptParser table.
//
// Freeform answers (LookupAnswer.Result) pass through verbatim.
func (s *Shim) Query(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.maxBody()))
	if err != nil {
		writeLegacyError(w, http.StatusBadRequest, "failed to read body")
		return
	}
	var q legacyLookupQuestion
	if err := json.Unmarshal(body, &q); err != nil {
		writeLegacyError(w, http.StatusBadRequest, "invalid query: "+err.Error())
		return
	}
	if q.Service == "" {
		writeLegacyError(w, http.StatusBadRequest, "service required")
		return
	}

	answer, err := s.Engine.Lookup(r.Context(), &lookup.LookupQuestion{
		Service: q.Service,
		Query:   q.Query,
	})
	if err != nil {
		writeLegacyError(w, http.StatusBadRequest, err.Error())
		return
	}

	legacy, err := s.canonicalToLegacyAnswer(r.Context(), q.Service, answer)
	if err != nil {
		writeLegacyError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, legacy)
}

// canonicalToLegacyAnswer reshapes a canonical LookupAnswer into the
// legacy form. For output-list answers it parses each BEEF, extracts
// the per-output script, and asks the service-specific ScriptParser to
// recover the Metadata blob legacy callers expect.
//
// Errors during per-output reconstruction are *logged as missing
// metadata* (we just omit the field) rather than failing the whole
// query, because failing would be a worse UX than returning the
// outpoint without its rich metadata. Callers can detect the missing-
// metadata case by the absent JSON field.
func (s *Shim) canonicalToLegacyAnswer(
	ctx context.Context,
	service string,
	answer *lookup.LookupAnswer,
) (*legacyLookupAnswer, error) {
	if answer == nil {
		return &legacyLookupAnswer{Type: "output-list"}, nil
	}

	switch answer.Type {
	case lookup.AnswerTypeFreeform:
		return &legacyLookupAnswer{
			Type:   "freeform",
			Result: answer.Result,
		}, nil

	case lookup.AnswerTypeOutputList, lookup.AnswerTypeFormula:
		out := &legacyLookupAnswer{Type: "output-list"}
		parser := s.Parsers[service]
		out.Outputs = make([]legacyAdmittedOutput, 0, len(answer.Outputs))
		for _, item := range answer.Outputs {
			if item == nil || len(item.Beef) == 0 {
				continue
			}
			legacy, err := s.reconstructLegacyOutput(ctx, service, parser, item)
			if err != nil {
				// Skip this output but don't fail the whole answer.
				continue
			}
			out.Outputs = append(out.Outputs, legacy)
		}
		return out, nil

	default:
		return nil, fmt.Errorf("legacyshim: unsupported answer type %q", answer.Type)
	}
}

// reconstructLegacyOutput parses an OutputListItem's BEEF, locates the
// admitted output at OutputIndex, and assembles the legacy
// AdmittedOutput record. Metadata is recovered by invoking the
// per-service ScriptParser; an unknown service or a parser that
// returns (nil, nil) yields an output record with no metadata field
// rather than an error.
func (s *Shim) reconstructLegacyOutput(
	ctx context.Context,
	service string,
	parser ScriptParser,
	item *lookup.OutputListItem,
) (legacyAdmittedOutput, error) {
	if err := ctx.Err(); err != nil {
		return legacyAdmittedOutput{}, err
	}
	tx, err := transaction.NewTransactionFromBEEF(item.Beef)
	if err != nil {
		return legacyAdmittedOutput{}, fmt.Errorf("parse output beef: %w", err)
	}
	if int(item.OutputIndex) >= len(tx.Outputs) {
		return legacyAdmittedOutput{}, fmt.Errorf("OutputIndex %d out of range (tx has %d outputs)", item.OutputIndex, len(tx.Outputs))
	}
	out := tx.Outputs[item.OutputIndex]
	if out == nil {
		return legacyAdmittedOutput{}, errors.New("nil output at OutputIndex")
	}
	var scriptBytes []byte
	if out.LockingScript != nil {
		scriptBytes = out.LockingScript.Bytes()
	}

	legacy := legacyAdmittedOutput{
		Txid:         tx.TxID().String(),
		Vout:         int(item.OutputIndex),
		Topic:        serviceToTopic(service),
		OutputScript: scriptBytes,
		Satoshis:     out.Satoshis,
	}

	if parser != nil {
		if meta, err := parser(scriptBytes); err == nil && meta != nil {
			legacy.Metadata = meta
		}
	}
	return legacy, nil
}

// serviceToTopic maps a canonical lookup-service name to the topic it
// indexes. Used to populate AdmittedOutput.Topic in the legacy
// response. Falls back to the service name when there's no known
// mapping (rare; only the 4 Anvil services are wired today).
func serviceToTopic(service string) string {
	switch service {
	case "ls_uhrp":
		return "tm_uhrp"
	case "ls_dex_swap":
		return "tm_dex_swap"
	case "ls_ordlock_listings":
		return "tm_ordlock_listings"
	case "ls_ordlock_buy_vaults":
		return "tm_ordlock_buy_vaults"
	default:
		return service
	}
}

// --- GET /overlay/topics + /overlay/services -----------------------------

// ListTopics translates engine.ListTopicManagers() into the legacy
// {name: {documentation, metadata}} JSON shape that
// internal/overlay/handlers.go:116-128 served.
func (s *Shim) ListTopics(w http.ResponseWriter, r *http.Request) {
	managers := s.Engine.ListTopicManagers()
	out := make(map[string]legacyListEntry, len(managers))
	for name, meta := range managers {
		out[name] = canonicalMetadataToLegacyEntry(meta)
	}
	writeJSON(w, http.StatusOK, out)
}

// ListServices is the mirror endpoint for lookup services. Each entry
// also carries a `topics` array of topic names the service indexes —
// populated from Shim.ServiceTopics. Anvil-Swap's discovery code and
// the TS SDK both treat that field as required (Codex review
// d671fa17fe5cc746 caught it being dropped in the first draft).
func (s *Shim) ListServices(w http.ResponseWriter, r *http.Request) {
	services := s.Engine.ListLookupServiceProviders()
	out := make(map[string]legacyListEntry, len(services))
	for name, meta := range services {
		entry := canonicalMetadataToLegacyEntry(meta)
		if topicList, ok := s.ServiceTopics[name]; ok {
			entry.Topics = topicList
		}
		out[name] = entry
	}
	writeJSON(w, http.StatusOK, out)
}

// canonicalMetadataToLegacyEntry serialises canonical *overlay.MetaData
// into the legacy shape. The canonical struct's fields go into the
// `metadata` map; the legacy `documentation` field comes from
// MetaData.Description (which is what Anvil's old handlers populated
// it with in practice).
func canonicalMetadataToLegacyEntry(meta *overlay.MetaData) legacyListEntry {
	if meta == nil {
		return legacyListEntry{}
	}
	entry := legacyListEntry{
		Documentation: meta.Description,
		Metadata:      make(map[string]any),
	}
	if meta.Name != "" {
		entry.Metadata["name"] = meta.Name
	}
	if meta.Description != "" {
		entry.Metadata["description"] = meta.Description
	}
	if meta.Icon != "" {
		entry.Metadata["iconURL"] = meta.Icon
	}
	if meta.Version != "" {
		entry.Metadata["version"] = meta.Version
	}
	return entry
}

// --- helpers --------------------------------------------------------------

// writeJSON mirrors internal/overlay/handlers.go:146-150 — same
// Content-Type + status semantics so legacy callers see identical
// response framing.
func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeLegacyError writes the LEGACY error envelope `{"error": msg}` —
// NOT the canonical `{status, message}` shape. Legacy callers parse
// the `error` field directly; switching them to canonical would break
// Anvil-Swap and SendBSV-Foundry. Lens 2 = 2c cost.
func writeLegacyError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
