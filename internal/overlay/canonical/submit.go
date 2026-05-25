package canonical

import (
	"encoding/json"
	"io"
	"net/http"
)

// SubmitRequest is the parsed input to POST /submit.
type SubmitRequest struct {
	// Topics are the BRC-22 topic manager names from the x-topics header.
	Topics []string

	// Body is the request body bytes (BEEF, optionally prefixed with
	// off-chain values per IncludesOffChainValues).
	Body []byte

	// IncludesOffChainValues mirrors the x-includes-off-chain-values header.
	// When true, the body carries off-chain values varint-delimited before
	// the BEEF bytes (vector overlay.submit.8). UPSTREAM_QUESTIONS Q2: the
	// exact byte order is disputed between SDK and vector note — Anvil
	// implementations should canonicalize when they ship real BEEF parsing.
	IncludesOffChainValues bool
}

// TopicAdmittance is one entry in a STEAK response — the per-topic admission
// result for a submitted transaction.
//
// MarshalJSON normalizes nil slices to empty arrays. The pinned conformance
// vectors document responses with `coinstakeOutputsToRetain: []` (empty
// array, present). Go's default JSON encoder serializes a nil []uint32 as
// `null` without `omitempty`, which fails the vector contract. The custom
// marshaler emits `[]` for both nil and empty slices, so the wire form is
// always an array. (Conversely, `omitempty` would omit the field entirely,
// breaking the same vectors.)
type TopicAdmittance struct {
	OutputsToAdmit           []uint32 `json:"outputsToAdmit"`
	CoinstakeOutputsToRetain []uint32 `json:"coinstakeOutputsToRetain"`
}

// MarshalJSON forces nil slices to emit as `[]`, never `null`.
func (t TopicAdmittance) MarshalJSON() ([]byte, error) {
	type alias TopicAdmittance
	a := alias(t)
	if a.OutputsToAdmit == nil {
		a.OutputsToAdmit = []uint32{}
	}
	if a.CoinstakeOutputsToRetain == nil {
		a.CoinstakeOutputsToRetain = []uint32{}
	}
	return json.Marshal(a)
}

// SubmitResponse is the STEAK shape: map of topic name to admittance result.
// JSON-marshalled directly as the response body.
type SubmitResponse map[string]TopicAdmittance

const submitMaxBodyBytes = 10 << 20 // 10 MiB, matches legacy /overlay/submit cap

func registerSubmit(mux *http.ServeMux, cfg Config) {
	mux.HandleFunc("POST /submit", func(w http.ResponseWriter, r *http.Request) {
		handleSubmit(w, r, cfg)
	})
}

func handleSubmit(w http.ResponseWriter, r *http.Request, cfg Config) {
	// Vector .11: Content-Type must be application/octet-stream.
	if r.Header.Get("Content-Type") != "application/octet-stream" {
		writeSubmitError(w, http.StatusBadRequest, "ERR_BAD_CONTENT_TYPE", "Content-Type must be application/octet-stream")
		return
	}

	// Vectors .4, .9: x-topics header must be present + valid JSON.
	rawTopics := r.Header.Get("x-topics")
	if rawTopics == "" {
		writeSubmitError(w, http.StatusBadRequest, "ERR_MISSING_TOPICS", "missing x-topics header")
		return
	}
	var topics []string
	if err := json.Unmarshal([]byte(rawTopics), &topics); err != nil {
		writeSubmitError(w, http.StatusBadRequest, "ERR_BAD_TOPICS", "x-topics must be a JSON array")
		return
	}
	// Vector .5: empty topics array.
	if len(topics) == 0 {
		writeSubmitError(w, http.StatusBadRequest, "ERR_EMPTY_TOPICS", "x-topics must be a non-empty array")
		return
	}

	// Vector .7: unknown topic manager.
	// Per the canonical contract, an unknown topic is engine-level — the
	// engine returns empty admission rather than an HTTP error. But vector
	// .7 expects 400. Reconcile: when Config.KnownTopics is set, reject
	// unknown topics at the route boundary with 400. When not set, defer to
	// the callback (or empty-STEAK fallback).
	if cfg.KnownTopics != nil {
		known := cfg.KnownTopics()
		for _, t := range topics {
			if !stringSliceContains(known, t) {
				writeSubmitError(w, http.StatusBadRequest, "ERR_UNKNOWN_TOPIC", "unknown topic manager: "+t)
				return
			}
		}
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, submitMaxBodyBytes))
	if err != nil {
		writeSubmitError(w, http.StatusBadRequest, "ERR_READ_BODY", "failed to read request body")
		return
	}
	// Vector .6: empty body.
	if len(body) == 0 {
		writeSubmitError(w, http.StatusBadRequest, "ERR_EMPTY_BODY", "request body is empty")
		return
	}

	includesOffChain := r.Header.Get("x-includes-off-chain-values") == "true"

	req := SubmitRequest{
		Topics:                 topics,
		Body:                   body,
		IncludesOffChainValues: includesOffChain,
	}

	var steak SubmitResponse
	if cfg.Submit != nil {
		s, err := cfg.Submit(req)
		if err != nil {
			writeSubmitError(w, http.StatusInternalServerError, "ERR_SUBMIT_FAILED", err.Error())
			return
		}
		steak = s
	} else {
		// Conformance-runner / no-engine path: return a STEAK shape with
		// empty admissions for each requested topic. This satisfies the
		// vector shape contract without claiming to admit anything. Production
		// MUST wire Config.Submit (mirrors the arc-ingest pattern from
		// Codex review 9fe46aca).
		steak = SubmitResponse{}
		for _, t := range topics {
			steak[t] = TopicAdmittance{OutputsToAdmit: []uint32{}}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(steak)
}

// submitError is the body shape of a /submit 4xx/5xx response. Vector .12
// requires both `status: "error"` and a `message` string field.
type submitError struct {
	Status  string `json:"status"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
}

func writeSubmitError(w http.ResponseWriter, code int, errCode, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(submitError{
		Status:  "error",
		Code:    errCode,
		Message: msg,
	})
}

func stringSliceContains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
