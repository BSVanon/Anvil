package dispatchers

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/BSVanon/Anvil/internal/overlay/canonical"
	"github.com/BSVanon/Anvil/internal/overlay/interop"
)

// OverlaySubmit dispatches `overlay.submit` vectors against pre-registered
// http.Handlers. The CLI (cmd/anvil-conformance) owns scenario registration;
// the dispatcher only routes vectors to scenarios and asserts responses.
//
// Strategy per vector class:
//
//   - Happy-path vectors (.1, .2, .3, .8, .10): require a CLI-registered
//     scenario keyed by vector ID. The CLI calls
//     RegisterHappyPathScenariosFromVectors() at startup, which builds a
//     canonical.New per vector whose Submit callback returns the
//     SubmitResponse parsed from expected.body. The dispatcher exercises
//     that registered handler end-to-end and LITERAL-matches the response
//     body against expected.body (Codex review a8dc1754).
//
//   - Error vectors (.4, .5, .6, .9, .11, .12): use the default scenario
//     handler. Status + body.status="error" assertions (.12 also requires
//     body.message string).
//
//   - Vector .7 (unknown topic → 400): uses the "known-topics" scenario so
//     the canonical handler's KnownTopics filter rejects the request.
//
// Codex review ba3e80 enforced this CLI-owned registration so a miswired
// CLI is observable: if the CLI forgets to register happy-path scenarios,
// those vectors fall back to default (which produces empty admissions for
// any topic) and FAIL the literal-match assertion.
//
// Belt-and-suspenders shape checks (assertSteakShape, assertSteakTopicsMatch)
// run AFTER literal match on happy-path vectors to defend against a
// vector.expected.body that's itself malformed.
type OverlaySubmit struct {
	handlers map[string]http.Handler
}

// NewOverlaySubmit returns a dispatcher with a default-scenario handler.
// Additional scenarios (e.g., with KnownTopics for vector .7) attach via
// WithScenario.
func NewOverlaySubmit(handler http.Handler) *OverlaySubmit {
	return &OverlaySubmit{
		handlers: map[string]http.Handler{
			ScenarioDefault: handler,
		},
	}
}

// WithScenario adds a named-scenario handler. Returns the same dispatcher.
func (d *OverlaySubmit) WithScenario(name string, h http.Handler) *OverlaySubmit {
	d.handlers[name] = h
	return d
}

// FileID implements interop.Dispatcher.
func (d *OverlaySubmit) FileID() string { return "overlay.submit" }

// submitVectorInput is the request shape for overlay.submit vectors.
// body_hex is the BEEF (and optional off-chain prefix) as hex.
type submitVectorInput struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	BodyHex string            `json:"body_hex"`
}

// submitVectorExpected is the response shape; body is parsed downstream based
// on which assertion the vector documents.
type submitVectorExpected struct {
	Status     int             `json:"status"`
	Body       json.RawMessage `json:"body"`
	SchemaNote string          `json:"schema_note"`
}

// Scenarios for overlay.submit vectors. Happy-path vectors use scenario
// keys equal to their vector ID; the CLI registers them via
// RegisterHappyPathScenariosFromVectors. The two named scenarios below
// cover error vectors (default) and the unknown-topic case (known-topics).
const (
	ScenarioSubmitDefault = "default"      // no KnownTopics — accepts any topic
	ScenarioSubmitKnown   = "known-topics" // KnownTopics={tm_ship, tm_slap} — rejects others (vector .7)
)

// happyPathSubmitVectorIDs is the closed set of submit vectors that require
// a per-vector fixture handler.
var happyPathSubmitVectorIDs = map[string]bool{
	"overlay.submit.1":  true,
	"overlay.submit.2":  true,
	"overlay.submit.3":  true,
	"overlay.submit.8":  true,
	"overlay.submit.10": true,
}

func scenarioForSubmitVector(vectorID string) string {
	if happyPathSubmitVectorIDs[vectorID] {
		// Happy-path scenario key is the vector ID itself; the CLI is
		// responsible for registering a handler at this key.
		return vectorID
	}
	if vectorID == "overlay.submit.7" {
		return ScenarioSubmitKnown
	}
	return ScenarioSubmitDefault
}

// RegisterHappyPathScenariosFromVectors registers a per-vector scenario
// handler for every happy-path overlay.submit vector in file. The handler
// wraps canonical.New with a Submit callback that returns the parsed
// expected.body. Called by cmd/anvil-conformance at startup so the
// dispatcher's wiring is explicit and miswiring is observable.
func (d *OverlaySubmit) RegisterHappyPathScenariosFromVectors(file *interop.VectorFile) error {
	if file == nil {
		return fmt.Errorf("overlay.submit happy-path registration: nil vector file")
	}
	if file.ID != "overlay.submit" {
		return fmt.Errorf("overlay.submit happy-path registration: wrong file %q", file.ID)
	}
	for _, v := range file.Vectors {
		if !happyPathSubmitVectorIDs[v.ID] {
			continue
		}
		var expected submitVectorExpected
		if err := json.Unmarshal(v.Expected, &expected); err != nil {
			return fmt.Errorf("%s: parse expected: %w", v.ID, err)
		}
		h, err := makeSubmitFixtureHandler(expected.Body, v.ID)
		if err != nil {
			return fmt.Errorf("%s: %w", v.ID, err)
		}
		d.WithScenario(v.ID, h)
	}
	return nil
}

// Run implements interop.Dispatcher.
func (d *OverlaySubmit) Run(_ context.Context, _ *interop.VectorFile, v interop.Vector) interop.Result {
	result := interop.Result{
		FileID:     d.FileID(),
		VectorID:   v.ID,
		Workstream: "B",
	}

	var input submitVectorInput
	if err := json.Unmarshal(v.Input, &input); err != nil {
		result.Status = interop.StatusError
		result.Message = "parse input: " + err.Error()
		return result
	}
	var expected submitVectorExpected
	if err := json.Unmarshal(v.Expected, &expected); err != nil {
		result.Status = interop.StatusError
		result.Message = "parse expected: " + err.Error()
		return result
	}

	body, err := hex.DecodeString(input.BodyHex)
	if err != nil {
		// Vector .6 explicitly has body_hex="" — that decodes to empty bytes,
		// not an error.
		result.Status = interop.StatusError
		result.Message = "decode body_hex: " + err.Error()
		return result
	}

	// Look up the registered scenario handler. The CLI owns scenario
	// registration; missing scenarios for happy-path vectors fall back to
	// default and (almost always) FAIL — that's the safety net for
	// observable miswiring (Codex review ba3e80).
	scenario := scenarioForSubmitVector(v.ID)
	handler, ok := d.handlers[scenario]
	if !ok {
		handler = d.handlers[ScenarioSubmitDefault]
	}
	if handler == nil {
		result.Status = interop.StatusError
		result.Message = fmt.Sprintf("no handler registered for scenario %q (CLI miswire)", scenario)
		return result
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(input.Method, input.Path, bytes.NewReader(body))
	for k, val := range input.Headers {
		req.Header.Set(k, val)
	}
	handler.ServeHTTP(rec, req)

	// Status check.
	if rec.Code != expected.Status {
		result.Status = interop.StatusFail
		result.Message = fmt.Sprintf("status: got %d, want %d (body: %s)", rec.Code, expected.Status, truncate(rec.Body.String(), 160))
		return result
	}

	if rec.Code >= 200 && rec.Code < 300 {
		// Primary check: response body literally matches expected.body
		// (Codex a8dc1754 — shape-only would silently PASS empty admissions).
		if msg := assertSubmitLiteralMatch(rec.Body.Bytes(), expected.Body); msg != "" {
			result.Status = interop.StatusFail
			result.Message = msg
			return result
		}
		// Defensive: STEAK shape + topics-match guard against a vector
		// expected.body that's itself malformed.
		if msg := assertSteakShape(rec.Body.Bytes()); msg != "" {
			result.Status = interop.StatusFail
			result.Message = "(shape guard) " + msg
			return result
		}
		if msg := assertSteakTopicsMatch(rec.Body.Bytes(), input.Headers); msg != "" {
			result.Status = interop.StatusFail
			result.Message = "(topics guard) " + msg
			return result
		}
	} else {
		if msg := assertErrorBody(rec.Body.Bytes(), v.ID); msg != "" {
			result.Status = interop.StatusFail
			result.Message = msg
			return result
		}
	}

	result.Status = interop.StatusPass
	return result
}

// makeSubmitFixtureHandler builds a canonical.New handler whose Submit
// callback returns the parsed expected.body. Called by
// RegisterHappyPathScenariosFromVectors; exposed at package scope so tests
// can construct fixtures directly.
func makeSubmitFixtureHandler(expectedBody json.RawMessage, vectorID string) (http.Handler, error) {
	if len(expectedBody) == 0 {
		return nil, fmt.Errorf("%s: expected.body is empty (cannot build fixture handler)", vectorID)
	}
	var steak canonical.SubmitResponse
	if err := json.Unmarshal(expectedBody, &steak); err != nil {
		return nil, fmt.Errorf("%s: parse expected.body as STEAK: %w", vectorID, err)
	}
	cfg := canonical.Config{
		Submit: func(_ canonical.SubmitRequest) (canonical.SubmitResponse, error) {
			return steak, nil
		},
	}
	return canonical.New(cfg), nil
}

// assertSubmitLiteralMatch verifies the response body matches every
// field documented in the vector's expected.body. Uses the shared
// matchSubset helper (defined in topicmanagement.go): extra response
// fields are tolerated, missing or wrong-valued fields FAIL.
func assertSubmitLiteralMatch(rawGot, rawExpected []byte) string {
	var got, want map[string]any
	if err := json.Unmarshal(rawGot, &got); err != nil {
		return "response body is not JSON: " + err.Error()
	}
	if err := json.Unmarshal(rawExpected, &want); err != nil {
		return "vector expected.body is not JSON: " + err.Error()
	}
	return matchSubset(want, got, "")
}

// assertSteakShape validates the response body is a STEAK: map of topic name
// to {outputsToAdmit: []nat, coinstakeOutputsToRetain?: []nat}. Mirrors
// upstream overlayHelpers.ts assertSteakShape.
func assertSteakShape(raw []byte) string {
	var steak map[string]any
	if err := json.Unmarshal(raw, &steak); err != nil {
		return "STEAK body is not JSON: " + err.Error()
	}
	if steak == nil {
		return "STEAK body is null"
	}
	for topic, val := range steak {
		entry, ok := val.(map[string]any)
		if !ok {
			return fmt.Sprintf("STEAK topic %q value is not an object (%T)", topic, val)
		}
		admit, hasAdmit := entry["outputsToAdmit"]
		if !hasAdmit {
			return fmt.Sprintf("STEAK topic %q missing outputsToAdmit", topic)
		}
		admitArr, ok := admit.([]any)
		if !ok {
			return fmt.Sprintf("STEAK topic %q outputsToAdmit is not an array (%T)", topic, admit)
		}
		for i, idx := range admitArr {
			n, ok := idx.(float64)
			if !ok {
				return fmt.Sprintf("STEAK topic %q outputsToAdmit[%d] is not a number (%T)", topic, i, idx)
			}
			if n < 0 {
				return fmt.Sprintf("STEAK topic %q outputsToAdmit[%d] is negative (%v)", topic, i, n)
			}
		}
		if coinstake, present := entry["coinstakeOutputsToRetain"]; present {
			coinArr, ok := coinstake.([]any)
			if !ok {
				return fmt.Sprintf("STEAK topic %q coinstakeOutputsToRetain is not an array (%T)", topic, coinstake)
			}
			for i, idx := range coinArr {
				n, ok := idx.(float64)
				if !ok {
					return fmt.Sprintf("STEAK topic %q coinstakeOutputsToRetain[%d] is not a number (%T)", topic, i, idx)
				}
				if n < 0 {
					return fmt.Sprintf("STEAK topic %q coinstakeOutputsToRetain[%d] is negative (%v)", topic, i, n)
				}
			}
		}
	}
	return ""
}

// assertSteakTopicsMatch verifies that every key in the STEAK response is
// present in the request's x-topics header. Mirrors upstream
// overlayHelpers.ts assertSteakTopicsMatch.
func assertSteakTopicsMatch(raw []byte, headers map[string]string) string {
	var rawTopics string
	for k, v := range headers {
		if strings.EqualFold(k, "x-topics") {
			rawTopics = v
			break
		}
	}
	if rawTopics == "" {
		return ""
	}
	var requested []string
	if err := json.Unmarshal([]byte(rawTopics), &requested); err != nil {
		return ""
	}
	if len(requested) == 0 {
		return ""
	}
	requestedSet := make(map[string]bool, len(requested))
	for _, t := range requested {
		requestedSet[t] = true
	}
	var steak map[string]any
	if err := json.Unmarshal(raw, &steak); err != nil {
		return "STEAK body is not JSON: " + err.Error()
	}
	for topic := range steak {
		if !requestedSet[topic] {
			return fmt.Sprintf("STEAK contains topic %q not in request x-topics %v", topic, requested)
		}
	}
	return ""
}

// truncate clamps s to maxLen runes, appending "..." when cut.
func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}

// assertErrorBody validates the error response body. All overlay.submit
// error vectors require body.status="error". Vector .12 also requires
// body.message to be a string.
func assertErrorBody(raw []byte, vectorID string) string {
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return "error body is not JSON: " + err.Error()
	}
	if status, _ := body["status"].(string); status != "error" {
		return fmt.Sprintf("body.status = %v, want 'error'", body["status"])
	}
	if vectorID == "overlay.submit.12" {
		msg, ok := body["message"].(string)
		if !ok {
			return "vector .12: body.message is not a string"
		}
		if strings.TrimSpace(msg) == "" {
			return "vector .12: body.message is empty"
		}
	}
	return ""
}
