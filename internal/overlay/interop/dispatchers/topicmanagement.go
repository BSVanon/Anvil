// Package dispatchers wires Anvil-specific Go code to the runner's
// Dispatcher interface. One Go file per VectorFile.ID; e.g. this file
// handles `overlay.topicmanagement`.
//
// Each dispatcher is responsible for:
//   - parsing Vector.Input into a typed shape
//   - exercising the relevant Anvil surface (HTTP handler, engine call, etc.)
//   - parsing Vector.Expected and asserting against actual behavior
//   - returning a Result with PASS / FAIL / SKIP / ERROR
//
// Conventions:
//   - Use in-process execution (httptest.NewRecorder) for HTTP vectors. Live
//     network execution is reserved for Workstream F Phase 7 against
//     overlay-express.
//   - SKIP vectors that require infrastructure we don't have yet (fault
//     injection, BRC-31 keys, etc.) with an informative SkipReason.
package dispatchers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/BSVanon/Anvil/internal/overlay/interop"
)

// Scenario names route vectors to the right pre-built handler. Each scenario
// represents a distinct node-state fixture (admin identity present, not-ready,
// etc.). The default scenario is used when a vector doesn't specify otherwise.
const (
	ScenarioDefault           = "default"        // ready, no admin identity, nodeName=overlay-node
	ScenarioNotReady          = "not-ready"      // ready=false (vector .2)
	ScenarioWithAdminIdentity = "admin-identity" // admin/config: identity set + nodeName=overlay-test-node (vector .5)
	ScenarioAdminStats        = "admin-stats"    // admin/stats: bearer token + topic/lookup names (vector .8)
)

// TopicManagement dispatches `overlay.topicmanagement` vectors against one
// of several pre-built http.Handler fixtures, keyed by scenario.
//
// Different vectors require different node configurations:
//   - .1, .3, .4: default ready node
//   - .2: not-ready node (returns 503 on /health)
//   - .5: node with admin identity + different nodeName
//   - .6: default node (no admin identity)
//
// Production wires every scenario it has a handler for; if a vector requests
// a scenario the dispatcher doesn't have, the dispatcher falls back to default
// and (often) FAILs honestly rather than silently SKIPping. That fall-back
// failure is the safety net Codex review b126d8fc asked for.
type TopicManagement struct {
	handlers map[string]http.Handler
}

// NewTopicManagement returns a dispatcher with the default-scenario handler.
// Attach additional scenarios via WithScenario.
func NewTopicManagement(handler http.Handler) *TopicManagement {
	return &TopicManagement{
		handlers: map[string]http.Handler{
			ScenarioDefault: handler,
		},
	}
}

// WithScenario attaches a handler for the named scenario. Returns the same
// dispatcher for chaining.
func (d *TopicManagement) WithScenario(name string, h http.Handler) *TopicManagement {
	d.handlers[name] = h
	return d
}

// WithNotReadyHandler is shorthand for WithScenario(ScenarioNotReady, h).
// Kept for callers wired before the scenario API existed.
func (d *TopicManagement) WithNotReadyHandler(h http.Handler) *TopicManagement {
	return d.WithScenario(ScenarioNotReady, h)
}

// FileID implements interop.Dispatcher.
func (d *TopicManagement) FileID() string { return "overlay.topicmanagement" }

// vectorInput is the canonical request shape used by every HTTP-style vector
// in this file. Body is present for POST vectors (.17, .18 ARC ingest).
type vectorInput struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    json.RawMessage   `json:"body"`
}

// vectorExpected is the canonical response shape for the health-class vectors.
// Body is JSON; status_oneof captures multi-status vectors.
type vectorExpected struct {
	Status       int             `json:"status"`
	StatusOneOf  []int           `json:"status_oneof"`
	Body         json.RawMessage `json:"body"`
	SchemaNote   string          `json:"schema_note"`
}

// Run implements interop.Dispatcher.
func (d *TopicManagement) Run(_ context.Context, _ *interop.VectorFile, v interop.Vector) interop.Result {
	// Workstream is always per-vector (not per-file) so the runner's
	// PendingByWorkstream aggregation distinguishes A from D honestly.
	result := interop.Result{
		FileID:     d.FileID(),
		VectorID:   v.ID,
		Workstream: workstreamForVector(v.ID),
	}

	// Vectors covered by the current slice (Workstream A). Anything else
	// lands as PENDING with its owning workstream so the report is honest
	// about what's not implemented yet.
	switch v.ID {
	case "overlay.topicmanagement.1",
		"overlay.topicmanagement.2",
		"overlay.topicmanagement.3",
		"overlay.topicmanagement.4",
		"overlay.topicmanagement.5",
		"overlay.topicmanagement.6",
		"overlay.topicmanagement.7",
		"overlay.topicmanagement.8",
		"overlay.topicmanagement.17",
		"overlay.topicmanagement.18":
		// Real run.
	default:
		result.Status = interop.StatusPending
		result.Message = fmt.Sprintf("dispatcher recognized vector but no handler wired yet (workstream %s)", result.Workstream)
		return result
	}

	var input vectorInput
	if err := json.Unmarshal(v.Input, &input); err != nil {
		result.Status = interop.StatusError
		result.Message = "parse input: " + err.Error()
		return result
	}
	var expected vectorExpected
	if err := json.Unmarshal(v.Expected, &expected); err != nil {
		result.Status = interop.StatusError
		result.Message = "parse expected: " + err.Error()
		return result
	}

	// Pick the handler fixture this vector requires. If the dispatcher
	// doesn't have the named scenario wired, we fall back to default — that
	// usually FAILs the vector honestly (matching Codex b126d8fc's "no
	// silent SKIPs" rule).
	scenario := scenarioForVector(v.ID)
	handler, ok := d.handlers[scenario]
	if !ok {
		handler = d.handlers[ScenarioDefault]
	}

	rec := httptest.NewRecorder()
	var bodyReader *bytes.Reader
	if len(input.Body) > 0 {
		bodyReader = bytes.NewReader(input.Body)
	} else {
		bodyReader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(input.Method, input.Path, bodyReader)
	for k, val := range input.Headers {
		req.Header.Set(k, val)
	}
	handler.ServeHTTP(rec, req)

	// Status check.
	if expected.Status != 0 && rec.Code != expected.Status {
		result.Status = interop.StatusFail
		result.Message = fmt.Sprintf("status: got %d, want %d", rec.Code, expected.Status)
		return result
	}
	if len(expected.StatusOneOf) > 0 && !intInSlice(rec.Code, expected.StatusOneOf) {
		result.Status = interop.StatusFail
		result.Message = fmt.Sprintf("status: got %d, want one of %v", rec.Code, expected.StatusOneOf)
		return result
	}

	// Body shape check.
	if len(expected.Body) > 0 {
		var gotBody map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &gotBody); err != nil {
			result.Status = interop.StatusFail
			result.Message = "response body is not JSON: " + err.Error()
			return result
		}
		var wantBody map[string]any
		if err := json.Unmarshal(expected.Body, &wantBody); err != nil {
			result.Status = interop.StatusError
			result.Message = "parse expected body: " + err.Error()
			return result
		}
		if mismatch := matchSubset(wantBody, gotBody, ""); mismatch != "" {
			result.Status = interop.StatusFail
			result.Message = "body mismatch: " + mismatch
			return result
		}
	}

	result.Status = interop.StatusPass
	return result
}

// matchSubset asserts every key/value in want is present in got with a matching
// value. Supports the `*_oneof` convention used by the vectors (e.g.
// `status_oneof: ["degraded","error"]` against `status: "degraded"`).
// Returns "" on match, or a human-readable mismatch description.
func matchSubset(want, got map[string]any, prefix string) string {
	for key, wantVal := range want {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}

		// `<field>_oneof` style: look for the bare `<field>` in got and
		// check the got-value is in the want-list.
		if oneOfKey, ok := strings.CutSuffix(key, "_oneof"); ok {
			gotVal, present := got[oneOfKey]
			if !present {
				return fmt.Sprintf("missing field %q", oneOfKey)
			}
			list, ok := wantVal.([]any)
			if !ok {
				return fmt.Sprintf("expected %s to be a list, got %T", path, wantVal)
			}
			if !anyInSlice(gotVal, list) {
				return fmt.Sprintf("%s = %v, want one of %v", oneOfKey, gotVal, list)
			}
			continue
		}

		gotVal, present := got[key]
		if !present {
			return fmt.Sprintf("missing field %q", path)
		}

		// Recurse into nested objects.
		if wantMap, ok := wantVal.(map[string]any); ok {
			gotMap, ok := gotVal.(map[string]any)
			if !ok {
				return fmt.Sprintf("%s: want object, got %T", path, gotVal)
			}
			if msg := matchSubset(wantMap, gotMap, path); msg != "" {
				return msg
			}
			continue
		}

		if !valuesEqual(wantVal, gotVal) {
			return fmt.Sprintf("%s = %v, want %v", path, gotVal, wantVal)
		}
	}
	return ""
}

// valuesEqual compares JSON-decoded values. Numbers from json.Unmarshal-into-any
// come back as float64; this normalizes int and float comparisons.
func valuesEqual(want, got any) bool {
	switch w := want.(type) {
	case float64:
		if g, ok := got.(float64); ok {
			return w == g
		}
		return false
	case string:
		g, ok := got.(string)
		return ok && w == g
	case bool:
		g, ok := got.(bool)
		return ok && w == g
	case nil:
		return got == nil
	default:
		return fmt.Sprintf("%v", want) == fmt.Sprintf("%v", got)
	}
}

// scenarioForVector returns the handler scenario this vector requires.
// Vectors that don't specify return ScenarioDefault.
func scenarioForVector(vectorID string) string {
	switch vectorID {
	case "overlay.topicmanagement.2":
		return ScenarioNotReady
	case "overlay.topicmanagement.5":
		return ScenarioWithAdminIdentity
	case "overlay.topicmanagement.8":
		return ScenarioAdminStats
	default:
		return ScenarioDefault
	}
}

func intInSlice(n int, list []int) bool {
	for _, v := range list {
		if v == n {
			return true
		}
	}
	return false
}

func anyInSlice(target any, list []any) bool {
	for _, v := range list {
		if valuesEqual(target, v) {
			return true
		}
	}
	return false
}

// workstreamForVector classifies one specific overlay.topicmanagement.* vector
// into the workstream that owns implementing it. Used only for honest PENDING
// messages while real handlers are landing.
func workstreamForVector(vectorID string) string {
	switch vectorID {
	case "overlay.topicmanagement.1",
		"overlay.topicmanagement.2",
		"overlay.topicmanagement.3",
		"overlay.topicmanagement.4":
		return "A"
	case "overlay.topicmanagement.5",
		"overlay.topicmanagement.6",
		"overlay.topicmanagement.7",
		"overlay.topicmanagement.8",
		"overlay.topicmanagement.17",
		"overlay.topicmanagement.18":
		return "A"
	case "overlay.topicmanagement.9",
		"overlay.topicmanagement.10",
		"overlay.topicmanagement.11",
		"overlay.topicmanagement.12",
		"overlay.topicmanagement.13",
		"overlay.topicmanagement.14",
		"overlay.topicmanagement.15",
		"overlay.topicmanagement.16":
		return "D"
	default:
		return "?"
	}
}
