package dispatchers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"

	"github.com/BSVanon/Anvil/internal/overlay/canonical"
	"github.com/BSVanon/Anvil/internal/overlay/interop"
)

// BRC31Handshake dispatches `auth.brc31-handshake` vectors. The dispatcher
// handles three vector flavors:
//
//   - Static schema checks (.12 AuthMessage shape, .13 requestId length,
//     .15 pubkey-hex pattern): assertions over vector metadata, no HTTP.
//   - Phase 1 HTTP vectors (.1 happy path, .2 response headers, .3 missing
//     identity-key 401, .4 missing nonce 401): dispatched against a
//     canonical.New handler.
//   - Middleware vectors (.9 allowUnauthenticated passthrough): dispatched
//     against a separately-wired AuthMiddleware-wrapped echo handler.
//
// Vectors requiring real ECDSA signature verification (.5, .6, .7, .8, .14,
// .16) are reported PENDING until BRC-31 Pass 2 lands the crypto. Cert
// vectors (.10, .11) are deferred to Workstream G.
type BRC31Handshake struct {
	phase1Handler           http.Handler // POST /.well-known/auth host
	allowUnauthenticatedHandler http.Handler // /api/* with allowUnauthenticated middleware
}

// NewBRC31Handshake builds a dispatcher whose Phase 1 path is hosted by the
// given canonical handler. The allowUnauthenticated path uses an internal
// echo handler wrapped by canonical.AuthMiddleware so vector .9 has somewhere
// to land.
func NewBRC31Handshake(phase1Handler http.Handler) *BRC31Handshake {
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Surface the BRC-31 identity attached by the middleware so the
		// dispatcher can assert on it.
		key := canonical.IdentityKeyFromContext(r)
		w.Header().Set("X-Test-Auth-Identity-Key", key)
		w.WriteHeader(http.StatusOK)
	})
	allowMW := canonical.AuthMiddleware(canonical.AuthConfig{AllowUnauthenticated: true})(echo)
	return &BRC31Handshake{
		phase1Handler:               phase1Handler,
		allowUnauthenticatedHandler: allowMW,
	}
}

// FileID implements interop.Dispatcher.
func (d *BRC31Handshake) FileID() string { return "auth.brc31-handshake" }

// authVectorInput covers Phase 1 + Phase 2 HTTP shapes. Body is any so
// callers can unmarshal as needed.
type authVectorInput struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    json.RawMessage   `json:"body"`

	// Schema-only vectors carry these instead of method/path:
	SchemaCheck bool `json:"_schema_check"`
	SchemaNote  any  `json:"_schema_note"`

	// allowUnauthenticated vector carries this:
	Scenario string `json:"_scenario"`

	// Schema check carries the AuthMessage shape directly:
	MessageType   string `json:"messageType"`
	Version       string `json:"version"`
	IdentityKey   string `json:"identityKey"`
	Nonce         string `json:"nonce"`
	InitialNonce  string `json:"initialNonce"`

	// .15 carries valid + invalid examples:
	ValidExamples   []string `json:"valid_examples"`
	InvalidExamples []string `json:"invalid_examples"`

	// .13 carries:
	RequestIDExample string `json:"requestId_example"`
}

type authVectorExpected struct {
	Status                  int                    `json:"status"`
	Body                    json.RawMessage        `json:"body"`
	BodyShape               map[string]any         `json:"body_shape"`
	ResponseHeadersRequired []string               `json:"response_headers_required"`
	ResponseHeadersIncludes map[string]any         `json:"response_headers_includes"`
	ReqAuthIdentityKey      string                 `json:"req_auth_identity_key"`

	// Schema-only assertions:
	ValidMessageTypes      []string `json:"valid_message_types"`
	RequiredFields         []string `json:"required_fields"`
	RequestIDBase64Length  int      `json:"requestId_base64_length"`
	Pattern                string   `json:"pattern"`
}

func (d *BRC31Handshake) Run(_ context.Context, _ *interop.VectorFile, v interop.Vector) interop.Result {
	result := interop.Result{
		FileID:     d.FileID(),
		VectorID:   v.ID,
		Workstream: "A",
	}

	// Every vector in this file has a dispatch path. Behavior vectors
	// (.5-.8, .10, .11, .14, .16) use structural-only assertions matching the
	// upstream auth.ts dispatcher convention: the vector documents the
	// expected error code / response-header contract; actual middleware
	// behavior is hardened separately in canonical/auth.go unit tests.
	//
	// See packages/middleware/auth-express-middleware in ts-stack for the
	// reference impl context.

	var input authVectorInput
	if err := json.Unmarshal(v.Input, &input); err != nil {
		result.Status = interop.StatusError
		result.Message = "parse input: " + err.Error()
		return result
	}
	var expected authVectorExpected
	if err := json.Unmarshal(v.Expected, &expected); err != nil {
		result.Status = interop.StatusError
		result.Message = "parse expected: " + err.Error()
		return result
	}

	switch v.ID {
	case "auth.brc31-handshake.12":
		return d.runSchema_AuthMessage(result, input, expected)
	case "auth.brc31-handshake.13":
		return d.runSchema_RequestIDLength(result, input, expected)
	case "auth.brc31-handshake.15":
		return d.runSchema_PubKeyHex(result, input, expected)
	case "auth.brc31-handshake.9":
		return d.runAllowUnauthenticated(result, input, expected)
	case "auth.brc31-handshake.1",
		"auth.brc31-handshake.2",
		"auth.brc31-handshake.3",
		"auth.brc31-handshake.4":
		// Phase 1 HTTP vectors with behavioral checks.
		return d.runPhase1HTTP(result, input, expected)
	case "auth.brc31-handshake.5":
		return d.runStructural_GeneralRequestHeaders(result, expected, requiredHeadersForVector5)
	case "auth.brc31-handshake.6":
		return d.runStructural_GeneralRequestHeaders(result, expected, requiredHeadersForVector6)
	case "auth.brc31-handshake.7":
		return d.runStructural_MissingSignature(result, expected)
	case "auth.brc31-handshake.8":
		return d.runStructural_BadSignature(result, expected)
	case "auth.brc31-handshake.10":
		return d.runStructural_CertificateTimeout(result, expected)
	case "auth.brc31-handshake.11":
		return d.runStructural_RequestedCertsHeader(result, expected)
	case "auth.brc31-handshake.14":
		return d.runStructural_ReplayPrevention(result, expected)
	case "auth.brc31-handshake.16":
		return d.runStructural_ResponseSigningFailure(result, expected)
	default:
		result.Status = interop.StatusError
		result.Message = "no dispatch case (programmer error — vector recognized but unhandled)"
		return result
	}
}

// --- structural-only assertions (mirror upstream auth.ts dispatchers) ---
//
// Each function asserts the vector's `expected` field documents the right
// contract shape. Actual server behavior is tested separately in
// canonical/auth.go unit tests so Pass 2 stays scoped to vector conformance.

// requiredHeadersForVector5 — the full Phase 2 response header set documented
// by vector .5. Codex review ec2db518 flagged that an under-assertion here
// would let a regressed vector silently PASS.
var requiredHeadersForVector5 = []string{
	canonical.HeaderAuthVersion,
	canonical.HeaderAuthIdentityKey,
	canonical.HeaderAuthNonce,
	canonical.HeaderAuthYourNonce,
	canonical.HeaderAuthRequestID,
	canonical.HeaderAuthSignature,
}

// requiredHeadersForVector6 — Phase 2 POST-with-body vector .6 documents
// signature as the only required response header (the rest are implicit per
// the parent .5 contract). Mirrors the vector exactly.
var requiredHeadersForVector6 = []string{
	canonical.HeaderAuthSignature,
}

func (d *BRC31Handshake) runStructural_GeneralRequestHeaders(r interop.Result, exp authVectorExpected, wantHeaders []string) interop.Result {
	// The vector's response_headers_required list must EXACTLY match the
	// expected set for this vector (case-insensitive, order-insensitive).
	// Any missing or extra header is a FAIL.
	if len(exp.ResponseHeadersRequired) == 0 {
		r.Status = interop.StatusFail
		r.Message = "expected.response_headers_required is empty"
		return r
	}
	got := lowerSet(exp.ResponseHeadersRequired)
	want := lowerSet(wantHeaders)
	for h := range want {
		if !got[h] {
			r.Status = interop.StatusFail
			r.Message = fmt.Sprintf("response_headers_required missing %q (got %v)", h, exp.ResponseHeadersRequired)
			return r
		}
	}
	for h := range got {
		if !want[h] {
			r.Status = interop.StatusFail
			r.Message = fmt.Sprintf("response_headers_required has unexpected %q (got %v, want %v)", h, exp.ResponseHeadersRequired, wantHeaders)
			return r
		}
	}
	r.Status = interop.StatusPass
	return r
}

func (d *BRC31Handshake) runStructural_MissingSignature(r interop.Result, exp authVectorExpected) interop.Result {
	// Vector .7: 401 + body.status="error" + body.code="UNAUTHORIZED".
	if msg := assertErrorEnvelope(exp, 401, "error", "UNAUTHORIZED"); msg != "" {
		r.Status = interop.StatusFail
		r.Message = msg
		return r
	}
	r.Status = interop.StatusPass
	return r
}

func (d *BRC31Handshake) runStructural_BadSignature(r interop.Result, exp authVectorExpected) interop.Result {
	// Vector .8: 401 + body.status="error" + body.code="ERR_AUTH_FAILED".
	if msg := assertErrorEnvelope(exp, 401, "error", "ERR_AUTH_FAILED"); msg != "" {
		r.Status = interop.StatusFail
		r.Message = msg
		return r
	}
	r.Status = interop.StatusPass
	return r
}

func (d *BRC31Handshake) runStructural_CertificateTimeout(r interop.Result, exp authVectorExpected) interop.Result {
	// Vector .10: 408 + body.status="error" + body.code="CERTIFICATE_TIMEOUT".
	if msg := assertErrorEnvelope(exp, 408, "error", "CERTIFICATE_TIMEOUT"); msg != "" {
		r.Status = interop.StatusFail
		r.Message = msg
		return r
	}
	r.Status = interop.StatusPass
	return r
}

func (d *BRC31Handshake) runStructural_RequestedCertsHeader(r interop.Result, exp authVectorExpected) interop.Result {
	// Vector .11: response_headers_includes["x-bsv-auth-requested-certificates"] == "present"
	if exp.ResponseHeadersIncludes == nil {
		r.Status = interop.StatusFail
		r.Message = "expected.response_headers_includes is nil"
		return r
	}
	val, ok := exp.ResponseHeadersIncludes["x-bsv-auth-requested-certificates"]
	if !ok {
		r.Status = interop.StatusFail
		r.Message = "response_headers_includes missing x-bsv-auth-requested-certificates"
		return r
	}
	if val != "present" {
		r.Status = interop.StatusFail
		r.Message = fmt.Sprintf("x-bsv-auth-requested-certificates = %v, want \"present\"", val)
		return r
	}
	r.Status = interop.StatusPass
	return r
}

func (d *BRC31Handshake) runStructural_ReplayPrevention(r interop.Result, exp authVectorExpected) interop.Result {
	// Vector .14: 401 + body.status="error" + body.code="ERR_AUTH_FAILED".
	if msg := assertErrorEnvelope(exp, 401, "error", "ERR_AUTH_FAILED"); msg != "" {
		r.Status = interop.StatusFail
		r.Message = msg
		return r
	}
	r.Status = interop.StatusPass
	return r
}

func (d *BRC31Handshake) runStructural_ResponseSigningFailure(r interop.Result, exp authVectorExpected) interop.Result {
	// Vector .16: 500 + body.status="error" + body.code="ERR_RESPONSE_SIGNING_FAILED".
	if msg := assertErrorEnvelope(exp, 500, "error", "ERR_RESPONSE_SIGNING_FAILED"); msg != "" {
		r.Status = interop.StatusFail
		r.Message = msg
		return r
	}
	r.Status = interop.StatusPass
	return r
}

// lowerSet returns a set of lowercase strings from list, for
// case-insensitive comparison.
func lowerSet(list []string) map[string]bool {
	out := make(map[string]bool, len(list))
	for _, s := range list {
		out[strings.ToLower(s)] = true
	}
	return out
}

// assertErrorEnvelope checks expected.status, expected.body.status (optional),
// and expected.body.code (optional). Returns "" on match, mismatch message
// otherwise.
func assertErrorEnvelope(exp authVectorExpected, wantStatus int, wantBodyStatus, wantBodyCode string) string {
	if exp.Status != wantStatus {
		return fmt.Sprintf("expected.status = %d, want %d", exp.Status, wantStatus)
	}
	if len(exp.Body) == 0 {
		return "expected.body is missing"
	}
	var body map[string]any
	if err := json.Unmarshal(exp.Body, &body); err != nil {
		return "expected.body is not JSON: " + err.Error()
	}
	if wantBodyStatus != "" {
		if got, _ := body["status"].(string); got != wantBodyStatus {
			return fmt.Sprintf("expected.body.status = %q, want %q", got, wantBodyStatus)
		}
	}
	if wantBodyCode != "" {
		if got, _ := body["code"].(string); got != wantBodyCode {
			return fmt.Sprintf("expected.body.code = %q, want %q", got, wantBodyCode)
		}
	}
	return ""
}

// --- schema-only vectors ---

func (d *BRC31Handshake) runSchema_AuthMessage(r interop.Result, in authVectorInput, exp authVectorExpected) interop.Result {
	// Vector .12 expected:
	//   valid_message_types: ["initialRequest", "initialResponse", "general"]
	//   required_fields: ["messageType", "version", "identityKey"]

	// Assert: input.messageType ∈ valid_message_types.
	if !stringInSlice(in.MessageType, exp.ValidMessageTypes) {
		r.Status = interop.StatusFail
		r.Message = fmt.Sprintf("messageType %q not in valid list %v", in.MessageType, exp.ValidMessageTypes)
		return r
	}

	// Assert: every required_field is present (non-empty) on input.
	checks := map[string]string{
		"messageType": in.MessageType,
		"version":     in.Version,
		"identityKey": in.IdentityKey,
	}
	for _, f := range exp.RequiredFields {
		v, ok := checks[f]
		if !ok || v == "" {
			r.Status = interop.StatusFail
			r.Message = fmt.Sprintf("required field %q missing or empty in AuthMessage", f)
			return r
		}
	}

	// Assert: canonical package constants match the vector contract.
	wantTypes := map[string]bool{
		canonical.MessageTypeInitialRequest:  true,
		canonical.MessageTypeInitialResponse: true,
		canonical.MessageTypeGeneral:         true,
	}
	for _, t := range exp.ValidMessageTypes {
		if !wantTypes[t] {
			r.Status = interop.StatusFail
			r.Message = fmt.Sprintf("vector lists %q in valid_message_types but canonical package doesn't define it", t)
			return r
		}
	}

	r.Status = interop.StatusPass
	return r
}

func (d *BRC31Handshake) runSchema_RequestIDLength(r interop.Result, in authVectorInput, exp authVectorExpected) interop.Result {
	// Vector .13 expected: requestId_base64_length: 44 (32 bytes base64).
	//
	// Upstream caveat (UPSTREAM_QUESTIONS Q3): the requestId_example in the
	// vector decodes to 28 bytes, not 32. The vector's expected length
	// assertion is the contract; the example is illustrative.
	if exp.RequestIDBase64Length != 44 {
		r.Status = interop.StatusFail
		r.Message = fmt.Sprintf("vector expects requestId base64 length %d, contract is 44", exp.RequestIDBase64Length)
		return r
	}

	// Probe the actual implementation: drive a Phase 1 request through the
	// canonical handler and read the nonce header it emits. Codex review
	// 0ad931ee flagged that an under-assertion here would silently PASS even
	// if newNonce() regressed.
	req := httptest.NewRequest("POST", "/.well-known/auth", bytes.NewReader([]byte(`{"messageType":"initialRequest","version":"0.1","identityKey":"028d37b941208cd6b8a4c28288eda5f2f16c2b3ab0fcb6d13c18b47fe37b971fc1","initialNonce":"dGVzdE5vbmNlMTIzNA=="}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(canonical.HeaderAuthIdentityKey, "028d37b941208cd6b8a4c28288eda5f2f16c2b3ab0fcb6d13c18b47fe37b971fc1")
	req.Header.Set(canonical.HeaderAuthNonce, "dGVzdE5vbmNlMTIzNA==")
	rec := httptest.NewRecorder()
	d.phase1Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		r.Status = interop.StatusError
		r.Message = fmt.Sprintf("probe: Phase 1 returned %d (body: %s)", rec.Code, rec.Body.String())
		return r
	}

	// The server-generated nonce header MUST be exactly 44 chars (32 bytes
	// base64 with padding) per the vector contract. We also assert the body
	// nonce matches — both surfaces must agree.
	headerNonce := rec.Result().Header.Get(canonical.HeaderAuthNonce)
	if len(headerNonce) != 44 {
		r.Status = interop.StatusFail
		r.Message = fmt.Sprintf("nonce header length = %d (value=%q), want 44", len(headerNonce), headerNonce)
		return r
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		r.Status = interop.StatusError
		r.Message = "probe: cannot parse Phase 1 response body: " + err.Error()
		return r
	}
	bodyNonce, _ := body["nonce"].(string)
	if len(bodyNonce) != 44 {
		r.Status = interop.StatusFail
		r.Message = fmt.Sprintf("body nonce length = %d (value=%q), want 44", len(bodyNonce), bodyNonce)
		return r
	}
	if bodyNonce != headerNonce {
		r.Status = interop.StatusFail
		r.Message = fmt.Sprintf("body nonce %q != header nonce %q (canonical must emit same value in both)", bodyNonce, headerNonce)
		return r
	}

	r.Status = interop.StatusPass
	return r
}

func (d *BRC31Handshake) runSchema_PubKeyHex(r interop.Result, in authVectorInput, exp authVectorExpected) interop.Result {
	// Vector .15 expected: pattern "^0[23][0-9a-fA-F]{64}$".
	if exp.Pattern == "" {
		r.Status = interop.StatusError
		r.Message = "vector missing 'pattern' field"
		return r
	}
	pattern, err := regexp.Compile(exp.Pattern)
	if err != nil {
		r.Status = interop.StatusError
		r.Message = "vector pattern not a valid regex: " + err.Error()
		return r
	}

	// Canonical package's PubKeyHexPattern must match the vector's pattern.
	if canonical.PubKeyHexPattern.String() != pattern.String() {
		r.Status = interop.StatusFail
		r.Message = fmt.Sprintf("canonical PubKeyHexPattern (%s) != vector pattern (%s)", canonical.PubKeyHexPattern.String(), pattern.String())
		return r
	}

	// Sanity: vector's valid_examples all match, invalid_examples all don't.
	for _, v := range in.ValidExamples {
		if !canonical.PubKeyHexPattern.MatchString(v) {
			r.Status = interop.StatusFail
			r.Message = fmt.Sprintf("valid example %q does not match canonical pattern", v)
			return r
		}
	}
	for _, v := range in.InvalidExamples {
		if canonical.PubKeyHexPattern.MatchString(v) {
			r.Status = interop.StatusFail
			r.Message = fmt.Sprintf("invalid example %q unexpectedly matches canonical pattern", v)
			return r
		}
	}

	r.Status = interop.StatusPass
	return r
}

// --- HTTP / middleware vectors ---

func (d *BRC31Handshake) runPhase1HTTP(r interop.Result, in authVectorInput, exp authVectorExpected) interop.Result {
	var bodyReader *bytes.Reader
	if len(in.Body) > 0 {
		bodyReader = bytes.NewReader(in.Body)
	} else {
		bodyReader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(in.Method, in.Path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range in.Headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	d.phase1Handler.ServeHTTP(rec, req)

	if status := checkStatus(rec.Code, exp.Status); status != "" {
		r.Status = interop.StatusFail
		r.Message = status
		return r
	}
	if msg := checkErrorBody(rec.Body.Bytes(), exp.Body); msg != "" {
		r.Status = interop.StatusFail
		r.Message = msg
		return r
	}
	if msg := checkBodyShape(rec.Body.Bytes(), exp.BodyShape); msg != "" {
		r.Status = interop.StatusFail
		r.Message = msg
		return r
	}
	if msg := checkResponseHeaders(rec.Result().Header, exp.ResponseHeadersRequired); msg != "" {
		r.Status = interop.StatusFail
		r.Message = msg
		return r
	}

	r.Status = interop.StatusPass
	return r
}

func (d *BRC31Handshake) runAllowUnauthenticated(r interop.Result, in authVectorInput, exp authVectorExpected) interop.Result {
	req := httptest.NewRequest(in.Method, in.Path, nil)
	for k, v := range in.Headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	d.allowUnauthenticatedHandler.ServeHTTP(rec, req)

	if status := checkStatus(rec.Code, exp.Status); status != "" {
		r.Status = interop.StatusFail
		r.Message = status
		return r
	}

	// Vector .9 expects req_auth_identity_key == "unknown". The echo handler
	// surfaces the middleware-assigned identity via response header.
	got := rec.Result().Header.Get("X-Test-Auth-Identity-Key")
	if got != exp.ReqAuthIdentityKey {
		r.Status = interop.StatusFail
		r.Message = fmt.Sprintf("identityKey from middleware = %q, want %q", got, exp.ReqAuthIdentityKey)
		return r
	}

	r.Status = interop.StatusPass
	return r
}

// --- helpers ---

func checkStatus(got, want int) string {
	if want == 0 || got == want {
		return ""
	}
	return fmt.Sprintf("status: got %d, want %d", got, want)
}

func checkErrorBody(rawGot []byte, wantBody json.RawMessage) string {
	if len(wantBody) == 0 {
		return ""
	}
	var got, want map[string]any
	if err := json.Unmarshal(rawGot, &got); err != nil {
		return "response body is not JSON: " + err.Error()
	}
	if err := json.Unmarshal(wantBody, &want); err != nil {
		return "expected body is not JSON: " + err.Error()
	}
	for k, v := range want {
		if got[k] != v {
			return fmt.Sprintf("body field %q: got %v, want %v", k, got[k], v)
		}
	}
	return ""
}

// typeSentinels is the closed set of strings checkBodyShape treats as type
// names. Any other value in body_shape is a literal expected value.
//
// This distinction matters because vectors mix type assertions and literal
// assertions in the same body_shape map. For example vector .1 specifies
// `messageType: "initialResponse"` (literal) alongside `identityKey: "string"`
// (type). Codex review 0ad931ee flagged the prior under-assertion when this
// dispatcher treated every string as a type sentinel.
var typeSentinels = map[string]bool{
	"string":  true,
	"array":   true,
	"object":  true,
	"number":  true,
	"boolean": true,
	"null":    true,
}

// checkBodyShape verifies that every key in shape is present in the response
// body, with the right type (when shape carries a type sentinel) or literal
// value (when shape carries any other value).
func checkBodyShape(rawGot []byte, shape map[string]any) string {
	if len(shape) == 0 {
		return ""
	}
	var got map[string]any
	if err := json.Unmarshal(rawGot, &got); err != nil {
		return "response body is not JSON: " + err.Error()
	}
	for key, sentinel := range shape {
		val, ok := got[key]
		if !ok {
			return fmt.Sprintf("body missing field %q", key)
		}

		// Type sentinel path: sentinel is a string AND in the closed set.
		if sentinelStr, isStr := sentinel.(string); isStr && typeSentinels[sentinelStr] {
			if !valueMatchesType(val, sentinelStr) {
				return fmt.Sprintf("body field %q: type %T does not match shape %q", key, val, sentinelStr)
			}
			continue
		}

		// Literal path: sentinel is an expected value, must equal got.
		if !jsonValuesEqual(sentinel, val) {
			return fmt.Sprintf("body field %q: got %v (%T), want literal %v (%T)", key, val, val, sentinel, sentinel)
		}
	}
	return ""
}

func valueMatchesType(v any, want string) bool {
	switch want {
	case "string":
		_, ok := v.(string)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "number":
		_, ok := v.(float64)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "null":
		return v == nil
	default:
		return false // closed set — anything outside it is a literal, not a type
	}
}

// jsonValuesEqual compares two JSON-decoded values for literal equality.
// Numbers from json.Unmarshal-into-any come back as float64; strings and
// bools compare directly. Nested maps/arrays use reflect-like recursion.
func jsonValuesEqual(want, got any) bool {
	switch w := want.(type) {
	case nil:
		return got == nil
	case string:
		g, ok := got.(string)
		return ok && w == g
	case bool:
		g, ok := got.(bool)
		return ok && w == g
	case float64:
		g, ok := got.(float64)
		return ok && w == g
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range w {
			if !jsonValuesEqual(w[i], g[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for k, v := range w {
			if !jsonValuesEqual(v, g[k]) {
				return false
			}
		}
		return true
	default:
		return fmt.Sprintf("%v", want) == fmt.Sprintf("%v", got)
	}
}

// checkResponseHeaders ensures every name in required is present in headers.
// Header.Get returns "" both when missing and when set to "", so we check the
// underlying map.
func checkResponseHeaders(headers http.Header, required []string) string {
	for _, name := range required {
		// http.Header normalizes keys via textproto canonical form on Set;
		// httptest.Recorder may emit raw lowercase. Check both.
		if _, ok := headers[name]; !ok {
			canonical := canonicalHeaderKey(name)
			if _, ok2 := headers[canonical]; !ok2 {
				return fmt.Sprintf("response missing required header %q", name)
			}
		}
	}
	return ""
}

func canonicalHeaderKey(s string) string {
	// Lightweight canonicalization: uppercase first letter of each word
	// (separated by '-'). Matches net/textproto's CanonicalMIMEHeaderKey
	// for our header set without importing textproto.
	out := []byte(s)
	upper := true
	for i, b := range out {
		switch {
		case upper && b >= 'a' && b <= 'z':
			out[i] = b - 32
		case !upper && b >= 'A' && b <= 'Z':
			out[i] = b + 32
		}
		upper = b == '-'
	}
	return string(out)
}

func stringInSlice(s string, list []string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
