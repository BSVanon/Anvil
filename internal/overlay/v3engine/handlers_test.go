package v3engine

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
)

// newTestServer wires the canonical handlers onto a fresh httptest
// server backed by the same fully-wired engine used by engine_test.go.
// Returns the server URL + a cleanup-tied teardown via t.Cleanup.
func newTestServer(t *testing.T) string {
	t.Helper()
	eng, _ := newTestEngine(t)
	mux := http.NewServeMux()
	NewHandlers(eng).Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestSubmitHandler_HappyPath(t *testing.T) {
	url := newTestServer(t)
	const hashHex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	tagged := buildUHRPTaggedBEEF(t, hashHex, "https://example.test/x", "image/png")

	topicsJSON, _ := json.Marshal(tagged.Topics)
	req, _ := http.NewRequest(http.MethodPost, url+"/submit", bytes.NewReader(tagged.Beef))
	req.Header.Set("x-topics", string(topicsJSON))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /submit: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	var steak overlay.Steak
	if err := json.NewDecoder(resp.Body).Decode(&steak); err != nil {
		t.Fatalf("decode steak: %v", err)
	}
	inst, ok := steak[topics.UHRPTopicName]
	if !ok || inst == nil || len(inst.OutputsToAdmit) != 1 || inst.OutputsToAdmit[0] != 0 {
		t.Fatalf("expected UHRP admit, got %+v", steak)
	}
}

func TestSubmitHandler_BadRequestPaths(t *testing.T) {
	url := newTestServer(t)

	cases := []struct {
		name      string
		method    string
		path      string
		body      []byte
		xtopics   string
		wantCode  int
		wantInMsg string
	}{
		{"wrong method", http.MethodGet, "/submit", nil, "", http.StatusMethodNotAllowed, "POST"},
		{"missing x-topics", http.MethodPost, "/submit", []byte{0x01}, "", http.StatusBadRequest, "x-topics required"},
		{"bad x-topics json", http.MethodPost, "/submit", []byte{0x01}, "not-json", http.StatusBadRequest, "invalid x-topics"},
		{"empty body", http.MethodPost, "/submit", nil, `["tm_uhrp"]`, http.StatusBadRequest, "empty body"},
		{"bad beef", http.MethodPost, "/submit", []byte{0x00, 0x01, 0x02}, `["tm_uhrp"]`, http.StatusBadRequest, "submit failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, url+tc.path, bytes.NewReader(tc.body))
			if tc.xtopics != "" {
				req.Header.Set("x-topics", tc.xtopics)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantCode {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("status: got %d want %d (%s)", resp.StatusCode, tc.wantCode, body)
			}
			assertCanonicalErrorEnvelope(t, resp.Body, tc.wantInMsg)
		})
	}
}

// TestSubmitHandler_OffChainValuesPrefix verifies the canonical
// `x-includes-off-chain-values: true` body shape from vector
// overlay.submit.8: `varint(len) + offChainValues + BEEF`.
func TestSubmitHandler_OffChainValuesPrefix(t *testing.T) {
	url := newTestServer(t)

	const hashHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	tagged := buildUHRPTaggedBEEF(t, hashHex, "https://example.test/off", "image/png")

	// Prepend a 4-byte off-chain prefix (the vector's "deadbeef") behind
	// a varint(4) length.
	offChain := []byte{0xde, 0xad, 0xbe, 0xef}
	body := append([]byte{byte(len(offChain))}, offChain...)
	body = append(body, tagged.Beef...)

	topicsJSON, _ := json.Marshal(tagged.Topics)
	req, _ := http.NewRequest(http.MethodPost, url+"/submit", bytes.NewReader(body))
	req.Header.Set("x-topics", string(topicsJSON))
	req.Header.Set("x-includes-off-chain-values", "true")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, raw)
	}
	var steak overlay.Steak
	if err := json.NewDecoder(resp.Body).Decode(&steak); err != nil {
		t.Fatalf("decode steak: %v", err)
	}
	if inst, ok := steak[topics.UHRPTopicName]; !ok || inst == nil || len(inst.OutputsToAdmit) != 1 {
		t.Fatalf("expected UHRP admit, got %+v", steak)
	}
}

// TestSubmitHandler_WrongContentTypeRejected enforces vector
// overlay.submit.11 — Content-Type: application/json (or anything not
// normalising to application/octet-stream) must yield 400 with the
// canonical error envelope, even when the body is a valid BEEF and
// x-topics is well-formed.
func TestSubmitHandler_WrongContentTypeRejected(t *testing.T) {
	url := newTestServer(t)
	const hashHex = "1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f"
	tagged := buildUHRPTaggedBEEF(t, hashHex, "", "")

	topicsJSON, _ := json.Marshal(tagged.Topics)
	req, _ := http.NewRequest(http.MethodPost, url+"/submit", bytes.NewReader(tagged.Beef))
	req.Header.Set("x-topics", string(topicsJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400 per vector overlay.submit.11, got %d: %s", resp.StatusCode, body)
	}
	assertCanonicalErrorEnvelope(t, resp.Body, "Content-Type")
}

// TestSubmitHandler_OctetStreamWithCharsetAccepted: parametric media-
// type values like "application/octet-stream; charset=binary" should
// still pass the guard. Real clients sometimes append boundary/charset
// parameters; mime.ParseMediaType strips them.
func TestSubmitHandler_OctetStreamWithCharsetAccepted(t *testing.T) {
	url := newTestServer(t)
	const hashHex = "2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e"
	tagged := buildUHRPTaggedBEEF(t, hashHex, "", "")

	topicsJSON, _ := json.Marshal(tagged.Topics)
	req, _ := http.NewRequest(http.MethodPost, url+"/submit", bytes.NewReader(tagged.Beef))
	req.Header.Set("x-topics", string(topicsJSON))
	req.Header.Set("Content-Type", "application/octet-stream; charset=binary")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 for octet-stream-with-params, got %d: %s", resp.StatusCode, body)
	}
}

// TestSubmitHandler_OffChainValuesTruncatedPrefix verifies the canonical
// error envelope when the declared prefix length exceeds the body.
func TestSubmitHandler_OffChainValuesTruncatedPrefix(t *testing.T) {
	url := newTestServer(t)
	// varint(99) but only 1 byte follows.
	body := []byte{0x63, 0x00}
	req, _ := http.NewRequest(http.MethodPost, url+"/submit", bytes.NewReader(body))
	req.Header.Set("x-topics", `["tm_uhrp"]`)
	req.Header.Set("x-includes-off-chain-values", "true")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for truncated prefix, got %d", resp.StatusCode)
	}
	assertCanonicalErrorEnvelope(t, resp.Body, "off-chain")
}

func TestLookupHandler_HappyPath(t *testing.T) {
	url := newTestServer(t)

	// Submit a UHRP entry first so the lookup has something to find.
	const hashHex = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	tagged := buildUHRPTaggedBEEF(t, hashHex, "https://example.test/y", "image/jpeg")
	topicsJSON, _ := json.Marshal(tagged.Topics)
	req, _ := http.NewRequest(http.MethodPost, url+"/submit", bytes.NewReader(tagged.Beef))
	req.Header.Set("x-topics", string(topicsJSON))
	if resp, err := http.DefaultClient.Do(req); err != nil {
		t.Fatalf("seed submit: %v", err)
	} else {
		resp.Body.Close()
	}

	q, _ := json.Marshal(topics.UHRPLookupQuery{ContentHash: hashHex})
	question := lookup.LookupQuestion{Service: topics.UHRPLookupServiceName, Query: q}
	body, _ := json.Marshal(&question)
	resp, err := http.Post(url+"/lookup", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /lookup: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, raw)
	}
	var answer lookup.LookupAnswer
	if err := json.NewDecoder(resp.Body).Decode(&answer); err != nil {
		t.Fatalf("decode answer: %v", err)
	}
	if answer.Type != lookup.AnswerTypeOutputList {
		t.Fatalf("expected output-list, got %s", answer.Type)
	}
	if len(answer.Outputs) != 1 || len(answer.Outputs[0].Beef) == 0 {
		t.Fatalf("expected 1 hydrated output, got %+v", answer.Outputs)
	}
}

// TestLookupHandler_UnknownService verifies vector overlay.lookup.6:
// unknown service returns 400 (status_oneof [400, 500]) with the
// canonical error envelope.
func TestLookupHandler_UnknownService(t *testing.T) {
	url := newTestServer(t)
	q, _ := json.Marshal(map[string]any{"service": "ls_unknown", "query": map[string]any{}})
	resp, err := http.Post(url+"/lookup", "application/json", bytes.NewReader(q))
	if err != nil {
		t.Fatalf("POST /lookup: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown service per vector overlay.lookup.6, got %d", resp.StatusCode)
	}
	assertCanonicalErrorEnvelope(t, resp.Body, "unknown lookup service")
}

// TestLookupHandler_MissingQuery enforces vector overlay.lookup.5:
// missing-query field returns 400.
func TestLookupHandler_MissingQuery(t *testing.T) {
	url := newTestServer(t)
	body := []byte(`{"service":"ls_uhrp"}`)
	resp, err := http.Post(url+"/lookup", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing query, got %d", resp.StatusCode)
	}
	assertCanonicalErrorEnvelope(t, resp.Body, "query required")
}

// TestLookupHandler_NullQueryRejected: query: null is treated as absent
// per vector overlay.lookup.5 + vector overlay.lookup.10's null-query
// rejection precedent. Body must carry the canonical error envelope —
// closing the verification gap Codex flagged in review 077b962a02931dce.
func TestLookupHandler_NullQueryRejected(t *testing.T) {
	url := newTestServer(t)
	body := []byte(`{"service":"ls_uhrp","query":null}`)
	resp, err := http.Post(url+"/lookup", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for null query, got %d", resp.StatusCode)
	}
	assertCanonicalErrorEnvelope(t, resp.Body, "query required")
}

// TestLookupHandler_AggregationBinary verifies vector overlay.lookup.3:
// `x-aggregation: yes` returns a binary application/octet-stream
// payload with the canonical header (varint(count) + per-outpoint
// records) followed by a single aggregated BEEF. We seed a UHRP entry,
// query it, and decode the binary response.
func TestLookupHandler_AggregationBinary(t *testing.T) {
	url := newTestServer(t)
	const hashHex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	tagged := buildUHRPTaggedBEEF(t, hashHex, "https://example.test/agg", "image/png")
	topicsJSON, _ := json.Marshal(tagged.Topics)
	req, _ := http.NewRequest(http.MethodPost, url+"/submit", bytes.NewReader(tagged.Beef))
	req.Header.Set("x-topics", string(topicsJSON))
	req.Header.Set("Content-Type", "application/octet-stream")
	if resp, err := http.DefaultClient.Do(req); err != nil {
		t.Fatalf("seed submit: %v", err)
	} else {
		resp.Body.Close()
	}

	q, _ := json.Marshal(map[string]any{
		"service": topics.UHRPLookupServiceName,
		"query":   topics.UHRPLookupQuery{ContentHash: hashHex},
	})
	lookupReq, _ := http.NewRequest(http.MethodPost, url+"/lookup", bytes.NewReader(q))
	lookupReq.Header.Set("Content-Type", "application/json")
	lookupReq.Header.Set("x-aggregation", "yes")
	resp, err := http.DefaultClient.Do(lookupReq)
	if err != nil {
		t.Fatalf("POST /lookup with x-aggregation: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("expected Content-Type application/octet-stream, got %q", ct)
	}
	binBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	// Parse header: varint(count) — we seeded one entry.
	if len(binBody) < 1 {
		t.Fatalf("response too short")
	}
	count := uint64(binBody[0]) // single-byte varint when value < 0xfd
	if count != 1 {
		t.Fatalf("expected count=1, got %d (raw byte=0x%x)", count, binBody[0])
	}
	cursor := 1
	// Next 32 bytes: txid LE.
	if len(binBody) < cursor+32 {
		t.Fatalf("response truncated at txid")
	}
	cursor += 32
	// varint(outputIndex) — should be 0 (1-byte varint).
	if binBody[cursor] != 0 {
		t.Fatalf("expected outputIndex=0, got %d", binBody[cursor])
	}
	cursor++
	// varint(contextLen) — should be 0 in Go canonical.
	if binBody[cursor] != 0 {
		t.Fatalf("expected contextLen=0, got %d", binBody[cursor])
	}
	cursor++
	// Remainder is the aggregated BEEF. We don't validate its exact
	// shape (transaction.NewBeefFromBytes covers that internally), but
	// it must be non-empty.
	if len(binBody)-cursor == 0 {
		t.Fatalf("aggregated BEEF missing")
	}
}

func TestLookupHandler_BadRequestPaths(t *testing.T) {
	url := newTestServer(t)
	cases := []struct {
		name     string
		method   string
		body     []byte
		wantCode int
	}{
		{"wrong method", http.MethodGet, nil, http.StatusMethodNotAllowed},
		{"invalid json", http.MethodPost, []byte("{"), http.StatusBadRequest},
		{"missing service", http.MethodPost, []byte(`{"query":{}}`), http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, url+"/lookup", bytes.NewReader(tc.body))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantCode {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("got %d want %d (%s)", resp.StatusCode, tc.wantCode, body)
			}
			assertCanonicalErrorEnvelope(t, resp.Body, "")
		})
	}
}

// assertCanonicalErrorEnvelope decodes the response body and asserts
// it matches the canonical ErrorResponse shape pinned by vector
// overlay.lookup.10: `{status:"error", message:string}`. If
// wantInMsg is non-empty, the message must contain it.
func assertCanonicalErrorEnvelope(t *testing.T, body io.Reader, wantInMsg string) {
	t.Helper()
	raw, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read error body: %v", err)
	}
	var env struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("error body is not JSON: %s (raw=%s)", err, raw)
	}
	if env.Status != "error" {
		t.Fatalf("error envelope status=%q, want \"error\" (vector overlay.lookup.10) — raw=%s", env.Status, raw)
	}
	if env.Message == "" {
		t.Fatalf("error envelope message empty — raw=%s", raw)
	}
	if wantInMsg != "" && !strings.Contains(env.Message, wantInMsg) {
		t.Fatalf("message %q does not contain %q", env.Message, wantInMsg)
	}
}

func TestListTopicManagersHandler(t *testing.T) {
	url := newTestServer(t)
	resp, err := http.Get(url + "/listTopicManagers")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var m map[string]*overlay.MetaData
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, want := range []string{
		topics.UHRPTopicName,
		topics.DEXSwapTopicName,
		topics.OrdLockTopicName,
		topics.OrdLockBuyTopicName,
	} {
		if _, ok := m[want]; !ok {
			t.Fatalf("missing topic %q in response: keys=%v", want, mapKeys(m))
		}
	}
}

func TestListLookupServiceProvidersHandler(t *testing.T) {
	url := newTestServer(t)
	resp, err := http.Get(url + "/listLookupServiceProviders")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var m map[string]*overlay.MetaData
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, want := range []string{
		topics.UHRPLookupServiceName,
		topics.DEXSwapLookupServiceName,
		topics.OrdLockLookupServiceName,
		topics.OrdLockBuyLookupServiceName,
	} {
		if _, ok := m[want]; !ok {
			t.Fatalf("missing service %q in response", want)
		}
	}
}

// TestCanonicalRoutes_RegisterWithCORSMiddleware verifies the
// production boot path: the Middleware wrap is applied to every
// canonical route INCLUDING the OPTIONS preflights so cross-origin
// browser callers (Anvil-Swap UI, SendBSV-Foundry, future TS SDK
// consumers) get the required Access-Control-* headers when they
// migrate to canonical /submit + /lookup. Codex review
// fe9707876f5618ca caught the original implementation mounting
// handlers raw — apps migrating per APP_MIGRATION_TODO.md would have
// hit cross-origin failures.
func TestCanonicalRoutes_RegisterWithCORSMiddleware(t *testing.T) {
	eng, _ := newTestEngine(t)
	mux := http.NewServeMux()

	// Sentinel middleware: stamps a marker header on every response so
	// the test can prove every canonical route went through the wrap.
	wrap := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Test-Wrapped", "yes")
			next(w, r)
		}
	}
	NewHandlers(eng).Register(mux, wrap)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	type probe struct {
		method, path string
		body         []byte
		ctype        string
	}
	probes := []probe{
		{http.MethodGet, "/listTopicManagers", nil, ""},
		{http.MethodGet, "/listLookupServiceProviders", nil, ""},
		// POST 4xx paths still go through the wrap.
		{http.MethodPost, "/submit", []byte{0x01}, "application/octet-stream"},
		{http.MethodPost, "/lookup", []byte(`{}`), "application/json"},
		{http.MethodPost, "/arc-ingest", []byte(`{}`), "application/json"},
		// OPTIONS preflights — the critical paths Codex flagged.
		{http.MethodOptions, "/submit", nil, ""},
		{http.MethodOptions, "/lookup", nil, ""},
		{http.MethodOptions, "/arc-ingest", nil, ""},
	}
	for _, p := range probes {
		req, _ := http.NewRequest(p.method, srv.URL+p.path, bytes.NewReader(p.body))
		if p.ctype != "" {
			req.Header.Set("Content-Type", p.ctype)
		}
		if p.method == http.MethodPost && p.path == "/submit" {
			req.Header.Set("x-topics", `["tm_uhrp"]`)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", p.method, p.path, err)
		}
		got := resp.Header.Get("X-Test-Wrapped")
		resp.Body.Close()
		if got != "yes" {
			t.Fatalf("%s %s: middleware not applied (X-Test-Wrapped=%q)", p.method, p.path, got)
		}
	}
}

// TestCanonicalRoutes_OptionsPreflight is the smoke test for the
// /submit, /lookup, /arc-ingest OPTIONS preflight handlers: they MUST
// return 200 (so browsers proceed with the real request) regardless
// of body or headers. The wrap middleware, when CorsWrap is wired in
// production, will then emit the Access-Control-Allow-* headers.
func TestCanonicalRoutes_OptionsPreflight(t *testing.T) {
	eng, _ := newTestEngine(t)
	mux := http.NewServeMux()
	NewHandlers(eng).Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	for _, path := range []string{"/submit", "/lookup", "/arc-ingest"} {
		t.Run(path, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodOptions, srv.URL+path, nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("OPTIONS %s: %v", path, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("OPTIONS %s: expected 200, got %d", path, resp.StatusCode)
			}
		})
	}
}

// keep hex import live so we get a clear compile error if test inputs drift.
var _ = hex.EncodeToString
