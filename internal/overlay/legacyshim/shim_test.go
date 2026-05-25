package legacyshim_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/overlay/legacyshim"
	anvilstorage "github.com/BSVanon/Anvil/internal/overlay/storage"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/BSVanon/Anvil/internal/overlay/v3engine"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

// newWiredShim builds the full canonical stack (storage adapter +
// headers store + lookups db + v3 engine) and wraps it in a
// legacyshim.Shim ready for HTTP tests. Mirrors the wiring in
// v3engine/engine_test.go to keep the tests honest about end-to-end
// behaviour.
func newWiredShim(t *testing.T) *legacyshim.Shim {
	t.Helper()
	root := t.TempDir()

	storageDB, err := leveldb.OpenFile(filepath.Join(root, "storage"), nil)
	if err != nil {
		t.Fatalf("storage db: %v", err)
	}
	t.Cleanup(func() { _ = storageDB.Close() })

	lookupDB, err := leveldb.OpenFile(filepath.Join(root, "lookup"), nil)
	if err != nil {
		t.Fatalf("lookup db: %v", err)
	}
	t.Cleanup(func() { _ = lookupDB.Close() })

	hdrStore, err := headers.NewTestStore(filepath.Join(root, "headers"))
	if err != nil {
		t.Fatalf("headers store: %v", err)
	}
	t.Cleanup(func() { _ = hdrStore.Close() })

	eng, err := v3engine.New(&v3engine.Config{
		Storage:      anvilstorage.New(storageDB),
		HeadersStore: hdrStore,
		LookupDB:     lookupDB,
		HostingURL:   "https://anvil.test",
	})
	if err != nil {
		t.Fatalf("v3engine.New: %v", err)
	}

	return &legacyshim.Shim{
		Engine:        eng,
		Parsers:       legacyshim.DefaultParsers(),
		ServiceTopics: legacyshim.DefaultServiceTopics(),
	}
}

// newShimServer is the httptest harness — mounts the shim routes on a
// fresh mux and returns the live URL.
func newShimServer(t *testing.T) string {
	t.Helper()
	shim := newWiredShim(t)
	mux := http.NewServeMux()
	shim.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// buildUHRPAtomicBEEF produces a single-output tx whose locking
// script is a BRC-26 UHRP advertisement for the given content hash,
// wrapped in atomic BEEF. Used by both the legacy submit path
// (octet-stream + X-Topics) and the JSON-bodied path.
func buildUHRPAtomicBEEF(t *testing.T, contentHashHex string) []byte {
	t.Helper()
	hashBytes, err := hex.DecodeString(contentHashHex)
	if err != nil || len(hashBytes) != 32 {
		t.Fatalf("bad content hash: %v", err)
	}
	scriptBytes := []byte{0x00, 0x6a, byte(len(topics.UHRPProtocolID))}
	scriptBytes = append(scriptBytes, []byte(topics.UHRPProtocolID)...)
	scriptBytes = append(scriptBytes, byte(len(hashBytes)))
	scriptBytes = append(scriptBytes, hashBytes...)

	tx := transaction.NewTransaction()
	s := script.Script(scriptBytes)
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: &s, Satoshis: 0})
	beef, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		t.Fatalf("NewBeefFromTransaction: %v", err)
	}
	atomic, err := beef.AtomicBytes(tx.TxID())
	if err != nil {
		t.Fatalf("AtomicBytes: %v", err)
	}
	return atomic
}

// --- /overlay/submit -----------------------------------------------------

func TestLegacySubmit_JSONBody(t *testing.T) {
	url := newShimServer(t)
	const hashHex = "1111111111111111111111111111111111111111111111111111111111111111"
	beef := buildUHRPAtomicBEEF(t, hashHex)

	body, _ := json.Marshal(map[string]any{
		"beef":   beef,
		"topics": []string{topics.UHRPTopicName},
	})
	resp, err := http.Post(url+"/overlay/submit", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, raw)
	}

	var steak map[string]map[string][]int
	if err := json.NewDecoder(resp.Body).Decode(&steak); err != nil {
		t.Fatalf("decode steak: %v", err)
	}
	inst, ok := steak[topics.UHRPTopicName]
	if !ok {
		t.Fatalf("missing %q in steak: %+v", topics.UHRPTopicName, steak)
	}
	if got := inst["outputsToAdmit"]; len(got) != 1 || got[0] != 0 {
		t.Fatalf("outputsToAdmit = %v, want [0]", got)
	}
}

func TestLegacySubmit_BinaryWithXTopicsHeader(t *testing.T) {
	url := newShimServer(t)
	const hashHex = "2222222222222222222222222222222222222222222222222222222222222222"
	beef := buildUHRPAtomicBEEF(t, hashHex)

	req, _ := http.NewRequest(http.MethodPost, url+"/overlay/submit", bytes.NewReader(beef))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Topics", `["tm_uhrp"]`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, raw)
	}
}

func TestLegacySubmit_LegacyErrorEnvelope(t *testing.T) {
	url := newShimServer(t)
	resp, err := http.Post(url+"/overlay/submit", "application/json", bytes.NewReader([]byte(`{"beef":null}`)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	var env map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env["error"] == "" {
		t.Fatalf("expected legacy {\"error\": ...} envelope, got %+v", env)
	}
	if _, hasStatus := env["status"]; hasStatus {
		t.Fatalf("shim must NOT emit canonical {status,message} envelope on legacy routes")
	}
}

// --- /overlay/query ------------------------------------------------------

func TestLegacyQuery_RoundTripWithMetadataReconstruction(t *testing.T) {
	shim := newWiredShim(t)
	mux := http.NewServeMux()
	shim.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Seed via the legacy submit path so we exercise the full
	// submit→query roundtrip.
	const hashHex = "3333333333333333333333333333333333333333333333333333333333333333"
	beef := buildUHRPAtomicBEEF(t, hashHex)
	submitBody, _ := json.Marshal(map[string]any{
		"beef":   beef,
		"topics": []string{topics.UHRPTopicName},
	})
	resp, err := http.Post(srv.URL+"/overlay/submit", "application/json", bytes.NewReader(submitBody))
	if err != nil {
		t.Fatalf("seed submit: %v", err)
	}
	resp.Body.Close()

	// Now query — should return one output, with Metadata reconstructed
	// from the BEEF (UHRPEntry shape: {content_hash, url, content_type}).
	q, _ := json.Marshal(map[string]any{
		"service": topics.UHRPLookupServiceName,
		"query":   topics.UHRPLookupQuery{ContentHash: hashHex},
	})
	resp, err = http.Post(srv.URL+"/overlay/query", "application/json", bytes.NewReader(q))
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, raw)
	}

	var answer struct {
		Type    string `json:"type"`
		Outputs []struct {
			Txid         string          `json:"txid"`
			Vout         int             `json:"vout"`
			Topic        string          `json:"topic"`
			OutputScript []byte          `json:"outputScript"`
			Metadata     json.RawMessage `json:"metadata"`
		} `json:"outputs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&answer); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if answer.Type != "output-list" {
		t.Fatalf("expected output-list, got %q", answer.Type)
	}
	if len(answer.Outputs) != 1 {
		t.Fatalf("expected 1 output, got %d", len(answer.Outputs))
	}
	out := answer.Outputs[0]
	if out.Topic != topics.UHRPTopicName {
		t.Fatalf("topic = %q, want %q", out.Topic, topics.UHRPTopicName)
	}
	if len(out.OutputScript) == 0 {
		t.Fatalf("outputScript missing")
	}
	// Metadata must round-trip to a UHRPEntry with the seeded hash.
	var entry topics.UHRPEntry
	if err := json.Unmarshal(out.Metadata, &entry); err != nil {
		t.Fatalf("decode metadata: %v (raw=%s)", err, out.Metadata)
	}
	if !strings.EqualFold(entry.ContentHash, hashHex) {
		t.Fatalf("metadata content hash = %q, want %q", entry.ContentHash, hashHex)
	}
}

func TestLegacyQuery_MissingService(t *testing.T) {
	url := newShimServer(t)
	resp, err := http.Post(url+"/overlay/query", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

// --- /overlay/topics + /overlay/services --------------------------------

func TestLegacyListTopicsAndServices(t *testing.T) {
	url := newShimServer(t)

	resp, err := http.Get(url + "/overlay/topics")
	if err != nil {
		t.Fatalf("GET topics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("topics status %d", resp.StatusCode)
	}
	var topicsMap map[string]map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&topicsMap); err != nil {
		t.Fatalf("decode topics: %v", err)
	}
	for _, want := range []string{
		topics.UHRPTopicName,
		topics.DEXSwapTopicName,
		topics.OrdLockTopicName,
		topics.OrdLockBuyTopicName,
	} {
		if _, ok := topicsMap[want]; !ok {
			t.Fatalf("missing topic %q in legacy /overlay/topics response", want)
		}
	}

	resp2, err := http.Get(url + "/overlay/services")
	if err != nil {
		t.Fatalf("GET services: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("services status %d", resp2.StatusCode)
	}
	var svcMap map[string]map[string]any
	if err := json.NewDecoder(resp2.Body).Decode(&svcMap); err != nil {
		t.Fatalf("decode services: %v", err)
	}
	for _, want := range []string{
		topics.UHRPLookupServiceName,
		topics.DEXSwapLookupServiceName,
		topics.OrdLockLookupServiceName,
		topics.OrdLockBuyLookupServiceName,
	} {
		if _, ok := svcMap[want]; !ok {
			t.Fatalf("missing service %q in legacy /overlay/services response", want)
		}
	}
}

// TestLegacyListServices_TopicsFieldPresent asserts the per-service
// `topics` array surfaces in GET /overlay/services exactly the way
// internal/overlay/handlers.go:135-143 returned it pre-shim. Codex
// review d671fa17fe5cc746 caught the first draft silently dropping
// this field — Anvil-Swap and the TS SDK both treat it as required.
func TestLegacyListServices_TopicsFieldPresent(t *testing.T) {
	url := newShimServer(t)
	resp, err := http.Get(url + "/overlay/services")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var services map[string]struct {
		Documentation string         `json:"documentation"`
		Metadata      map[string]any `json:"metadata"`
		Topics        []string       `json:"topics"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&services); err != nil {
		t.Fatalf("decode: %v", err)
	}
	wantTopics := map[string]string{
		topics.UHRPLookupServiceName:       topics.UHRPTopicName,
		topics.DEXSwapLookupServiceName:    topics.DEXSwapTopicName,
		topics.OrdLockLookupServiceName:    topics.OrdLockTopicName,
		topics.OrdLockBuyLookupServiceName: topics.OrdLockBuyTopicName,
	}
	for svc, wantTopic := range wantTopics {
		entry, ok := services[svc]
		if !ok {
			t.Fatalf("service %q missing from /overlay/services", svc)
		}
		if len(entry.Topics) != 1 || entry.Topics[0] != wantTopic {
			t.Fatalf("service %q topics = %v, want [%s]", svc, entry.Topics, wantTopic)
		}
	}
}

// TestShim_RegisterWithCORSMiddleware verifies the boot path: the
// Middleware wrap is applied to every legacy route so browser callers
// see the same Access-Control-* headers they received before the shim.
// Without this Foundry's cross-origin /overlay/submit + Anvil-Swap's
// browser-side discovery POSTs would regress with CORS errors.
func TestShim_RegisterWithCORSMiddleware(t *testing.T) {
	shim := newWiredShim(t)
	mux := http.NewServeMux()

	// Sentinel middleware: stamps a marker header on every response so
	// the test can prove every legacy route went through the wrap.
	wrap := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Test-Wrapped", "yes")
			next(w, r)
		}
	}
	shim.Register(mux, wrap)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	type probe struct {
		method, path string
		body         []byte
	}
	probes := []probe{
		{http.MethodGet, "/overlay/topics", nil},
		{http.MethodGet, "/overlay/services", nil},
		// Submit + Query intentionally bad-body so we exercise the
		// 4xx path; the wrap should still have stamped the header.
		{http.MethodPost, "/overlay/submit", []byte(`{}`)},
		{http.MethodPost, "/overlay/query", []byte(`{}`)},
		{http.MethodOptions, "/overlay/submit", nil},
		{http.MethodOptions, "/overlay/query", nil},
	}
	for _, p := range probes {
		req, _ := http.NewRequest(p.method, srv.URL+p.path, bytes.NewReader(p.body))
		if len(p.body) > 0 {
			req.Header.Set("Content-Type", "application/json")
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

// TestShim_RegisterWithNilMiddleware proves nil-middleware is a
// supported no-op path (tests use it; boot code MUST NOT).
func TestShim_RegisterWithNilMiddleware(t *testing.T) {
	shim := newWiredShim(t)
	mux := http.NewServeMux()
	shim.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/overlay/topics")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("nil-middleware path failed: status %d", resp.StatusCode)
	}
}

// --- direct package-level smoke ------------------------------------------

func TestDefaultServiceTopics_MapsAllFourServices(t *testing.T) {
	m := legacyshim.DefaultServiceTopics()
	wants := map[string]string{
		topics.UHRPLookupServiceName:       topics.UHRPTopicName,
		topics.DEXSwapLookupServiceName:    topics.DEXSwapTopicName,
		topics.OrdLockLookupServiceName:    topics.OrdLockTopicName,
		topics.OrdLockBuyLookupServiceName: topics.OrdLockBuyTopicName,
	}
	for svc, wantTopic := range wants {
		got, ok := m[svc]
		if !ok {
			t.Fatalf("DefaultServiceTopics missing %q", svc)
		}
		if len(got) != 1 || got[0] != wantTopic {
			t.Fatalf("DefaultServiceTopics[%q] = %v, want [%s]", svc, got, wantTopic)
		}
	}
}

func TestDefaultParsers_CoverAllFourServices(t *testing.T) {
	parsers := legacyshim.DefaultParsers()
	for _, svc := range []string{
		topics.UHRPLookupServiceName,
		topics.DEXSwapLookupServiceName,
		topics.OrdLockLookupServiceName,
		topics.OrdLockBuyLookupServiceName,
	} {
		if _, ok := parsers[svc]; !ok {
			t.Fatalf("DefaultParsers missing %q", svc)
		}
	}
}

// keep unused-import-guard at the bottom so future imports show up
// cleanly.
var _ = context.Background
var _ = engine.SubmitModeCurrent
var _ overlay.TaggedBEEF
