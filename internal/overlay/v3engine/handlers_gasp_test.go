package v3engine

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-overlay-services/pkg/core/gasp"
)

// TestGASP_RoutesRegistered_BadRequestPaths exercises the canonical
// /requestSyncResponse and /requestForeignGASPNode routes for their
// bad-request paths. The federation surface is wired into v3engine.Register
// in W-10.3 — these tests pin the route registration + error envelope,
// even before the Advertiser implementation lands.
func TestGASP_RoutesRegistered_BadRequestPaths(t *testing.T) {
	url := newTestServer(t)

	// 64-hex placeholder txid used in valid-shape payloads below.
	const validHexTxid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	validNodeReq := []byte(`{"graphID":"` + validHexTxid + `.0","txid":"` + validHexTxid + `","outputIndex":0,"metadata":false}`)

	cases := []struct {
		name      string
		method    string
		path      string
		body      []byte
		topic     string
		wantCode  int
		wantInMsg string
	}{
		{"wrong method sync", http.MethodGet, "/requestSyncResponse", nil, "", http.StatusMethodNotAllowed, "POST"},
		{"missing topic sync", http.MethodPost, "/requestSyncResponse", []byte(`{"version":1,"since":0}`), "", http.StatusBadRequest, "X-BSV-Topic"},
		{"bad json sync", http.MethodPost, "/requestSyncResponse", []byte(`not-json`), "tm_uhrp", http.StatusBadRequest, "invalid JSON"},
		{"wrong method node", http.MethodGet, "/requestForeignGASPNode", nil, "", http.StatusMethodNotAllowed, "POST"},
		{"missing topic node", http.MethodPost, "/requestForeignGASPNode", validNodeReq, "", http.StatusBadRequest, "X-BSV-Topic"},
		{"bad json node", http.MethodPost, "/requestForeignGASPNode", []byte(`not-json`), "tm_uhrp", http.StatusBadRequest, "invalid JSON"},
		{"missing graphID", http.MethodPost, "/requestForeignGASPNode", []byte(`{"txid":"` + validHexTxid + `","outputIndex":0}`), "tm_uhrp", http.StatusBadRequest, "graphID required"},
		{"missing txid", http.MethodPost, "/requestForeignGASPNode", []byte(`{"graphID":"` + validHexTxid + `.0","outputIndex":0}`), "tm_uhrp", http.StatusBadRequest, "txid required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, url+tc.path, bytes.NewReader(tc.body))
			if tc.topic != "" {
				req.Header.Set("X-BSV-Topic", tc.topic)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantCode {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected status %d, got %d: %s", tc.wantCode, resp.StatusCode, body)
			}
			body, _ := io.ReadAll(resp.Body)
			var envelope struct {
				Status  string `json:"status"`
				Message string `json:"message"`
			}
			if err := json.Unmarshal(body, &envelope); err != nil {
				t.Fatalf("expected canonical error envelope, got %s", body)
			}
			if envelope.Status != "error" {
				t.Fatalf("expected status=error, got %q", envelope.Status)
			}
			if !strings.Contains(envelope.Message, tc.wantInMsg) {
				t.Fatalf("expected message containing %q, got %q", tc.wantInMsg, envelope.Message)
			}
		})
	}
}

// TestGASP_RequestForeignGASPNode_MissingOutputReturns404 pins the
// canonical 404 mapping for the missing-output sentinel. Without this,
// federation peers asking for a node we don't have would see a 500 —
// indistinguishable from a real server error and likely to trigger
// retries that compound load on a node that simply doesn't have the
// requested state. Codex review 24358e121cfe3e64 caught the original
// implementation mapping every error to 500.
func TestGASP_RequestForeignGASPNode_MissingOutputReturns404(t *testing.T) {
	url := newTestServer(t)
	// 64-hex txid the fresh test engine has never admitted; the engine
	// returns engine.ErrNotFound which the handler must translate to
	// HTTP 404.
	const unknownTxid = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	body := []byte(`{"graphID":"` + unknownTxid + `.0","txid":"` + unknownTxid + `","outputIndex":0,"metadata":false}`)
	req, _ := http.NewRequest(http.MethodPost, url+"/requestForeignGASPNode", bytes.NewReader(body))
	req.Header.Set("X-BSV-Topic", "tm_uhrp")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 404, got %d: %s", resp.StatusCode, raw)
	}
	var envelope struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		t.Fatalf("expected canonical error envelope: %v", err)
	}
	if envelope.Status != "error" {
		t.Fatalf("expected status=error, got %q", envelope.Status)
	}
	if !strings.Contains(envelope.Message, "not found") {
		t.Fatalf("expected 'not found' message, got %q", envelope.Message)
	}
}

// TestGASP_RequestSyncResponse_EmptyTopicReturnsCanonicalInitialResponse
// confirms that asking for sync state on a topic with no admitted
// outputs returns a canonical gasp.InitialResponse JSON (UTXOList:[],
// since:0) rather than null or an error. Bit-identical with what the
// upstream OverlayGASPRemote.GetInitialResponse decoder expects, so a
// peer hitting our Anvil node sees the same wire shape it would see
// hitting any other canonical overlay node.
func TestGASP_RequestSyncResponse_EmptyTopicReturnsCanonicalInitialResponse(t *testing.T) {
	url := newTestServer(t)
	body, _ := json.Marshal(gasp.InitialRequest{Version: 1, Since: 0})
	req, _ := http.NewRequest(http.MethodPost, url+"/requestSyncResponse", bytes.NewReader(body))
	req.Header.Set("X-BSV-Topic", "tm_uhrp")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, raw)
	}
	// Decode into the canonical type — must round-trip cleanly through
	// the same gasp.InitialResponse type the upstream client decodes.
	var out gasp.InitialResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode canonical gasp.InitialResponse: %v", err)
	}
	if out.UTXOList == nil {
		t.Fatalf("UTXOList must be empty slice not nil (canonical wire format expects []*gasp.Output)")
	}
	if len(out.UTXOList) != 0 {
		t.Fatalf("expected empty UTXOList for fresh engine, got %d entries", len(out.UTXOList))
	}
}
