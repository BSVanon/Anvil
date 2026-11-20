package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	authhttp "github.com/bsv-blockchain/go-sdk/auth/clients/authhttp"
)

// capturedBRC31Request is one proxied HTTP request, captured verbatim so it
// can be replayed byte-for-byte. A fresh request signed by the same wallet
// would mint a fresh nonce and would not reproduce a replay; only resending
// the exact bytes of a request already accepted once does.
type capturedBRC31Request struct {
	method, path string
	hdr          http.Header
	body         []byte
}

// TestBRC31ReplayedNonceGets401 proves a verbatim replay of an authenticated
// messagebox request answers 401, not go-bsv-middleware's default 500 — see
// brc31ReplayNonceStatus's doc comment (brc31_messagebox.go) for the status
// and its citation. The first, honest request must still succeed normally.
func TestBRC31ReplayedNonceGets401(t *testing.T) {
	srv, _, _ := testServerBRC31(t)

	// A capturing proxy sits in front of the real handler so the exact
	// signed request (headers and body) can be captured and replayed
	// verbatim.
	var mu sync.Mutex
	var captured []capturedBRC31Request
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(b))
		mu.Lock()
		captured = append(captured, capturedBRC31Request{r.Method, r.URL.RequestURI(), r.Header.Clone(), b})
		mu.Unlock()
		srv.Handler().ServeHTTP(w, r)
	}))
	defer proxy.Close()

	_, _, callerWallet := newKeyWallet(t)
	client := authhttp.New(callerWallet)
	first, err := client.Fetch(context.Background(), proxy.URL+"/listMessages", &authhttp.SimplifiedFetchRequestOptions{
		Method:  "POST",
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    []byte(`{"messageBox":"inbox"}`),
	})
	if err != nil {
		t.Fatalf("authenticated fetch: %v", err)
	}
	first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first, honest request: status %d, want 200 (an honest request must be unaffected)", first.StatusCode)
	}

	mu.Lock()
	var gen *capturedBRC31Request
	for i := range captured {
		if captured[i].path == "/listMessages" {
			gen = &captured[i]
		}
	}
	mu.Unlock()
	if gen == nil {
		t.Fatal("no captured /listMessages request to replay")
	}

	replay, err := http.NewRequest(gen.method, proxy.URL+gen.path, bytes.NewReader(gen.body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range gen.hdr {
		replay.Header[k] = v
	}
	resp, err := http.DefaultClient.Do(replay)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusInternalServerError {
		t.Fatalf("replayed nonce still answers 500 (body: %s)", raw)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed nonce: status %d, want 401 (body: %s)", resp.StatusCode, raw)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("replay body not JSON: %v (%s)", err, raw)
	}
	if out["code"] != "ERR_REPLAYED_NONCE" {
		t.Errorf("replay body code = %v, want ERR_REPLAYED_NONCE (%s)", out["code"], raw)
	}
}
