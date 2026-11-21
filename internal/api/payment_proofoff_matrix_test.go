package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func assertNoProofChallenge(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if got := w.Header().Get(HeaderX402Challenge); got != "" {
		t.Fatalf("response carried %s: %q", HeaderX402Challenge, got)
	}
}

func assertNoChallengeActivity(t *testing.T, pg *PaymentGate, provider *countingProvider) {
	t.Helper()
	pg.mu.Lock()
	pending, reserved := len(pg.pendingChallenges), pg.reservedPending
	pg.mu.Unlock()
	if mints := provider.mints.Load(); mints != 0 || pending != 0 || reserved != 0 {
		t.Fatalf("challenge activity with proof scheme off: mints=%d pending=%d reserved=%d", mints, pending, reserved)
	}
}

func TestProofOffNeverMintsAcrossPricedRequests(t *testing.T) {
	arc := usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
		return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
	})
	fixture := newBRC121Fix(t, 100)
	provider := &countingProvider{}
	fixture.pg.noProofScheme = true
	fixture.pg.nonceProvider = provider
	fixture.pg.arcClient = arc

	srv := testServer(t)
	srv.paymentGate = fixture.pg
	rebuildRoutes(srv)

	validDirect := func() map[string]string {
		return map[string]string{HeaderBSVPayment: signedEFPaying(t, paidOut{testPayeeScript(t), 100})}
	}
	validBRC121 := func() map[string]string {
		return fixture.payment(t, 100, brc121Pay{})
	}
	malformedBase := validBRC121()
	malformedBRC121 := func(header string) func() map[string]string {
		return func() map[string]string {
			h := make(map[string]string, len(malformedBase))
			for name, value := range malformedBase {
				h[name] = value
			}
			h[header] = "malformed"
			return h
		}
	}
	headerCases := []struct {
		name    string
		headers func() map[string]string
	}{
		{"none", func() map[string]string { return nil }},
		{"proof", func() map[string]string { return map[string]string{HeaderX402Proof: base64Url([]byte(`{}`))} }},
		{"direct", validDirect},
		{"proof and direct", func() map[string]string {
			h := validDirect()
			h[HeaderX402Proof] = base64Url([]byte(`{}`))
			return h
		}},
		{"brc121", validBRC121},
		{"malformed proof", func() map[string]string { return map[string]string{HeaderX402Proof: "%%%"} }},
		{"malformed direct", func() map[string]string { return map[string]string{HeaderBSVPayment: "%%%"} }},
		{"malformed brc121 beef", malformedBRC121(headerBRC121Beef)},
		{"malformed brc121 sender", malformedBRC121(headerBRC121Sender)},
		{"malformed brc121 nonce", malformedBRC121(headerBRC121Nonce)},
		{"malformed brc121 time", malformedBRC121(headerBRC121Time)},
		{"malformed brc121 vout", malformedBRC121(headerBRC121Vout)},
	}

	for _, route := range pricedRouteCases() {
		for _, headers := range headerCases {
			t.Run(route.name+"/"+headers.name, func(t *testing.T) {
				row := route
				if !strings.Contains(row.path, "?") {
					row.path += "?shape=priced"
				} else {
					row.path += "&shape=priced"
				}
				w := serveRouteCase(srv, row, headers.headers())
				assertNoProofChallenge(t, w)
				assertNoChallengeActivity(t, fixture.pg, provider)
			})
		}
	}

	large := pricedRouteCase{name: "large body", method: http.MethodPost, path: "/data?shape=large", body: bytes.Repeat([]byte("x"), 2<<20)}
	w := serveRouteCase(srv, large, nil)
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("large unpaid request got %d, want 402", w.Code)
	}
	assertNoProofChallenge(t, w)

	for i := 0; i < 20; i++ {
		w = serveRouteCase(srv, pricedRouteCase{method: http.MethodGet, path: "/status?repeat=yes"}, nil)
		if w.Code != http.StatusPaymentRequired {
			t.Fatalf("repeated request %d got %d, want 402", i, w.Code)
		}
		assertNoProofChallenge(t, w)
	}

	const concurrent = 32
	var wg sync.WaitGroup
	results := make(chan *httptest.ResponseRecorder, concurrent)
	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- serveRouteCase(srv, pricedRouteCase{method: http.MethodGet, path: "/status?concurrent=yes"}, nil)
		}()
	}
	wg.Wait()
	close(results)
	for result := range results {
		if result.Code != http.StatusPaymentRequired {
			t.Fatalf("concurrent request got %d, want 402", result.Code)
		}
		assertNoProofChallenge(t, result)
	}
	assertNoChallengeActivity(t, fixture.pg, provider)
}
