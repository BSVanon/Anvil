package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// TestIsAppContentRouteOnlyDataReads: app monetization (passthrough/split
// pricing, token gating) must only ever be consulted on the two routes that
// actually serve a topic's content, GET /data and GET /data/subscribe (SSE),
// and on HEAD to either. A mutation that widened this to any GET, or dropped
// the method check, would let a topic's own pricing or token model waive or
// replace the node's toll on every other route, and on every write.
func TestIsAppContentRouteOnlyDataReads(t *testing.T) {
	cases := []struct {
		method string
		path   string
		want   bool
	}{
		{"GET", "/data", true},
		{"GET", "/data/subscribe", true},
		{"HEAD", "/data", true},
		{"HEAD", "/data/subscribe", true},
		{"GET", "/status", false},
		{"HEAD", "/status", false},
		{"GET", "/headers/tip", false},
		{"GET", "/mempool/watch", false},
		{"GET", "/content/abc", false},
		{"POST", "/data", false},      // a write to the data route is not a content read
		{"POST", "/broadcast", false}, // every write is a node route, never app-priced
		{"DELETE", "/data", false},
		{"GET", "/data/subscribe/", false}, // not an exact path match
		{"GET", "/dataset", false},         // not an exact path match, despite the prefix
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path+"?topic=x", nil)
		if got := isAppContentRoute(req); got != c.want {
			t.Errorf("isAppContentRoute(%s %s) = %v, want %v", c.method, c.path, got, c.want)
		}
	}
}

// TestHeadOnDataGetsTheAnswerGetGets: the mux serves HEAD /data with the GET
// handler, so HEAD goes through the same content rules: 401 for a
// token-gated topic and 402 for a priced one, where a HEAD outside them got
// 200 and the content's Content-Length.
func TestHeadOnDataGetsTheAnswerGetGets(t *testing.T) {
	srv := testServer(t)
	key, _ := ec.NewPrivateKey()
	base := time.Now().Unix()
	seedEnvelopeAt(t, srv.envelopeStore, "tg", `{"x":1}`, base, tokenModel(key))
	seedEnvelopeAt(t, srv.envelopeStore, "pp", `{"x":1}`, base, passthrough(appPayeeScript(), 1000))
	srv.tokenGate = NewTokenGate(NewTopicMonetizationResolver(srv.envelopeStore), true)
	srv.paymentGate = testGateWithAppPayments(t, 0, srv.envelopeStore)
	srv.mux = http.NewServeMux()
	srv.routes()

	for path, want := range map[string]int{
		"/data?topic=tg": http.StatusUnauthorized,
		"/data?topic=pp": http.StatusPaymentRequired,
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			req := httptest.NewRequest(method, path, nil)
			req.Host = "localhost"
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)
			if w.Code != want {
				t.Errorf("%s %s: got %d, want %d", method, path, w.Code, want)
			}
		}
	}
}
