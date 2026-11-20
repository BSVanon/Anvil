package api

import (
	"net/http/httptest"
	"testing"
)

// TestIsAppContentRouteOnlyGetData: app monetization (passthrough/split
// pricing, token gating) must only ever be consulted on the two routes
// that actually serve a topic's content — GET /data and GET /data/subscribe
// (SSE). A mutation that widened this to any GET, or dropped the method
// check, would reopen cold review's BL2(a)/RISK 3: a topic's own pricing or
// token model waiving or replacing the node's toll on every other route,
// and on every write.
func TestIsAppContentRouteOnlyGetData(t *testing.T) {
	cases := []struct {
		method string
		path   string
		want   bool
	}{
		{"GET", "/data", true},
		{"GET", "/data/subscribe", true},
		{"GET", "/status", false},
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
