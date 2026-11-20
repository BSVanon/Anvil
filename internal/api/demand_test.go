package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestOperatorQueryDoesNotCountTowardDemand: GET /data with the operator's
// own bearer token must not increment the gossip demand counter — only a
// non-operator read (anonymous, payer, or app-token) should. Demand drives
// the heartbeat's advertised interest to the rest of the mesh; an operator
// reading their own node's data is not evidence that anyone else wants it.
func TestOperatorQueryDoesNotCountTowardDemand(t *testing.T) {
	srv, mgr := testServerWithGossip(t)
	const topic = "oracle:demand-check"
	storePublicTopic(t, srv, topic)

	req := httptest.NewRequest("GET", "/data?topic="+topic+"&limit=10", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}

	if d := mgr.TopicDemand(topic); d != 0 {
		t.Fatalf("an operator-authenticated read must not count toward demand; got %d", d)
	}

	// An anonymous read on the same topic DOES count, confirming the guard
	// is specific to the operator credential, not a wholesale removal of
	// demand tracking.
	req2 := httptest.NewRequest("GET", "/data?topic="+topic+"&limit=10", nil)
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w2.Code, w2.Body.String())
	}
	if d := mgr.TopicDemand(topic); d != 1 {
		t.Fatalf("an anonymous read should count toward demand; got %d", d)
	}
}

// TestOperatorSubscribeDoesNotCountTowardDemand: the SSE analog of
// TestOperatorQueryDoesNotCountTowardDemand — GET /data/subscribe with the
// operator's own bearer token must not increment demand either.
func TestOperatorSubscribeDoesNotCountTowardDemand(t *testing.T) {
	srv, mgr := testServerWithGossip(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	const topic = "oracle:sse-demand-check"
	resp, cancel := subscribeSSE(t, ts, "/data/subscribe?topic="+topic, "", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer test-token")
	})
	defer cancel()
	defer resp.Body.Close()

	waitForSSESubscription(t, srv, topic)

	if d := mgr.TopicDemand(topic); d != 0 {
		t.Fatalf("an operator-authenticated subscribe must not count toward demand; got %d", d)
	}
}
