package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/messaging"
)

// The operator read-all-boxes switch: when
// OperatorReadsAllBoxes is true, an operator-token caller (not a BRC-31
// identity) may read any recipient's inbox instead of being scoped to
// its own; when false or unset, every caller is scoped to itself. Covers
// the POST read path (scopedRecipient), the SSE subscribe path
// (handleMessageSubscribe), and operatorBoxAllowed directly.

// TestOperatorBoxAllowed is a direct unit test of the operator-box
// predicate: naming nothing or the node's own box is always allowed;
// naming another box depends on operator_reads_all_boxes.
func TestOperatorBoxAllowed(t *testing.T) {
	srv, nodeHex := messageHandlerServer(t, messaging.Options{})
	_, other, _ := newKeyWallet(t)

	if !srv.operatorBoxAllowed("") || !srv.operatorBoxAllowed(nodeHex) {
		t.Fatal("naming nothing or the node's own box must always be allowed")
	}
	if !srv.operatorBoxAllowed(other) {
		t.Fatal("default (operator_reads_all_boxes unset) must allow naming another box")
	}

	srv.messagingPolicy.OperatorReadsAllBoxes = apiBoolPtr(false)
	if !srv.operatorBoxAllowed("") || !srv.operatorBoxAllowed(nodeHex) {
		t.Fatal("the node's own box must remain allowed even when the switch is false")
	}
	if srv.operatorBoxAllowed(other) {
		t.Fatal("naming another box must be denied when operator_reads_all_boxes is false")
	}

	srv.messagingPolicy.OperatorReadsAllBoxes = apiBoolPtr(true)
	if !srv.operatorBoxAllowed(other) {
		t.Fatal("naming another box must be allowed when the switch is explicitly true")
	}
}

// TestScopedRecipientOperatorSwitch exercises the operator-box switch's
// required test: "listing or acknowledging another box gets a 403 when the
// switch is false, and nothing changes when it is true."
func TestScopedRecipientOperatorSwitch(t *testing.T) {
	srv, nodeHex := messageHandlerServer(t, messaging.Options{})
	_, other, _ := newKeyWallet(t)
	operatorCaller := messageCaller{identityHex: nodeHex, scoped: false}

	for _, switchVal := range []*bool{nil, apiBoolPtr(true)} {
		srv.messagingPolicy.OperatorReadsAllBoxes = switchVal
		w := httptest.NewRecorder()
		got, ok := srv.scopedRecipient(w, operatorCaller, other)
		if !ok || got != other {
			t.Fatalf("switch=%v: naming another box should be unaffected: got=%q ok=%v", switchVal, got, ok)
		}
	}

	srv.messagingPolicy.OperatorReadsAllBoxes = apiBoolPtr(false)
	w := httptest.NewRecorder()
	got, ok := srv.scopedRecipient(w, operatorCaller, other)
	if ok || got != "" || w.Code != http.StatusForbidden {
		t.Fatalf("switch=false: naming another box should 403: got=%q ok=%v code=%d", got, ok, w.Code)
	}

	// The node's own box, and no recipient at all, remain allowed.
	for _, body := range []string{"", nodeHex} {
		w = httptest.NewRecorder()
		got, ok = srv.scopedRecipient(w, operatorCaller, body)
		if !ok || got != nodeHex {
			t.Fatalf("switch=false, body=%q: own box should remain allowed: got=%q ok=%v", body, got, ok)
		}
	}

	// A BRC-31-scoped caller is always restricted to its own identity,
	// regardless of the switch.
	scopedCaller := messageCaller{identityHex: other, scoped: true}
	w = httptest.NewRecorder()
	got, ok = srv.scopedRecipient(w, scopedCaller, nodeHex)
	if !ok || got != other {
		t.Fatalf("a scoped caller must stay scoped to itself regardless of body/switch: got=%q ok=%v", got, ok)
	}
}

// TestHandleMessageSubscribeOperatorSwitch is the operator-box switch's SSE path:
// the operator fallback's ?recipient= query override is gated the same
// way as scopedRecipient.
//
// Uses a real HTTP server (not httptest.NewRecorder from a second
// goroutine): the 200 cases enter handleMessageSubscribe's streaming
// loop, which keeps writing to the ResponseWriter until the request
// context is cancelled — reading a shared httptest.ResponseRecorder's
// fields from the test goroutine while that loop runs concurrently is a
// data race. A real server lets the http.Client/transport own that
// synchronization instead.
func TestHandleMessageSubscribeOperatorSwitch(t *testing.T) {
	srv := testServerWithMsgStore(t)
	_, other, _ := newKeyWallet(t)
	ts := httptest.NewServer(http.HandlerFunc(srv.handleMessageSubscribe))
	t.Cleanup(ts.Close)

	get := func(recipient string) int {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		u := ts.URL + "/messages/subscribe?messageBox=box"
		if recipient != "" {
			u += "&recipient=" + url.QueryEscape(recipient)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Anvil-Auth", srv.authToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	srv.messagingPolicy.OperatorReadsAllBoxes = apiBoolPtr(false)
	if code := get(other); code != http.StatusForbidden {
		t.Fatalf("switch=false, other recipient: code = %d", code)
	}
	if code := get(srv.identityPub); code != http.StatusOK {
		t.Fatalf("switch=false, own recipient: code = %d", code)
	}
	if code := get(""); code != http.StatusOK {
		t.Fatalf("switch=false, no recipient: code = %d", code)
	}
}
