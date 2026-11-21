package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// The node's own price, decided per envelope, still lets every honest payer
// and every free node through: each topic below is served once its own
// rules are met, and only then.

// nodePriceRequest is a GET of path carrying the node price gate records
// for it, and, when outputs is not nil, a verified payment of those outputs.
func nodePriceRequest(t *testing.T, pg *PaymentGate, path string, outputs ...paidOut) *http.Request {
	t.Helper()
	r := pg.withNodePrice(httptest.NewRequest(http.MethodGet, path, nil))
	if outputs == nil {
		return r
	}
	paid := map[string]uint64{}
	for _, o := range outputs {
		script := scriptOutput(t, o.script, o.sats).LockingScript
		paid[string(*script)] = o.sats
	}
	return r.WithContext(pg.withPayment(r.Context(), &X402Receipt{outputs: paid}))
}

// TestNodePriceCoveredByTheNodesScriptOnly pins the rule each node-priced
// envelope is decided by: one output to the node's own script, at least the
// price the gate recorded for the route.
func TestNodePriceCoveredByTheNodesScriptOnly(t *testing.T) {
	pg := testGate(t, 100)
	pg.endpointPrices = map[string]int{"/data/subscribe": 0}
	node := testPayeeScript(t)
	cases := []struct {
		name string
		req  *http.Request
		want bool
	}{
		{"no payment", nodePriceRequest(t, pg, "/data?topic=a"), false},
		{"the node's price to the node's script", nodePriceRequest(t, pg, "/data?topic=a", paidOut{node, 100}), true},
		{"less than the node's price", nodePriceRequest(t, pg, "/data?topic=a", paidOut{node, 99}), false},
		{"the node's price to another script", nodePriceRequest(t, pg, "/data?topic=a", paidOut{otherAppScript(), 100}), false},
		{"a route the node does not price", nodePriceRequest(t, pg, "/data/subscribe?topic=a"), true},
		{"no gate ran", httptest.NewRequest(http.MethodGet, "/data?topic=a", nil), true},
	}
	for _, tc := range cases {
		if got := nodePriceCovered(tc.req); got != tc.want {
			t.Errorf("%s: nodePriceCovered = %v, want %v", tc.name, got, tc.want)
		}
	}
	pg.payeeScriptHex = "76a9zz"
	if nodePriceCovered(nodePriceRequest(t, pg, "/data?topic=a", paidOut{"76a9", 100})) {
		t.Error("a node payee script that is not hex must not be covered by a payment to its decodable prefix")
	}
}

// TestNodePricedModels: unmonetized, free-model and split envelopes pay the
// node's price; passthrough and token-model ones do not.
func TestNodePricedModels(t *testing.T) {
	cases := []struct {
		mon  *envelope.Monetization
		want bool
	}{
		{nil, true},
		{&envelope.Monetization{Model: envelope.MonetizationFree}, true},
		{&envelope.Monetization{Model: envelope.MonetizationSplit, PriceSats: 50}, true},
		{&envelope.Monetization{Model: envelope.MonetizationPassthrough, PriceSats: 50}, false},
		{&envelope.Monetization{Model: envelope.MonetizationToken}, false},
		{&envelope.Monetization{Model: "not-a-model"}, true},
	}
	for _, tc := range cases {
		if got := nodePriced(&envelope.Envelope{Monetization: tc.mon}); got != tc.want {
			t.Errorf("%+v: nodePriced = %v, want %v", tc.mon, got, tc.want)
		}
	}
}

// TestUnmonetizedTopicServedForTheNodePriceOnEitherPath: on a charging node,
// an unmonetized topic answers 402 unpaid, and paying the node's price serves
// it, through X402-Proof and through X-Bsv-Payment alike.
func TestUnmonetizedTopicServedForTheNodePriceOnEitherPath(t *testing.T) {
	srv := nodePriceServer(t)
	seedEnvelopeAt(t, srv.envelopeStore, "plain", `{"m":"plain-content"}`, time.Now().Unix(), nil)
	rebuildRoutes(srv)
	path := "/data?topic=plain"

	ch := getChallenge(t, srv, http.MethodGet, path)
	if ch.AmountSats != 100 || ch.PayeeLockingScriptHex != testPayeeScript(t) {
		t.Fatalf("want the node's 100-sat challenge, got %d to %s", ch.AmountSats, ch.PayeeLockingScriptHex)
	}
	_, envs := queryWithProof(t, srv, path, ch, buildProof(t, ch, 100, testPayeeScript(t)))
	if !payloadsByMarker(envs, "plain-content")["plain-content"] {
		t.Fatal("X402-Proof paying the node's price must serve the unmonetized topic")
	}
	w := getWithHeaders(srv, path, map[string]string{HeaderBSVPayment: signedEFPaying(t, paidOut{testPayeeScript(t), 100})})
	if w.Code != http.StatusOK || !payloadsByMarker(envelopesIn(t, w), "plain-content")["plain-content"] {
		t.Fatalf("X-Bsv-Payment paying the node's price must serve the unmonetized topic: %d %s", w.Code, w.Body.String())
	}
}

// TestFreeNodeServesUnmonetizedWithoutPayment: a node that charges nothing,
// with or without a payment gate for app payments, serves unmonetized content
// to a caller who pays nothing.
func TestFreeNodeServesUnmonetizedWithoutPayment(t *testing.T) {
	for _, withGate := range []bool{true, false} {
		srv := testServer(t)
		seedEnvelopeAt(t, srv.envelopeStore, "free", `{"m":"free-content"}`, time.Now().Unix(), nil)
		seedEnvelopeAt(t, srv.envelopeStore, "free", `{"m":"free-model"}`, time.Now().Unix()+1, &envelope.Monetization{Model: envelope.MonetizationFree})
		if withGate {
			srv.paymentGate = testGateWithAppPayments(t, 0, srv.envelopeStore)
		}
		rebuildRoutes(srv)
		w := getWithHeaders(srv, "/data?topic=free", nil)
		seen := payloadsByMarker(envelopesIn(t, w), "free-content", "free-model")
		if w.Code != http.StatusOK || !seen["free-content"] || !seen["free-model"] {
			t.Fatalf("gate %v: a free node must serve unmonetized content unpaid, got %d %s", withGate, w.Code, w.Body.String())
		}
	}
}

// TestSplitTopicPaidInFullIsServed: a split topic's challenge names the node
// and the app, and a proof that pays both serves the split envelope.
func TestSplitTopicPaidInFullIsServed(t *testing.T) {
	srv := nodePriceServer(t)
	seedEnvelopeAt(t, srv.envelopeStore, "sp", `{"m":"split-content"}`, time.Now().Unix(), &envelope.Monetization{
		Model: envelope.MonetizationSplit, PayeeLockingScriptHex: appPayeeScript(), PriceSats: 50})
	rebuildRoutes(srv)
	ch := getChallenge(t, srv, http.MethodGet, "/data?topic=sp")
	if ch.AmountSats != 150 || len(ch.Payees) != 2 {
		t.Fatalf("want a 150-sat challenge naming the node and the app, got %d, %+v", ch.AmountSats, ch.Payees)
	}
	_, envs := queryWithProof(t, srv, "/data?topic=sp", ch, buildMultiPayeeProof(t, ch, ch.Payees))
	if !payloadsByMarker(envs, "split-content")["split-content"] {
		t.Fatal("a split envelope paid in full must be served")
	}
}

// TestPassthroughTopicPaidToItsAppIsServed: a passthrough topic's challenge
// names its app alone, and paying the app serves it on a charging node.
func TestPassthroughTopicPaidToItsAppIsServed(t *testing.T) {
	srv := nodePriceServer(t)
	seedEnvelopeAt(t, srv.envelopeStore, "pt", `{"m":"passthrough-content"}`, time.Now().Unix(), passthrough(appPayeeScript(), 70))
	rebuildRoutes(srv)
	ch, envs := payAndQuery(t, srv, "/data?topic=pt", 70)
	if ch.AmountSats != 70 || ch.PayeeLockingScriptHex != appPayeeScript() {
		t.Fatalf("want the app's 70-sat challenge, got %d to %s", ch.AmountSats, ch.PayeeLockingScriptHex)
	}
	if !payloadsByMarker(envs, "passthrough-content")["passthrough-content"] {
		t.Fatal("a passthrough envelope paid to its app must be served")
	}
}

// TestTokenModelTopicWithItsTokenIsServed: on a charging node, a token-model
// topic is served to a caller with a token its rule's key issued.
func TestTokenModelTopicWithItsTokenIsServed(t *testing.T) {
	srv := nodePriceServer(t)
	key, _ := ec.NewPrivateKey()
	seedEnvelopeAt(t, srv.envelopeStore, "lic", `{"m":"licensed-content"}`, time.Now().Unix(), tokenModel(key))
	srv.tokenGate = NewTokenGate(NewTopicMonetizationResolver(srv.envelopeStore), true)
	rebuildRoutes(srv)
	code, envs := queryWithAppToken(t, srv, "/data?topic=lic", mintAppToken(key, "lic"))
	if code != http.StatusOK || !payloadsByMarker(envs, "licensed-content")["licensed-content"] {
		t.Fatalf("a token-model envelope must be served to its token: got %d", code)
	}
}
