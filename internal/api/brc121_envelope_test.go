package api

import (
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/spv"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// brc121Server is nodePriceServer (a node charging 100, app payments on, a
// mock ARC accepting every payment) taking BRC-121 into a fake node wallet.
func brc121Server(t *testing.T) (*Server, *fakeBRC121Wallet, *brc121Payer) {
	t.Helper()
	srv := nodePriceServer(t)
	payer := newBRC121Payer()
	wallet := newFakeBRC121Wallet()
	if err := srv.paymentGate.startBRC121(wallet, spv.NewValidator(brc121HeaderStore(t, payer.source)), t.TempDir(), slog.Default()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.paymentGate.closeBRC121)
	return srv, wallet, payer
}

// TestBRC121OfferOnNodeOnlyChallengesOnly: a 402 whose payees are the node's
// own offers BRC-121 at the node's price with the node wallet's key, exposed
// to browsers; a passthrough, split or token-gated challenge offers nothing.
func TestBRC121OfferOnNodeOnlyChallengesOnly(t *testing.T) {
	srv, wallet, _ := brc121Server(t)
	now := time.Now().Unix()
	seedEnvelopeAt(t, srv.envelopeStore, "plain", `{"m":"p"}`, now, nil)
	seedEnvelopeAt(t, srv.envelopeStore, "pass", `{"m":"p"}`, now, passthrough(appPayeeScript(), 50))
	seedEnvelopeAt(t, srv.envelopeStore, "split", `{"m":"p"}`, now, &envelope.Monetization{Model: envelope.MonetizationSplit, PayeeLockingScriptHex: appPayeeScript(), PriceSats: 50})
	appKey, _ := ec.NewPrivateKey()
	seedEnvelopeAt(t, srv.envelopeStore, "tok", `{"m":"p"}`, now, tokenModel(appKey))
	srv.tokenGate = NewTokenGate(NewTopicMonetizationResolver(srv.envelopeStore), true)
	rebuildRoutes(srv)

	w := getWithHeaders(srv, "/data?topic=plain", nil)
	if w.Code != http.StatusPaymentRequired || w.Header().Get(headerBRC121Sats) != "100" || w.Header().Get(headerBRC121Server) != wallet.root.PubKey().ToDERHex() {
		t.Fatalf("a node-only challenge offers BRC-121: got %d, %q %q", w.Code, w.Header().Get(headerBRC121Sats), w.Header().Get(headerBRC121Server))
	}
	if got := w.Header().Get(HeaderX402Challenge); got != "" {
		t.Fatal("a BRC-121 offer also advertised the node-only proof path")
	}
	expose := strings.ToLower(w.Header().Get("Access-Control-Expose-Headers"))
	if !strings.Contains(expose, headerBRC121Sats) || !strings.Contains(expose, headerBRC121Server) {
		t.Fatalf("the offer headers must be exposed to browsers, got %q", expose)
	}
	for _, topic := range []string{"pass", "split", "tok"} {
		w := getWithHeaders(srv, "/data?topic="+topic, nil)
		if w.Header().Get(headerBRC121Sats) != "" || w.Header().Get(headerBRC121Server) != "" {
			t.Fatalf("%s: a challenge with an app payee or a token gate must not offer BRC-121 (%d)", topic, w.Code)
		}
	}
	srv.paymentGate.allowPassthrough, srv.paymentGate.allowSplit = false, false
	for _, topic := range []string{"pass", "split"} {
		w := getWithHeaders(srv, "/data?topic="+topic, nil)
		if w.Code != http.StatusOK || w.Header().Get(HeaderX402Challenge) != "" {
			t.Fatalf("%s: a disabled app model offered a payment that cannot unlock the content: %d", topic, w.Code)
		}
		assertNoBRC121Offer(t, w)
	}
}

// TestBRC121CORSAllowsItsHeaders: the node's CORS answer allows the five
// request headers.
func TestBRC121CORSAllowsItsHeaders(t *testing.T) {
	srv, _, _ := brc121Server(t)
	w := getWithHeaders(srv, "/data?topic=x", map[string]string{"Origin": "https://example.org"})
	allow := strings.ToLower(w.Header().Get("Access-Control-Allow-Headers"))
	for _, h := range []string{headerBRC121Beef, headerBRC121Sender, headerBRC121Nonce, headerBRC121Time, headerBRC121Vout} {
		if !strings.Contains(allow, h) {
			t.Fatalf("CORS must allow %s, got %q", h, allow)
		}
	}
}

// TestBRC121CoversNodePricedEnvelopesOnly: paying the node's price by BRC-121
// serves the topic's node-priced envelopes, and leaves a split envelope's
// app share, a passthrough envelope, a token-model envelope and a private
// envelope redacted.
func TestBRC121CoversNodePricedEnvelopesOnly(t *testing.T) {
	srv, wallet, payer := brc121Server(t)
	const topic = "mixed"
	now := time.Now().Unix()
	appKey, _ := ec.NewPrivateKey()
	seedEnvelopeAt(t, srv.envelopeStore, topic, `{"m":"split-app"}`, now, &envelope.Monetization{Model: envelope.MonetizationSplit, PayeeLockingScriptHex: appPayeeScript(), PriceSats: 50})
	seedEnvelopeAt(t, srv.envelopeStore, topic, `{"m":"pass-app"}`, now+1, passthrough(appPayeeScript(), 50))
	seedEnvelopeAt(t, srv.envelopeStore, topic, `{"m":"token-app"}`, now+2, tokenModel(appKey))
	seedEnvelopeAt(t, srv.envelopeStore, topic, `{"m":"free-model"}`, now+3, &envelope.Monetization{Model: envelope.MonetizationFree})
	srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{Type: "data", Topic: topic, Payload: `{"m":"private-env"}`,
		Pubkey: "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66", Signature: "3045022100abcd",
		TTL: 60, Timestamp: now + 4, Private: true})
	seedEnvelopeAt(t, srv.envelopeStore, topic, `{"m":"node-plain"}`, now+5, nil)
	rebuildRoutes(srv)

	w := getWithHeaders(srv, "/data?topic="+topic, payer.pay(t, wallet.root.PubKey(), 100, time.Now(), brc121Pay{}))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d %s", w.Code, w.Body.String())
	}
	seen := payloadsByMarker(envelopesIn(t, w), "node-plain", "free-model", "split-app", "pass-app", "token-app", "private-env")
	if !seen["node-plain"] || !seen["free-model"] {
		t.Fatalf("the node-priced envelopes must be served, saw %v", seen)
	}
	for _, m := range []string{"split-app", "pass-app", "token-app", "private-env"} {
		if seen[m] {
			t.Fatalf("a BRC-121 payment unlocked %s, which it never covers", m)
		}
	}
}
