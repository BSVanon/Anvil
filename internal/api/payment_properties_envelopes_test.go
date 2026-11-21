package api

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

func propertyPaidRequest(t *testing.T, pg *PaymentGate, path, kind string, outs ...paidOut) *http.Request {
	t.Helper()
	r := pg.withNodePrice(httptest.NewRequest(http.MethodGet, path, nil))
	receipt := &X402Receipt{outputs: make(map[string]uint64)}
	if kind == "brc121" {
		receipt.nodeCoverage = 100
		if len(outs) > 0 {
			receipt.nodeCoverage = outs[0].sats
		}
	} else {
		for _, out := range outs {
			b, err := hex.DecodeString(out.script)
			if err != nil {
				t.Fatal(err)
			}
			receipt.outputs[string(b)] = out.sats
		}
	}
	return r.WithContext(pg.withPayment(r.Context(), receipt))
}

// Coverage is evaluated per envelope. Proof and direct receipts carry their
// verified outputs; BRC-121 carries only the node share. No newer rule can
// transfer either form of coverage to an older envelope.
func TestPaymentPropertyPerEnvelopeNodePriceOnEveryPath(t *testing.T) {
	node, app := testPayeeScript(t), appPayeeScript()
	pg := NewPaymentGate(PaymentGateConfig{PriceSats: 100, PayeeScriptHex: node, NonceProvider: &DevNonceProvider{}, AllowPassthrough: true, AllowSplit: true})
	plain := &envelope.Envelope{Topic: "priced"}
	free := &envelope.Envelope{Topic: "priced", Monetization: &envelope.Monetization{Model: envelope.MonetizationFree}}
	split := &envelope.Envelope{Topic: "priced", Monetization: &envelope.Monetization{Model: envelope.MonetizationSplit, PayeeLockingScriptHex: app, PriceSats: 50}}
	pass := &envelope.Envelope{Topic: "priced", Monetization: passthrough(app, 50)}
	key, _ := ec.NewPrivateKey()
	token := &envelope.Envelope{Topic: "priced", Monetization: tokenModel(key)}

	for _, kind := range []string{"proof", "direct"} {
		t.Run(kind, func(t *testing.T) {
			nodeOnly := propertyPaidRequest(t, pg, "/data?topic=priced", kind, paidOut{node, 100})
			underpaid := propertyPaidRequest(t, pg, "/data?topic=priced", kind, paidOut{node, 99})
			wrongPayee := propertyPaidRequest(t, pg, "/data?topic=priced", kind, paidOut{app, 100})
			both := propertyPaidRequest(t, pg, "/data?topic=priced", kind, paidOut{node, 100}, paidOut{app, 50})
			appOnly := propertyPaidRequest(t, pg, "/data?topic=priced", kind, paidOut{app, 50})
			if !envelopeCovered(nodeOnly, plain) || !envelopeCovered(nodeOnly, free) {
				t.Fatal("node price did not cover an unmonetized or free-model envelope")
			}
			if envelopeCovered(underpaid, plain) || envelopeCovered(wrongPayee, free) {
				t.Fatal("node-priced envelope accepted too few sats or another script")
			}
			if envelopeCovered(nodeOnly, split) || !envelopeCovered(both, split) {
				t.Fatal("split envelope did not require both distinct shares")
			}
			if envelopeCovered(nodeOnly, pass) || !envelopeCovered(appOnly, pass) {
				t.Fatal("passthrough envelope did not keep its app-payee rule")
			}
			if envelopeCovered(both, token) {
				t.Fatal("payment unlocked a token envelope")
			}
		})
	}

	t.Run("brc121", func(t *testing.T) {
		r := propertyPaidRequest(t, pg, "/data?topic=priced", "brc121")
		underpaid := propertyPaidRequest(t, pg, "/data?topic=priced", "brc121", paidOut{sats: 99})
		if !envelopeCovered(r, plain) || !envelopeCovered(r, free) {
			t.Fatal("BRC-121 node coverage did not cover node-priced envelopes")
		}
		if envelopeCovered(underpaid, plain) || envelopeCovered(underpaid, free) {
			t.Fatal("BRC-121 underpayment covered the node price")
		}
		if envelopeCovered(r, split) || envelopeCovered(r, pass) || envelopeCovered(r, token) {
			t.Fatal("BRC-121 node coverage escaped into an app share or token rule")
		}
	})

	// The newer passthrough envelope determines the offer and can hide the
	// older node-priced envelope. Paying it does not redirect the app output
	// into the node's price.
	newer := &envelope.Envelope{Topic: "priced", Monetization: passthrough(app, 1)}
	appPayment := propertyPaidRequest(t, pg, "/data?topic=priced", "direct", paidOut{app, 1})
	if !envelopeCovered(appPayment, newer) || envelopeCovered(appPayment, plain) {
		t.Fatal("newer envelope redirected its payment to older node-priced content")
	}
	nodePayment := propertyPaidRequest(t, pg, "/data?topic=priced", "brc121")
	if !envelopeCovered(nodePayment, plain) || envelopeCovered(nodePayment, newer) {
		t.Fatal("newer envelope inherited a payment made for older node-priced content")
	}

	ctx := withAppTokenIssuer(withAppTokenTopic(tokenRequest(t).Context(), "priced"), token.Monetization.AuthPubkey)
	if !envelopeCovered(tokenRequest(t).WithContext(ctx), token) {
		t.Fatal("token envelope did not keep its own credential rule")
	}
}

func tokenRequest(t *testing.T) *http.Request {
	t.Helper()
	return httptest.NewRequest(http.MethodGet, "/data?topic=priced", nil)
}

// One output cannot satisfy two entries, even when both entries name the
// same script. Receipt sats are the actual distinct outputs assigned, not the
// requirements and not unrelated transaction outputs.
func TestPaymentPropertySplitUsesDistinctOutputsAndExactReceiptSum(t *testing.T) {
	payee := testPayeeScript(t)
	payees := []Payee{
		{Role: "infrastructure", LockingScriptHex: payee, AmountSats: 40},
		{Role: "content", LockingScriptHex: payee, AmountSats: 50},
	}
	one := transaction.NewTransaction()
	one.AddOutput(scriptOutput(t, payee, 100))
	if _, err := matchPayees(one, payees); err == nil {
		t.Fatal("one output satisfied two payee entries")
	}

	arc := usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
		return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
	})
	pg := NewPaymentGate(PaymentGateConfig{PriceSats: 1, PayeeScriptHex: payee, NonceProvider: &DevNonceProvider{}, ARCClient: arc})
	ef := signedEFPaying(t, paidOut{payee, 60}, paidOut{payee, 80}, paidOut{otherAppScript(), 999})
	receipt, err := pg.verifyDirectPayment(t.Context(), ef, payees)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Satoshis != 140 {
		t.Fatalf("receipt sats %d, want the two assigned outputs' 140", receipt.Satoshis)
	}

	srv := testServer(t)
	seedEnvelopeAt(t, srv.envelopeStore, "same-script", `{"split":true}`, time.Now().Unix(), &envelope.Monetization{
		Model: envelope.MonetizationSplit, PayeeLockingScriptHex: payee, PriceSats: 50,
	})
	srv.paymentGate = NewPaymentGate(PaymentGateConfig{PriceSats: 100, PayeeScriptHex: payee, NonceProvider: &DevNonceProvider{},
		Resolver: NewTopicMonetizationResolver(srv.envelopeStore), AllowSplit: true})
	rebuildRoutes(srv)
	path := "/data?topic=same-script"
	challenge := getChallenge(t, srv, http.MethodGet, path)
	w := getWithHeaders(srv, path, map[string]string{HeaderX402Proof: buildMultiPayeeProof(t, challenge, challenge.Payees)})
	raw, decodeErr := base64.RawURLEncoding.DecodeString(w.Header().Get(HeaderX402Receipt))
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	var proofReceipt X402Receipt
	if w.Code != http.StatusOK || json.Unmarshal(raw, &proofReceipt) != nil || proofReceipt.Satoshis != 150 {
		t.Fatalf("proof receipt: %d %s", w.Code, string(raw))
	}
}

// Payment is accounting state, not operator authentication. This checks the
// context shape produced by every payment path at the private-envelope read.
func TestPaymentPropertyPaidRequestNeverReceivesPrivateEnvelope(t *testing.T) {
	srv := testServer(t)
	storePrivate(t, srv, `{"secret":"private"}`)
	pg := testGate(t, 100)
	for _, kind := range []string{"proof", "direct", "brc121"} {
		t.Run(kind, func(t *testing.T) {
			r := propertyPaidRequest(t, pg, "/data?topic=app:private-x", kind, paidOut{testPayeeScript(t), 100})
			w := httptest.NewRecorder()
			srv.handleQueryData(w, r)
			var result struct {
				Count int `json:"count"`
			}
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Count != 0 {
				t.Fatalf("paid private read: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

// BRC-121 deliberately has no challenge token (0121.md:21-26). Offering it
// must therefore avoid both nonce minting and the proof-path header.
func TestPaymentPropertyBRC121OfferMintsNoNonce(t *testing.T) {
	provider := &countingProvider{}
	pg := NewPaymentGate(PaymentGateConfig{PriceSats: 100, PayeeScriptHex: testPayeeScript(t), NonceProvider: provider,
		mintBudget: newMintBudget(10, 60, time.Now)})
	pg.brc121 = &brc121Gate{server: "02" + strings.Repeat("0", 64)}
	w := serveGate(pg, http.MethodGet, "/status", "", "")
	if w.Code != http.StatusPaymentRequired || w.Header().Get(headerBRC121Sats) != "100" {
		t.Fatalf("BRC-121 offer: %d %v", w.Code, w.Header())
	}
	if provider.mints.Load() != 0 || w.Header().Get(HeaderX402Challenge) != "" {
		t.Fatalf("BRC-121 offer minted %d nonces or carried a proof challenge", provider.mints.Load())
	}
}
