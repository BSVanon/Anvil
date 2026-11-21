package api

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

// The newest envelope on a topic prices the request (resolvePayees), so its
// rule can still hide the topic's older envelopes, but it can no longer unlock
// them or take the node's price for them: each node-priced envelope is
// unlocked only by a payment to the node's own script (nodePriceCovered).
// Each attack below worked before that rule, over GET /data and over SSE.

// paidOut is one output of a direct payment: sats to the locking script.
type paidOut struct {
	script string
	sats   uint64
}

// signedEFPaying returns, as hex, a validly signed Extended Format
// transaction that spends a synthetic parent and pays outs.
func signedEFPaying(t *testing.T, outs ...paidOut) string {
	t.Helper()
	key, _ := ec.NewPrivateKey()
	addr, _ := bsvscript.NewAddressFromPublicKey(key.PubKey(), true)
	lock, _ := p2pkh.Lock(addr)
	src := transaction.NewTransaction()
	src.AddOutput(&transaction.TransactionOutput{Satoshis: 1_000_000, LockingScript: lock})
	tx := transaction.NewTransaction()
	tx.AddInput(&transaction.TransactionInput{SourceTXID: src.TxID(), SourceTxOutIndex: 0, SequenceNumber: 0xffffffff, SourceTransaction: src})
	for _, o := range outs {
		b, err := hex.DecodeString(o.script)
		if err != nil {
			t.Fatalf("decode script: %v", err)
		}
		ls := bsvscript.Script(b)
		tx.AddOutput(&transaction.TransactionOutput{Satoshis: o.sats, LockingScript: &ls})
	}
	unlock, _ := p2pkh.Unlock(key, nil)
	tx.Inputs[0].UnlockingScriptTemplate = unlock
	if err := tx.Sign(); err != nil {
		t.Fatalf("sign: %v", err)
	}
	ef, err := tx.EFHex()
	if err != nil {
		t.Fatalf("extended format: %v", err)
	}
	return ef
}

// getWithHeaders sends GET path through srv with headers set.
func getWithHeaders(srv *Server, path string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "localhost"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// envelopesIn decodes the envelopes of a GET /data answer.
func envelopesIn(t *testing.T, w *httptest.ResponseRecorder) []map[string]interface{} {
	t.Helper()
	var resp struct {
		Envelopes []map[string]interface{} `json:"envelopes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %d %s: %v", w.Code, w.Body.String(), err)
	}
	return resp.Envelopes
}

// readSSEUntilKeySentinel is readSSEUntilSentinel (sse_private_test.go) for a
// subscriber who may see the sentinel redacted, as one who has not paid the
// node sees every unmonetized envelope: it waits for the sentinel's signing
// key, which a redacted copy still carries, rather than for its payload.
func readSSEUntilKeySentinel(t *testing.T, srv *Server, resp *http.Response, topic string) string {
	t.Helper()
	key, _ := ec.NewPrivateKey()
	sentinel := &envelope.Envelope{Type: "data", Topic: topic, Payload: `{"sentinel":true}`, Timestamp: time.Now().Unix()}
	sentinel.Sign(key)
	srv.NotifyEnvelope(sentinel)
	body := readSSEUntilContains(resp, sentinel.Pubkey)
	if !strings.Contains(body, sentinel.Pubkey) {
		t.Fatalf("the sentinel never arrived over SSE, so nothing proves the earlier event's absence; got:\n%s", body)
	}
	return body
}

// nodePriceAttack is one attack on the node's own price of 100 sats: setup
// seeds the attacker's newer envelope on topic, and headers is what the
// attacker sends. honest is the honest envelope the attack is after.
type nodePriceAttack struct {
	name    string
	honest  *envelope.Monetization
	setup   func(t *testing.T, srv *Server, topic string)
	headers func(t *testing.T, topic string) map[string]string
}

func nodePriceAttacks() []nodePriceAttack {
	attackerKey, _ := ec.NewPrivateKey()
	split := &envelope.Monetization{Model: envelope.MonetizationSplit, PayeeLockingScriptHex: appPayeeScript(), PriceSats: 50}
	return []nodePriceAttack{{
		name: "a newer token rule and the attacker's own token",
		setup: func(t *testing.T, srv *Server, topic string) {
			seedEnvelopeAt(t, srv.envelopeStore, topic, `{"m":"attacker-decl"}`, time.Now().Unix()+100, tokenModel(attackerKey))
			srv.tokenGate = NewTokenGate(NewTopicMonetizationResolver(srv.envelopeStore), true)
		},
		headers: func(t *testing.T, topic string) map[string]string {
			return map[string]string{"X-App-Token": mintAppToken(attackerKey, topic)}
		},
	}, {
		name: "a newer passthrough asking 1 sat to the attacker's own script",
		setup: func(t *testing.T, srv *Server, topic string) {
			seedEnvelopeAt(t, srv.envelopeStore, topic, `{"m":"attacker-decl"}`, time.Now().Unix()+100, passthrough(otherAppScript(), 1))
		},
		headers: func(t *testing.T, topic string) map[string]string {
			return map[string]string{HeaderBSVPayment: signedEFPaying(t, paidOut{otherAppScript(), 1})}
		},
	}, {
		name:   "a newer passthrough naming the split's own app payee, paid the app's share only",
		honest: split,
		setup: func(t *testing.T, srv *Server, topic string) {
			seedEnvelopeAt(t, srv.envelopeStore, topic, `{"m":"attacker-decl"}`, time.Now().Unix()+100, passthrough(appPayeeScript(), 50))
		},
		headers: func(t *testing.T, topic string) map[string]string {
			return map[string]string{HeaderBSVPayment: signedEFPaying(t, paidOut{appPayeeScript(), 50})}
		},
	}}
}

// nodePriceServer is a server whose node charges 100 sats, with app payments
// on and a mock ARC that accepts every payment.
func nodePriceServer(t *testing.T) *Server {
	t.Helper()
	srv := testServer(t)
	srv.paymentGate = testGateWithAppPayments(t, 100, srv.envelopeStore)
	srv.paymentGate.arcClient = mockARCServer(t)
	return srv
}

func rebuildRoutes(srv *Server) {
	srv.mux = http.NewServeMux()
	srv.routes()
}

// TestNewerEnvelopeDoesNotUnlockOlderNodePricedEnvelopes: none of the attacks
// unlocks the honest envelope on GET /data. The request itself is admitted,
// since the newest rule prices it, and the honest payload stays redacted.
func TestNewerEnvelopeDoesNotUnlockOlderNodePricedEnvelopes(t *testing.T) {
	for _, a := range nodePriceAttacks() {
		srv := nodePriceServer(t)
		const topic = "oracle:rates:bsv"
		seedEnvelopeAt(t, srv.envelopeStore, topic, `{"m":"honest-payload"}`, time.Now().Unix(), a.honest)
		a.setup(t, srv, topic)
		rebuildRoutes(srv)

		w := getWithHeaders(srv, "/data?topic="+topic, a.headers(t, topic))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: the newest rule admits the request, got %d %s", a.name, w.Code, w.Body.String())
		}
		if payloadsByMarker(envelopesIn(t, w), "honest-payload")["honest-payload"] {
			t.Fatalf("%s: the honest payload was served without the node's 100-sat price", a.name)
		}
	}
}

// TestNewerEnvelopeDoesNotUnlockLiveNodePricedEnvelopesOverSSE: the same
// attacks on a subscription. The subscribe request's node price holds for the
// stream, so the honest envelope arrives redacted.
func TestNewerEnvelopeDoesNotUnlockLiveNodePricedEnvelopesOverSSE(t *testing.T) {
	for _, a := range nodePriceAttacks() {
		srv := nodePriceServer(t)
		const topic = "oracle:rates:live"
		a.setup(t, srv, topic)
		rebuildRoutes(srv)
		ts := httptest.NewServer(srv.Handler())

		headers := a.headers(t, topic)
		resp, cancel := subscribeSSE(t, ts, "/data/subscribe?topic="+topic, "", func(r *http.Request) {
			for k, v := range headers {
				r.Header.Set(k, v)
			}
		})
		waitForSSESubscription(t, srv, topic)
		key, _ := ec.NewPrivateKey()
		honest := &envelope.Envelope{Type: "data", Topic: topic, Payload: `{"m":"honest-live"}`, Timestamp: time.Now().Unix(), Monetization: a.honest}
		honest.Sign(key)
		srv.NotifyEnvelope(honest)
		body := readSSEUntilKeySentinel(t, srv, resp, topic)
		resp.Body.Close()
		cancel()
		ts.Close()
		if strings.Contains(body, "honest-live") {
			t.Fatalf("%s: the honest envelope streamed without the node's 100-sat price", a.name)
		}
		if !strings.Contains(body, honest.Pubkey) || !strings.Contains(body, "paid content") {
			t.Fatalf("%s: the honest envelope should arrive redacted; got:\n%s", a.name, body)
		}
	}
}

// TestOnlyAPaymentToTheNodesScriptCoversTheNodePrice: a newer passthrough asks
// 100 to the attacker's own script, the node's own price. Paying that script
// 100 is not paying the node, so the honest unmonetized envelope stays
// redacted; adding an output of 100 to the node's script unlocks it.
func TestOnlyAPaymentToTheNodesScriptCoversTheNodePrice(t *testing.T) {
	srv := nodePriceServer(t)
	base := time.Now().Unix()
	seedEnvelopeAt(t, srv.envelopeStore, "np", `{"m":"honest-unmonetized"}`, base, nil)
	seedEnvelopeAt(t, srv.envelopeStore, "np", `{"m":"attacker-decl"}`, base+100, passthrough(otherAppScript(), 100))
	rebuildRoutes(srv)

	if ch := getChallenge(t, srv, http.MethodGet, "/data?topic=np"); ch.AmountSats != 100 || ch.PayeeLockingScriptHex != otherAppScript() {
		t.Fatalf("the newest rule prices the request: want 100 to the attacker's script, got %d to %s", ch.AmountSats, ch.PayeeLockingScriptHex)
	}
	w := getWithHeaders(srv, "/data?topic=np", map[string]string{HeaderBSVPayment: signedEFPaying(t, paidOut{otherAppScript(), 100})})
	seen := payloadsByMarker(envelopesIn(t, w), "honest-unmonetized", "attacker-decl")
	if seen["honest-unmonetized"] {
		t.Fatal("100 sats to a script other than the node's covered the node's 100-sat price")
	}
	if !seen["attacker-decl"] {
		t.Fatal("the passthrough envelope the payment did pay must be unlocked")
	}
	w = getWithHeaders(srv, "/data?topic=np", map[string]string{HeaderBSVPayment: signedEFPaying(t,
		paidOut{otherAppScript(), 100}, paidOut{testPayeeScript(t), 100})})
	if !payloadsByMarker(envelopesIn(t, w), "honest-unmonetized")["honest-unmonetized"] {
		t.Fatalf("an output of 100 to the node's own script must cover the node's price: %d %s", w.Code, w.Body.String())
	}
}
