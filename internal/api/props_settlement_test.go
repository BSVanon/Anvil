package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func TestSettlementPropertyUnderpaymentIsRejected(t *testing.T) {
	usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
		return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
	})
	for _, kind := range []string{"proof", "direct", "brc121"} {
		t.Run(kind, func(t *testing.T) {
			if kind == "brc121" {
				f := newBRC121Fix(t, 100)
				srv := testServer(t)
				srv.paymentGate = f.pg
				rebuildRoutes(srv)
				w := getWithHeaders(srv, "/stats", f.payment(t, 99, brc121Pay{}))
				if w.Code != http.StatusPaymentRequired || codeOf(t, w) != codeBRC121Underpaid {
					t.Fatalf("underpayment = %d %s", w.Code, w.Body.String())
				}
				return
			}
			srv := testServerWithPaymentGate(t, 100)
			srv.paymentGate.arcClient = usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
				return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
			})
			headers := map[string]string{}
			if kind == "proof" {
				challenge := getChallenge(t, srv, http.MethodGet, "/stats")
				headers[HeaderX402Proof] = buildProof(t, challenge, 99, testPayeeScript(t))
			} else {
				headers[HeaderBSVPayment] = signedEFPaying(t, paidOut{testPayeeScript(t), 99})
			}
			w := getWithHeaders(srv, "/stats", headers)
			if w.Code != http.StatusPaymentRequired {
				t.Fatalf("underpayment = %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestSettlementPropertyEnvelopeRules(t *testing.T) {
	usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
		return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
	})
	node, app := testPayeeScript(t), appPayeeScript()
	rows := []struct {
		name  string
		topic string
		mon   *envelope.Monetization
		bad   []paidOut
		good  []paidOut
	}{
		{"unmonetized", "plain", nil, []paidOut{{app, 100}}, []paidOut{{node, 100}}},
		{"free model", "free", &envelope.Monetization{Model: envelope.MonetizationFree}, []paidOut{{app, 100}}, []paidOut{{node, 100}}},
		{"split", "split", &envelope.Monetization{Model: envelope.MonetizationSplit, PayeeLockingScriptHex: app, PriceSats: 50}, []paidOut{{node, 100}}, []paidOut{{node, 100}, {app, 50}}},
		{"passthrough", "pass", passthrough(app, 50), []paidOut{{node, 100}}, []paidOut{{app, 50}}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			srv := testServer(t)
			topic := "example:settlement-" + row.topic
			seedEnvelopeAt(t, srv.envelopeStore, topic, `{"value":"clear"}`, time.Now().Unix(), row.mon)
			srv.paymentGate = testGateWithAppPayments(t, 100, srv.envelopeStore)
			srv.paymentGate.arcClient = usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
				return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
			})
			rebuildRoutes(srv)
			path := "/data?topic=" + topic
			bad := getWithHeaders(srv, path, map[string]string{HeaderBSVPayment: signedEFPaying(t, row.bad...)})
			if bad.Code != http.StatusPaymentRequired {
				t.Fatalf("incomplete settlement = %d %s", bad.Code, bad.Body.String())
			}
			good := getWithHeaders(srv, path, map[string]string{HeaderBSVPayment: signedEFPaying(t, row.good...)})
			if good.Code != http.StatusOK || !containsUnredactedPayload(good.Body.String()) {
				t.Fatalf("complete settlement = %d %s", good.Code, good.Body.String())
			}
		})
	}

	t.Run("token", func(t *testing.T) {
		srv := testServer(t)
		key, _ := ec.NewPrivateKey()
		topic := "example:settlement-token"
		seedEnvelopeAt(t, srv.envelopeStore, topic, `{"value":"clear"}`, time.Now().Unix(), tokenModel(key))
		resolver := NewTopicMonetizationResolver(srv.envelopeStore)
		srv.paymentGate = testGateWithAppPayments(t, 100, srv.envelopeStore)
		srv.tokenGate = NewTokenGate(resolver, true)
		rebuildRoutes(srv)
		path := "/data?topic=" + topic
		paid := getWithHeaders(srv, path, map[string]string{HeaderBSVPayment: signedEFPaying(t, paidOut{node, 100})})
		if paid.Code != http.StatusUnauthorized {
			t.Fatalf("payment on token model = %d %s", paid.Code, paid.Body.String())
		}
		admitted := getWithHeaders(srv, path, map[string]string{"X-App-Token": mintAppToken(key, topic)})
		if admitted.Code != http.StatusOK || !containsUnredactedPayload(admitted.Body.String()) {
			t.Fatalf("valid token = %d %s", admitted.Code, admitted.Body.String())
		}
	})
}

func containsUnredactedPayload(body string) bool {
	return strings.Contains(body, `\"clear\"`) && !strings.Contains(body, "[paid content") && !strings.Contains(body, "[token-gated content")
}
