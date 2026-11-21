package api

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

func scriptOutput(t *testing.T, scriptHex string, sats uint64) *transaction.TransactionOutput {
	t.Helper()
	b, err := hex.DecodeString(scriptHex)
	if err != nil {
		t.Fatalf("decode script: %v", err)
	}
	s := bsvscript.Script(b)
	return &transaction.TransactionOutput{LockingScript: &s, Satoshis: sats}
}

// paymentCovers asks about one output to the payee, never a sum: two
// outputs of 60 to the same payee do not cover a price of 100.
func TestPaymentCoversOneOutputAtItsPayeeAndCappedPrice(t *testing.T) {
	tx := transaction.NewTransaction()
	tx.AddOutput(scriptOutput(t, appPayeeScript(), 60))
	tx.AddOutput(scriptOutput(t, appPayeeScript(), 60))
	tx.AddOutput(scriptOutput(t, testPayeeScript(t), 500))
	paidWithCap := func(maxAppPriceSats int) *http.Request {
		pg := &PaymentGate{maxAppPriceSats: maxAppPriceSats}
		req := httptest.NewRequest("GET", "/data?topic=a", nil)
		return req.WithContext(pg.withPayment(req.Context(), &X402Receipt{outputs: paidOutputs(tx)}))
	}
	noCap, capped := paidWithCap(0), paidWithCap(50)
	cases := []struct {
		name  string
		req   *http.Request
		payee string
		price int
		want  bool
	}{
		{"one output pays the payee the price", noCap, appPayeeScript(), 60, true},
		{"the payee's outputs are not summed", noCap, appPayeeScript(), 100, false},
		{"one output below the price", noCap, testPayeeScript(t), 501, false},
		{"another payee's output pays nothing here", noCap, otherAppScript(), 1, false},
		{"upper-case hex names the same script", noCap, strings.ToUpper(appPayeeScript()), 60, true},
		{"no payee", noCap, "", 1, false},
		{"a payee that is not hex", noCap, "zz", 1, false},
		{"a price over the cap costs the cap", capped, appPayeeScript(), 1000, true},
		{"the cap never pays another payee", capped, otherAppScript(), 1000, false},
	}
	for _, tc := range cases {
		if got := paymentCovers(tc.req, tc.payee, tc.price); got != tc.want {
			t.Errorf("%s: paymentCovers = %v, want %v", tc.name, got, tc.want)
		}
	}
	unpaid := httptest.NewRequest("GET", "/data?topic=a", nil)
	if paymentCovers(unpaid, appPayeeScript(), 1) {
		t.Fatal("a request with no verified payment covers nothing")
	}
}

func TestAppTokenIssuerMatches(t *testing.T) {
	const issuer = "02aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	req := httptest.NewRequest("GET", "/data?topic=a", nil)
	if appTokenIssuerMatches(req, issuer) {
		t.Fatal("a request with no validated token matches no issuer")
	}
	req = req.WithContext(withAppTokenIssuer(req.Context(), strings.ToUpper(issuer)))
	if !appTokenIssuerMatches(req, issuer) {
		t.Fatal("the issuing key must match, whatever its hex case")
	}
	if appTokenIssuerMatches(req, "03"+issuer[2:]) || appTokenIssuerMatches(req, "") {
		t.Fatal("only the issuing key may match")
	}
}
