package api

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestDirectPaymentRefusalsCarryStableCodes: each way a direct payment is
// refused before or at ARC is answered with its stable code, and the
// messages a payer acts on say what to do.
func TestDirectPaymentRefusalsCarryStableCodes(t *testing.T) {
	payee := testPayeeScript(t)
	withARC := testServerWithPaymentGate(t, 100)
	withARC.paymentGate.arcClient = mockARCServer(t)

	signed := buildSignedDirectPaymentTx(t, payee, 100)
	beef, err := signed.AtomicBEEF(true)
	if err != nil {
		t.Fatalf("AtomicBEEF: %v", err)
	}
	tooMany := buildSignedDirectPaymentTx(t, payee, 100)
	for i := 0; i < maxDirectPaymentInputs; i++ {
		tooMany.Inputs = append(tooMany.Inputs, tooMany.Inputs[0])
	}
	tooManyEF, err := tooMany.EFHex()
	if err != nil {
		t.Fatalf("serialize extended format: %v", err)
	}

	cases := []struct {
		name, header, code, says string
	}{
		{"only spaces", "   ", codePaymentMalformed, "empty payment header"},
		{"neither hex nor base64", "!!!", codePaymentMalformed, "not valid hex or base64"},
		{"hex that is not a transaction", "00", codePaymentMalformed, "invalid transaction in payment header"},
		{"Atomic BEEF", hex.EncodeToString(beef), codePaymentMalformed, "invalid transaction in payment header"},
		{"a raw transaction, whose inputs carry no source output", signed.Hex(), codeDirectPaymentUnverifiable, "Extended Format"},
		{"more inputs than the cap", tooManyEF, codeDirectPaymentUnverifiable, "the most a direct payment verifies is 10"},
	}
	for _, tc := range cases {
		w := serveDirectPayment(withARC, "/stats", tc.header)
		requirePaymentCode(t, w, tc.code)
		if !strings.Contains(w.Body.String(), tc.says) {
			t.Fatalf("%s: got %s, want it to say %q", tc.name, w.Body.String(), tc.says)
		}
	}

	ef, err := buildSignedDirectPaymentTx(t, payee, 100).EFHex()
	if err != nil {
		t.Fatalf("serialize extended format: %v", err)
	}
	noARC := testServerWithPaymentGate(t, 100)
	w := serveDirectPayment(noARC, "/stats", ef)
	requirePaymentCode(t, w, codeDirectPaymentUnavailable)
	var body codedError
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	const noARCWording = "this node takes no X-Bsv-Payment because it has no ARC client to confirm that a payment's inputs exist and are unspent"
	if body.Description != "direct payment rejected: "+noARCWording {
		t.Fatalf("no ARC: description %q, want exactly %q after the path prefix", body.Description, noARCWording)
	}

	notAccepted := testServerWithPaymentGate(t, 100)
	notAccepted.paymentGate.arcClient = mockARCWithStatus(t, "REJECTED", 0)
	w = serveDirectPayment(notAccepted, "/stats", ef)
	requirePaymentCode(t, w, codePaymentNotAccepted)
	if !strings.Contains(w.Body.String(), "retry the same transaction shortly") || !strings.Contains(w.Body.String(), "rather than paying with a new one") {
		t.Fatalf("not accepted: got %s, want it to ask for the same transaction again, not a new payment", w.Body.String())
	}
	if w := serveDirectPayment(withARC, "/stats", ef); w.Code != http.StatusOK {
		t.Fatalf("the same transaction, once the network accepts it: got %d %s, want 200", w.Code, w.Body.String())
	}
}
