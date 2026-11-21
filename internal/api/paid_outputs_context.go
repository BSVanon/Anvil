package api

import (
	"context"
	"encoding/hex"
	"net/http"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// verifiedPayment is what a verified x402 payment paid: for each locking
// script, the largest single output paying it, and the app-price cap of the
// gate that verified it. The payment gate's Middleware (payment.go) sets it as
// a request-context value, through withPayment, once a proof or direct payment
// has verified; a client can neither set nor read it.
//
// It carries the payment's outputs and never a topic, so each envelope's
// redaction (envelopeForRequest, envelope_redaction.go) asks whether this
// payment paid that envelope's own payee its own price. Like withPaid's
// marker (paid_context.go), it marks a request paid, never authenticated: it
// never unlocks a `private` envelope.
type verifiedPayment struct {
	outputs         map[string]uint64 // locking script bytes -> the largest single output paying it
	maxAppPriceSats int               // the gate's max_app_price_sats, 0 when none
	nodeCoverage    uint64            // what a BRC-121 payment paid the node: node coverage only (brc121.go)
}

type verifiedPaymentKey struct{}

// paidOutputs maps each locking script tx's outputs pay to the largest single
// output paying it.
func paidOutputs(tx *transaction.Transaction) map[string]uint64 {
	outs := make(map[string]uint64, len(tx.Outputs))
	for _, out := range tx.Outputs {
		if out.LockingScript == nil {
			continue
		}
		key := string(*out.LockingScript)
		if out.Satoshis > outs[key] {
			outs[key] = out.Satoshis
		}
	}
	return outs
}

// withPayment returns ctx marked paid (withPaid) and carrying what receipt's
// verified payment paid, with this gate's app-price cap.
func (pg *PaymentGate) withPayment(ctx context.Context, receipt *X402Receipt) context.Context {
	return context.WithValue(withPaid(ctx), verifiedPaymentKey{}, &verifiedPayment{
		outputs:         receipt.outputs,
		maxAppPriceSats: pg.maxAppPriceSats,
		nodeCoverage:    receipt.nodeCoverage,
	})
}

// paymentCovers reports whether r carries a verified payment with one output
// that pays payeeScriptHex at least priceSats, capped as the verifying gate
// caps app prices (capAppPrice, payment_resolve.go): the price its 402
// challenge asks for that payee.
func paymentCovers(r *http.Request, payeeScriptHex string, priceSats int) bool {
	p, ok := r.Context().Value(verifiedPaymentKey{}).(*verifiedPayment)
	if !ok || payeeScriptHex == "" {
		return false
	}
	script, err := hex.DecodeString(payeeScriptHex)
	if err != nil {
		return false
	}
	paid, ok := p.outputs[string(script)]
	price := capAppPrice(priceSats, p.maxAppPriceSats)
	return ok && price > 0 && paid >= uint64(price)
}
