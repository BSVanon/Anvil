package api

import (
	"context"
	"encoding/hex"
	"net/http"

	"github.com/BSVanon/Anvil/internal/envelope"
)

// nodePrice is the node's own price for a request's route and the script it
// is paid to, exactly as the payment gate that priced the request applied
// them (PaymentGate.nodePayee). The gate's Middleware records it in the
// request's context before anything else, so it is there however the gate
// lets the request through: paid, admitted free for a validated app token, or
// free because the price is 0. Like the other payment and token markers, it is
// a context value a client can neither set nor read.
//
// The node's price is decided for each envelope, the same as an app's
// (envelopeCovered, envelope_redaction.go). The 402 challenge prices a request
// from the newest public envelope on its topic (resolvePayees), and that
// envelope's rule can waive the node's price for the request: a token-model
// rule admits a validated token free, and a passthrough rule names only its
// app's payee. Neither waives it for the topic's other envelopes. A
// node-priced envelope (nodePriced) is unlocked only by a verified payment
// with one output that pays script at least sats, whatever rule the newest
// envelope on its topic declares. For an SSE subscription, the subscribe
// request's record holds for the life of the stream.
type nodePrice struct {
	sats   int    // 0 when the node charges nothing on the route
	script []byte // nil when the node's payee script is not valid hex, which nothing can pay
}

type nodePriceKey struct{}

// nodePayee is the node's own payee for a request to path, or nil when the
// node charges nothing there: its price for path (priceForPath), paid to its
// payee script, when the price is above 0 and the script is set.
func (pg *PaymentGate) nodePayee(path string) *Payee {
	price := pg.priceForPath(path)
	if price <= 0 || pg.payeeScriptHex == "" {
		return nil
	}
	return &Payee{Role: "infrastructure", LockingScriptHex: pg.payeeScriptHex, AmountSats: price}
}

// withNodePrice returns r carrying the node's own price for r's route
// (nodePrice). A payee script that is not valid hex is recorded as no script,
// so nothing covers the price rather than a prefix of it.
func (pg *PaymentGate) withNodePrice(r *http.Request) *http.Request {
	np := &nodePrice{}
	if p := pg.nodePayee(r.URL.Path); p != nil {
		np.sats = p.AmountSats
		if script, err := hex.DecodeString(p.LockingScriptHex); err == nil {
			np.script = script
		}
	}
	return r.WithContext(context.WithValue(r.Context(), nodePriceKey{}, np))
}

// nodePriced reports whether env's payload pays the node's own price on a
// route where the node charges: every envelope except a passthrough one,
// whose price the operator lets its app take in place of the node's
// (allow_passthrough), and a token-model one, whose app sells its own
// credentials. An unmonetized envelope, a free-model one and a split one are
// node-priced; so is any other model, which Monetization.Validate never lets
// in, rather than letting it skip the node's price.
func nodePriced(env *envelope.Envelope) bool {
	mon := env.Monetization
	return mon == nil || (mon.Model != envelope.MonetizationPassthrough && mon.Model != envelope.MonetizationToken)
}

// nodePriceCovered reports whether r has paid the node's own price recorded
// by the gate that priced it (nodePrice): true when that price is 0 or no
// gate ran, since a free node prices nothing; otherwise only when r carries a
// verified payment with one output that pays the node's own payee script at
// least that price, on the X-Bsv-Payment or X402-Proof path, or a BRC-121
// payment of at least that price to the node wallet (its nodeCoverage). An
// output paying any other script, an app's or the payer's own, never counts.
func nodePriceCovered(r *http.Request) bool {
	np, _ := r.Context().Value(nodePriceKey{}).(*nodePrice)
	if np == nil || np.sats <= 0 {
		return true
	}
	p, _ := r.Context().Value(verifiedPaymentKey{}).(*verifiedPayment)
	if p != nil && p.nodeCoverage >= uint64(np.sats) {
		return true
	}
	if p == nil || len(np.script) == 0 {
		return false
	}
	paid, ok := p.outputs[string(np.script)]
	return ok && paid >= uint64(np.sats)
}
