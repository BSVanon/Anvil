package api

import (
	"net/http"

	"github.com/BSVanon/Anvil/internal/envelope"
)

// TopicMonetizationResolver looks up the monetization metadata for a topic
// by examining the latest envelope. This is how the payment gate becomes
// topic-aware without coupling to the full envelope store.
type TopicMonetizationResolver struct {
	store *envelope.Store
}

// NewTopicMonetizationResolver creates a resolver backed by the envelope store.
func NewTopicMonetizationResolver(store *envelope.Store) *TopicMonetizationResolver {
	if store == nil {
		return nil
	}
	return &TopicMonetizationResolver{store: store}
}

// Resolve returns the monetization metadata for a topic, or nil if none.
// Looks at the latest PUBLIC envelope for the topic — a private envelope's
// monetization (payee script, price, auth pubkey) must never surface via a
// 402 challenge or the token gate's 401/403, or either becomes an existence
// oracle for a private-only topic: a private-only monetized topic must
// answer exactly like a topic that doesn't exist at all (no payee, no
// price, no token requirement to probe for).
//
// It reads topic's own envelopes only (QueryExactTopic), never a sub-topic's
// such as "topic:x", so a newer envelope on a sub-topic cannot replace the
// topic's own pricing or token rule.
func (r *TopicMonetizationResolver) Resolve(topic string) *envelope.Monetization {
	if r == nil || topic == "" {
		return nil
	}
	envs, err := r.store.QueryExactTopic(topic, 0)
	if err != nil {
		return nil
	}
	for _, env := range envs {
		if env.Private {
			continue
		}
		return env.Monetization
	}
	return nil
}

// resolvePayees determines the payee list for a request based on the
// topic's monetization metadata and the node's config.
//
// Returns the payee list, whether this is a token-gated topic (skip x402),
// and whether the node payee is a fallback for a disabled app model.
// An empty payee list with tokenGated=false means the request is free (pass through).
func (pg *PaymentGate) resolvePayees(r *http.Request) (payees []Payee, tokenGated, disabledFallback bool) {
	// The node's payee, only when the node charges on this path; the same
	// price and script the gate records for the per-envelope decision
	// (nodePayee, node_price_context.go).
	nodePayee := pg.nodePayee(r.URL.Path)

	// Check if this request targets a topic with monetization metadata.
	// Topic-level monetization (passthrough/split pricing, token gating)
	// only ever applies on a content route (isAppContentRoute,
	// content_route.go), the routes that actually serve that topic's
	// content. On every other route, and on every write, only the node's
	// own per-path price (nodePayee) ever applies, and tokenGated is always
	// false, so no topic's declared pricing or token model can replace or
	// waive the node's toll there. Resolve reads the topic's own envelopes
	// only, so a sub-topic's monetization never applies either.
	topic := r.URL.Query().Get("topic")
	if pg.resolver == nil || topic == "" || !isAppContentRoute(r) {
		if nodePayee != nil {
			return []Payee{*nodePayee}, false, false
		}
		return nil, false, false // node is free, no app monetization to check
	}

	mon := pg.resolver.Resolve(topic)
	if mon == nil {
		if nodePayee != nil {
			return []Payee{*nodePayee}, false, false
		}
		return nil, false, false
	}

	switch mon.Model {
	case envelope.MonetizationPassthrough:
		if !pg.allowPassthrough {
			if nodePayee != nil {
				return []Payee{*nodePayee}, false, true
			}
			return nil, false, true
		}
		return []Payee{{
			Role:             "content",
			LockingScriptHex: mon.PayeeLockingScriptHex,
			AmountSats:       capAppPrice(mon.PriceSats, pg.maxAppPriceSats),
		}}, false, false

	case envelope.MonetizationSplit:
		if !pg.allowSplit {
			if nodePayee != nil {
				return []Payee{*nodePayee}, false, true
			}
			return nil, false, true
		}
		appPayee := Payee{
			Role:             "content",
			LockingScriptHex: mon.PayeeLockingScriptHex,
			AmountSats:       capAppPrice(mon.PriceSats, pg.maxAppPriceSats),
		}
		if nodePayee != nil {
			return []Payee{*nodePayee, appPayee}, false, false
		}
		return []Payee{appPayee}, false, false

	case envelope.MonetizationToken:
		// tokenGated=true tells the caller (payment.go's Middleware) to
		// check the request's appTokenTopic context value before admitting
		// for free — this function has no access to that per-request
		// state, and never grants the free pass itself. Without a
		// validated token, a token-model topic owes the node's own price
		// like any other topic.
		if nodePayee != nil {
			return []Payee{*nodePayee}, true, false
		}
		return nil, true, false

	case envelope.MonetizationFree:
		if nodePayee != nil {
			return []Payee{*nodePayee}, false, false
		}
		return nil, false, false

	default:
		if nodePayee != nil {
			return []Payee{*nodePayee}, false, false
		}
		return nil, false, false
	}
}

// capAppPrice is what this node charges for an app's declared price: at most
// maxAppPriceSats (max_app_price_sats) when that is above 0. The 402
// challenge asks for this price, and a payment unredacts an envelope only
// when it pays at least this price (paymentCovers, paid_outputs_context.go).
func capAppPrice(price, maxAppPriceSats int) int {
	if maxAppPriceSats > 0 && price > maxAppPriceSats {
		return maxAppPriceSats
	}
	return price
}
