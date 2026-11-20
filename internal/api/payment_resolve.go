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
// QueryByTopic's durable path is a prefix scan (envelope/store.go:218),
// documented for LISTING (docs/ANVIL_CAPABILITIES.md: "Prefix matching for
// subscriptions") — so envs can hold sub-topic envelopes like "topic:x"
// alongside topic's own. A money or access decision must never pick up a
// different topic's monetization this way: cold review's BL2(b) found a
// newer sub-topic envelope (e.g. "prem:x", token-gated) hijacking the
// parent's own pricing/token-gating ("prem") for both the 402 toll and the
// token requirement, since the old code returned the first non-private
// envelope QueryByTopic's prefix scan happened to surface, regardless of
// its own Topic. Skipping anything whose own Topic isn't an exact match
// confines this resolution to topic's own declared monetization, same as
// the ephemeral store's exact-match query path (envelope/store.go:236).
func (r *TopicMonetizationResolver) Resolve(topic string) *envelope.Monetization {
	if r == nil || topic == "" {
		return nil
	}
	envs, err := r.store.QueryByTopic(topic, 0)
	if err != nil {
		return nil
	}
	for _, env := range envs {
		if env.Topic != topic {
			continue
		}
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
// Returns the payee list and whether this is a token-gated topic (skip x402).
// An empty payee list with tokenGated=false means the request is free (pass through).
func (pg *PaymentGate) resolvePayees(r *http.Request) (payees []Payee, tokenGated bool) {
	// Build node payee only if node actually charges.
	// Per-endpoint pricing overrides the default if configured.
	nodePrice := pg.priceForPath(r.URL.Path)
	var nodePayee *Payee
	if nodePrice > 0 && pg.payeeScriptHex != "" {
		nodePayee = &Payee{
			Role:             "infrastructure",
			LockingScriptHex: pg.payeeScriptHex,
			AmountSats:       nodePrice,
		}
	}

	// Check if this request targets a topic with monetization metadata.
	// Topic-level monetization (passthrough/split pricing, token gating)
	// only ever applies on a content route (isAppContentRoute,
	// content_route.go) — GET /data or GET /data/subscribe, the routes that
	// actually serve that topic's content. On every other route, and on
	// every write, ?topic= is passed straight through to this fall-through:
	// only the node's own per-path price (nodePayee) ever applies, and
	// tokenGated is always false, so no topic's declared pricing or token
	// model can replace or waive the node's toll (cold review BL2(a), RISK
	// 3) or, via Resolve's prefix-scanned result, waive it based on a
	// different (sub-)topic's monetization (BL2(b)).
	topic := r.URL.Query().Get("topic")
	if pg.resolver == nil || topic == "" || !isAppContentRoute(r) {
		if nodePayee != nil {
			return []Payee{*nodePayee}, false
		}
		return nil, false // node is free, no app monetization to check
	}

	mon := pg.resolver.Resolve(topic)
	if mon == nil {
		if nodePayee != nil {
			return []Payee{*nodePayee}, false
		}
		return nil, false
	}

	switch mon.Model {
	case envelope.MonetizationPassthrough:
		if !pg.allowPassthrough {
			if nodePayee != nil {
				return []Payee{*nodePayee}, false
			}
			return nil, false
		}
		return []Payee{{
			Role:             "content",
			LockingScriptHex: mon.PayeeLockingScriptHex,
			AmountSats:       capAppPrice(mon.PriceSats, pg.maxAppPriceSats),
		}}, false

	case envelope.MonetizationSplit:
		if !pg.allowSplit {
			if nodePayee != nil {
				return []Payee{*nodePayee}, false
			}
			return nil, false
		}
		appPayee := Payee{
			Role:             "content",
			LockingScriptHex: mon.PayeeLockingScriptHex,
			AmountSats:       capAppPrice(mon.PriceSats, pg.maxAppPriceSats),
		}
		if nodePayee != nil {
			return []Payee{*nodePayee, appPayee}, false
		}
		return []Payee{appPayee}, false

	case envelope.MonetizationToken:
		// tokenGated=true tells the caller (payment.go's Middleware) to
		// check the request's appTokenTopic context value before admitting
		// for free — this function has no access to that per-request
		// state, and never grants the free pass itself. Without a
		// validated token, a token-model topic owes the node's own price
		// like any other topic.
		if nodePayee != nil {
			return []Payee{*nodePayee}, true
		}
		return nil, true

	case envelope.MonetizationFree:
		if nodePayee != nil {
			return []Payee{*nodePayee}, false
		}
		return nil, false

	default:
		if nodePayee != nil {
			return []Payee{*nodePayee}, false
		}
		return nil, false
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
