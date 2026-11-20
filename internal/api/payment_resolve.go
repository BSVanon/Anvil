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
func (r *TopicMonetizationResolver) Resolve(topic string) *envelope.Monetization {
	if r == nil || topic == "" {
		return nil
	}
	envs, err := r.store.QueryByTopic(topic, 0)
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

	// Check if this request targets a topic with monetization metadata
	topic := r.URL.Query().Get("topic")
	if pg.resolver == nil || topic == "" {
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
		appPrice := mon.PriceSats
		if pg.maxAppPriceSats > 0 && appPrice > pg.maxAppPriceSats {
			appPrice = pg.maxAppPriceSats
		}
		return []Payee{{
			Role:             "content",
			LockingScriptHex: mon.PayeeLockingScriptHex,
			AmountSats:       appPrice,
		}}, false

	case envelope.MonetizationSplit:
		if !pg.allowSplit {
			if nodePayee != nil {
				return []Payee{*nodePayee}, false
			}
			return nil, false
		}
		appPrice := mon.PriceSats
		if pg.maxAppPriceSats > 0 && appPrice > pg.maxAppPriceSats {
			appPrice = pg.maxAppPriceSats
		}
		appPayee := Payee{
			Role:             "content",
			LockingScriptHex: mon.PayeeLockingScriptHex,
			AmountSats:       appPrice,
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
