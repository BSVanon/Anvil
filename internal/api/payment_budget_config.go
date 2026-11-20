package api

import (
	"log/slog"
	"time"
)

// The ceilings of the configured mint budget. Without them a huge
// x402_mints_per_minute rounds the refill interval down to zero and a huge
// x402_mint_burst gives the bucket years of slack, and either one lets
// callers mint without limit. At the ceilings the node mints at most
// maxMintBurst + maxMintsPerMinute*60 = 4,600 nonces in an hour, which costs
// 4,600 nonce sats plus 23..76 sats of fees each (payment_budget.go):
// 110,400..354,200 sats.
const (
	maxMintBurst      = 1000
	maxMintsPerMinute = 60
)

// ConfigureMintBudget replaces defaultMintBudget with one allowing burst
// mints at once and refilling at perMinute mints a minute: the [api]
// x402_mint_burst and x402_mints_per_minute keys. Each value is bounded first
// (boundMintBudgetValue), and the budget in effect is logged.
//
// Call it once, at startup, before any PaymentGate or UTXONoncePool is made:
// both capture defaultMintBudget when they are built (withMintBudget), so a
// later call does not reach them.
func ConfigureMintBudget(burst, perMinute int) {
	burst = boundMintBudgetValue("x402_mint_burst", burst, mintBurst, maxMintBurst)
	perMinute = boundMintBudgetValue("x402_mints_per_minute", perMinute, mintsPerMinute, maxMintsPerMinute)
	defaultMintBudget = newMintBudget(burst, perMinute, time.Now)
	slog.Info("x402: nonce mint budget", "burst", burst, "per_minute", perMinute,
		"max_mints_per_hour", burst+perMinute*60)
}

// boundMintBudgetValue returns v within 1..ceiling: def for 0, which is the
// key left unset, and for a negative v; ceiling for a v above it. A value it
// replaces, other than 0, is logged as a warning.
func boundMintBudgetValue(setting string, v, def, ceiling int) int {
	switch {
	case v == 0:
		return def
	case v < 0:
		slog.Warn("x402: negative mint budget value, using the default", "setting", setting, "value", v, "default", def)
		return def
	case v > ceiling:
		slog.Warn("x402: mint budget value over its ceiling, using the ceiling", "setting", setting, "value", v, "ceiling", ceiling)
		return ceiling
	}
	return v
}
