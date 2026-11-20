package gateway

import "sync/atomic"

// Counters are decision 8's aggregate, per-node gateway counters — no
// per-client or per-site breakdown, so they carry no privacy risk even
// though they are served on the existing, otherwise-open GET /stats (see
// internal/api's SetGatewayStats hook). The zero value is ready to use.
type Counters struct {
	Requests     atomic.Int64
	NotFound     atomic.Int64
	TXTLookups   atomic.Int64
	TXTStale     atomic.Int64
	ScopeRefused atomic.Int64
}

// Snapshot returns the current counts, keyed exactly as decision 8 names
// them, ready to merge into GET /stats.
func (c *Counters) Snapshot() map[string]int64 {
	if c == nil {
		return nil
	}
	return map[string]int64{
		"gateway_requests":         c.Requests.Load(),
		"gateway_not_found":        c.NotFound.Load(),
		"gateway_txt_lookups":      c.TXTLookups.Load(),
		"gateway_txt_stale_served": c.TXTStale.Load(),
		"gateway_scope_refused":    c.ScopeRefused.Load(),
	}
}
