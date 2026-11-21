package gateway

import "sync/atomic"

// Counters are the aggregate, per-node gateway counters — no per-client
// or per-site breakdown, so they carry no privacy risk even though they
// are served on the existing, otherwise-open GET /stats (see
// internal/api's SetGatewayStats hook). The zero value is ready to use.
//
// The TLS/ACME fields (TLSHandshakes, CertIssued, CertErrors,
// ACMERefusedHost) are the same shared instance passed to
// NewResolver/NewSiteHandler, reused rather than duplicated so the TLS
// listeners and the challenge cache need no second stats plumbing into
// GET /stats — see cmd/anvil's gateway wiring.
type Counters struct {
	Requests     atomic.Int64
	NotFound     atomic.Int64
	TXTLookups   atomic.Int64
	TXTStale     atomic.Int64
	ScopeRefused atomic.Int64

	TLSHandshakes   atomic.Int64
	CertIssued      atomic.Int64
	CertErrors      atomic.Int64
	ACMERefusedHost atomic.Int64
}

// Snapshot returns the current counts, ready to merge into GET /stats.
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

		"gateway_tls_handshakes":    c.TLSHandshakes.Load(),
		"gateway_cert_issued":       c.CertIssued.Load(),
		"gateway_cert_errors":       c.CertErrors.Load(),
		"gateway_acme_refused_host": c.ACMERefusedHost.Load(),
	}
}
