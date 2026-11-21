package api

import "github.com/BSVanon/Anvil/internal/content"

// ContentServer exposes the node's shared on-chain content server — its
// existing fetch, txid check and cache (internal/content.Server) — so the
// gateway mechanism (internal/gateway, wired in cmd/anvil) serves a custom
// domain's inscriptions from the exact same warm cache /content/ already
// uses, rather than a second, cold one.
func (s *Server) ContentServer() *content.Server { return s.contentServer }

// SetGatewayStats registers a callback whose returned counters are merged
// into GET /stats under "gateway" when non-nil.
// aggregate gateway counters (internal/gateway) surface through, without
// this package depending on internal/gateway. Call at most once; the last
// call wins. A nil or empty-map result omits the "gateway" field entirely
// (e.g. gateway mode off).
func (s *Server) SetGatewayStats(fn func() map[string]int64) { s.gatewayStatsFn = fn }
