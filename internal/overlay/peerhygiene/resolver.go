package peerhygiene

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
)

// Resolver is a drop-in replacement for engine.NewLookupResolverWithNetwork that
// satisfies the engine's LookupResolverProvider interface (SLAPTrackers /
// SetSLAPTrackers / Query) while routing every per-host lookup through the
// hygiene Facilitator. The engine's own LookupResolver hides the underlying
// go-sdk resolver's Facilitator behind a private field, so the only way to inject
// hygiene is to build the go-sdk resolver ourselves and supply this provider to
// engine.LookupResolver.
//
// Behaviour is otherwise identical to the engine's resolver: same SLAP-tracker
// handling, same Query semantics — unreachable peers just get skipped/backed-off
// instead of re-queried every round.
type Resolver struct {
	inner *lookup.LookupResolver
}

// NewResolver builds a hygiene-wrapped lookup resolver for the given network,
// with trackers applied directly at construction. logger may be nil.
// Per-host lookups go through BoundedFacilitator instead of go-sdk's
// HTTPSOverlayLookupFacilitator, whose unbounded read and wire-sized
// allocations let any advertised host crash the node.
//
// trackers is taken as-given: pass nil to get go-sdk's network-default SLAP
// trackers (lookup.NewLookupResolver backfills only when SLAPTrackers is
// nil), or a non-nil slice — including an empty one — to pin the resolver to
// exactly those trackers from the start. This exists because the
// construct-then-SetSLAPTrackers two-step this replaced was fragile: go-sdk's
// own SetSLAPTrackers (mirrored by this package's own, see SetSLAPTrackers
// below) silently no-ops on an empty slice, so a call site that always
// intends to override could, if trackers were ever computed as empty, end up
// silently keeping whatever NewLookupResolver had already defaulted to.
// Passing the real tracker set at construction removes that ambiguity: there
// is no separate step where the override can be skipped. SetSLAPTrackers
// remains for a resolver already in use that needs its trackers changed
// later; it is unrelated to this constructor-time fix.
func NewResolver(network overlay.Network, trackers []string, logger *slog.Logger) *Resolver {
	cfg := &lookup.LookupResolver{
		Facilitator:   NewFacilitator(&BoundedFacilitator{Client: http.DefaultClient}, logger),
		NetworkPreset: network,
		SLAPTrackers:  trackers,
	}
	return &Resolver{inner: lookup.NewLookupResolver(cfg)}
}

// SLAPTrackers returns the currently configured SLAP trackers.
func (r *Resolver) SLAPTrackers() []string { return r.inner.SLAPTrackers }

// SetSLAPTrackers configures the SLAP trackers; an empty slice leaves them
// unchanged (mirrors engine.LookupResolver.SetSLAPTrackers).
func (r *Resolver) SetSLAPTrackers(trackers []string) {
	if len(trackers) == 0 {
		return
	}
	r.inner.SLAPTrackers = trackers
}

// Query resolves a lookup question across the configured peers, with dead-peer
// hygiene applied per host via the wrapped Facilitator.
func (r *Resolver) Query(ctx context.Context, question *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	return r.inner.Query(ctx, question)
}
