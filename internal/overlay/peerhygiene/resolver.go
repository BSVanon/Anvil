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

// NewResolver builds a hygiene-wrapped lookup resolver for the given network.
// logger may be nil.
func NewResolver(network overlay.Network, logger *slog.Logger) *Resolver {
	cfg := &lookup.LookupResolver{
		Facilitator:   NewFacilitator(&lookup.HTTPSOverlayLookupFacilitator{Client: http.DefaultClient}, logger),
		NetworkPreset: network,
	}
	// NewLookupResolver preserves a non-nil cfg.Facilitator and applies the
	// network's default SLAP trackers.
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
