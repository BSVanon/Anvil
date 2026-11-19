package peerhygiene

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

// The memory budget for decoding lookup answers from advertised peers, any of
// which may be hostile.
//
// Every cap below bounds one answer, and at most LookupSlots answers are
// decoded at once, process-wide: an answer holds a slot from the moment its
// reply is read until go-sdk's facilitator, or BoundedFacilitator, has decoded
// it and closed the body. The worst case one slot holds live, for a binary
// answer (a JSON answer holds less), with B, N, E and P the caps below:
//
//	the guard's copy of the body (netguard)            B       2 MiB
//	go-sdk's io.ReadAll copy, at its last growth       2.25 B  4.5 MiB
//	one BEEF parse, by its cost bound                  P       4 MiB
//	the outputs' re-serialized BEEFs, with slack       2 E     2 MiB
//	outpoint and output records, ~152 bytes each       N       1.5 MiB
//	                                                           ~14 MiB
//
// Garbage collection at GOGC=100 lets the heap reach twice its live size, so
// one slot can claim about 28 MiB and LookupSlots slots about 112 MiB: within
// the 256 MiB set aside for the lookup path, which leaves the rest for answers
// already decoded. go-sdk's LookupResolver holds every decoded answer until
// the last host of a query replies (or the query times out), at most
// 2E + 40N, about 2.4 MiB, for a binary answer and PJSON + E + 40N for a JSON
// one. That part grows with the number of hosts a query reaches, which no
// per-answer cap and no slot can bound. Measured, each host that answers as
// expensively as the caps allow keeps about 4 MiB of heap in use until its
// query ends: a query reaching 48 of them peaks at 185 to 235 MiB with the
// slots and at 345 to 515 MiB without (the many-hosts tests that use
// hostiletest), and one reaching some 60 or more passes 256 MiB. The hosts a
// query reaches come from SLAP advertisements, so bounding them takes a
// change to go-sdk's resolver, outside this package.
//
// Honest answers fit with room to spare. A SHIP or SLAP advertisement with its
// merkle proof is about 1.15 KiB on the wire, re-serializes to the same per
// output, and costs about 4.3 KiB by beefCost. The caps admit about 900 of
// them per binary answer (E binds) and about 770 per JSON one (PJSON binds);
// the largest real answers hold tens, and held about 70 during the 2026-06
// advertisement flood.
const (
	// MaxLookupResponseBytes (B) caps how many bytes of one peer's /lookup
	// reply are read.
	MaxLookupResponseBytes int64 = 2 << 20
	// MaxLookupOutputs (N) caps the outputs one answer may list, in either
	// format. Real SHIP/SLAP answers list one output per advertising host and
	// topic: tens today, hundreds at most. 10,000 leaves headroom of an order
	// of magnitude and more.
	MaxLookupOutputs = 10_000
	// MaxAnswerBEEFBytes (E) caps the BEEF bytes one answer's outputs carry
	// in all: the re-serialized BEEF of every output of a binary answer,
	// repeats included, and the decoded BEEF of every output of a JSON one.
	// This is what go-sdk's resolver keeps of an answer until its query ends.
	MaxAnswerBEEFBytes int64 = 1 << 20
	// MaxBEEFParseCost (P) caps beefCost for any BEEF an answer carries: a
	// binary answer's shared BEEF, from which every output's re-serialized
	// BEEF takes a subset, and each output's BEEF in a JSON answer.
	MaxBEEFParseCost = 4 << 20
	// MaxJSONDecodeCost (PJSON) caps jsonCost for a JSON answer as a whole,
	// which bounds what decoding it, its interface{} "result" included,
	// keeps.
	MaxJSONDecodeCost = 2 << 20
	// LookupSlots is how many lookup answers the node decodes at once.
	LookupSlots = 4
)

var lookupSlots = make(chan struct{}, LookupSlots)

// ErrNoLookupSlot is returned, wrapping the context's cause, when a lookup's
// context ends while it waits for a decoding slot.
var ErrNoLookupSlot = errors.New("peerhygiene: no lookup decoding slot came free")

// AcquireLookupSlot waits until one of the LookupSlots decoding slots is free,
// or until ctx ends, and takes it. The caller must call release once the
// answer has been decoded; release returns the slot the first time it is
// called and does nothing after.
func AcquireLookupSlot(ctx context.Context) (release func(), err error) {
	select {
	case lookupSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %w", ErrNoLookupSlot, context.Cause(ctx))
	}
	var once sync.Once
	return func() { once.Do(func() { <-lookupSlots }) }, nil
}

// slotClaim records whether a lookup exchange already holds a slot.
// BoundedFacilitator puts one in its request context. When the request goes
// through the netguard transport, the transport takes the slot, holds it
// until the body is closed, and marks the claim, so the facilitator does not
// wait for a second slot while holding the first.
type slotClaim struct{ held atomic.Bool }

type slotClaimKey struct{}

func withSlotClaim(ctx context.Context) (context.Context, *slotClaim) {
	c := &slotClaim{}
	return context.WithValue(ctx, slotClaimKey{}, c), c
}

// MarkLookupSlotHeld tells a BoundedFacilitator whose request carries ctx
// that the exchange already holds a decoding slot, taken by the transport.
// Without a claim in ctx it does nothing.
func MarkLookupSlotHeld(ctx context.Context) {
	if c, ok := ctx.Value(slotClaimKey{}).(*slotClaim); ok {
		c.held.Store(true)
	}
}
