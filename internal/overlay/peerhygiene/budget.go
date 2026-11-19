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
// A peer's reply is read first, under one of bodyread.LookupPermits (32)
// process-wide read permits and within bodyread's time and rate limits, and
// only then checked and decoded, under one of LookupSlots (4) decoding slots,
// so a peer that sends its reply slowly holds a permit, never a slot. The
// bodies read and waiting for a slot hold at most 32 B, 64 MiB, beside what
// the slots hold. Through http.DefaultClient the netguard transport reads and
// checks the reply and hands go-sdk's facilitator, in a binary reply's place,
// the JSON answer of the outputs it checked (PrepareLookupAnswer);
// BoundedFacilitator reads and decodes its own requests' replies the same way.
//
// Every cap below bounds one answer. What one slot holds live at once, for a
// binary answer through netguard (a JSON answer holds less), with B, N, E and
// P the caps below, is the larger of two phases, each about 12.6 MiB:
//
//	checking: the body B, the shared BEEF's parse by its cost bound P,
//	the outputs' rebuilt BEEFs E, the JSON built from them 4/3 E + 40 N,
//	and the outpoint and output records, about 152 bytes each, N;
//	go-sdk's decode: the JSON handed on, go-sdk's io.ReadAll copy of it,
//	2.25 times at its last growth, and the decoded outputs, E + 48 N.
//
// Garbage collection at GOGC=100 lets the heap reach twice its live size, so
// one slot can claim about 26 MiB and LookupSlots slots about 104 MiB, which
// with the bodies read ahead leaves about 88 MiB of the 256 MiB set aside for
// the lookup path for answers already decoded. go-sdk's LookupResolver holds
// every decoded answer until the last host of a query replies (or the query
// times out), E + 48 N, about 2.5 MiB, for a binary answer and PJSON + E +
// 40 N for a JSON one. That part grows with the number of hosts a query
// reaches, which no per-answer cap and no slot can bound. Measured, a query
// reaching 48 hosts that each answer as expensively as the caps allow peaks
// at 234 to 262 MiB of heap in use with the slots and at 363 to 371 MiB
// without (the many-hosts tests that use hostiletest), about 5 MiB a host, so
// a query reaching some 50 or more such hosts can pass 256 MiB. The hosts a
// query reaches come from SLAP advertisements, so bounding them takes a
// change to go-sdk's resolver, outside this package.
//
// Honest answers fit. go-sdk v1.7.7 rebuilds every output of a binary answer
// with each proof of its transaction's BUMP, which grows as the square of the
// outputs mined in one block (see splitProofs); split, 256 advertisements of
// 1.8 KB mined in one block of 2^20 transactions come to 704 KB of outputs,
// where go-sdk would have built 32.8 MB. On anvil-a (2026-11-19) the SHIP and
// SLAP advertisements' transactions average 1.9 KB (5.1 KB at most), and the
// largest answer to a question go-sdk's resolvers ask lists 74 outpoints with
// 136 KB of transactions; listing every advertisement, as an empty query
// does, came to 354 outpoints. E admits those 74 with their proofs and
// ancestors many times over, and the caps admit 800 small advertisements
// with 20-level proofs in a binary answer and 700 in a JSON one.
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
	// It was 1 MiB, under the 1.2 MB or so that listing every advertisement
	// anvil-a holds would come to, at some 2 KB of transaction and 1.4 KB of
	// proof and ancestry each.
	MaxAnswerBEEFBytes int64 = 2 << 20
	// MaxAnswerCombineWork caps the merkle-path elements that combining
	// same-block proofs may walk for one answer: while its outputs' BEEFs are
	// rebuilt, and when go-sdk parses each output again, repeats included.
	MaxAnswerCombineWork uint64 = 4 << 20
	// MaxBEEFParseCost (P) caps beefCost for any BEEF an answer carries: a
	// binary answer's shared BEEF, from which every output's re-serialized
	// BEEF takes a subset, and each output's BEEF in a JSON answer.
	MaxBEEFParseCost = 4 << 20
	// MaxJSONDecodeCost (PJSON) caps jsonCost for a JSON answer as a whole,
	// which bounds what decoding it, its interface{} "result" included,
	// keeps.
	MaxJSONDecodeCost = 2 << 20
	// MaxOutputScriptChunks caps the chunks script.Chunks decodes from the
	// locking script an output of an answer names. go-sdk's resolver and
	// topic broadcaster decode that script as an advertisement
	// (admintoken.Decode), which held 71.2 MiB for a script of 1.5 million
	// one-byte opcodes; at the cap it holds some 6 MiB. A SHIP or SLAP
	// advertisement decodes to about ten chunks.
	MaxOutputScriptChunks = 100_000
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
