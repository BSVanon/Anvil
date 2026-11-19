// Package beefscan refuses BEEFs whose structure would make the work done on
// them before their scripts run cost more than a request may, before any of
// it runs.
//
// The routes that take an untrusted BEEF (routeguard.PreVerify for /submit
// and /overlay/submit, spv's Validator.ValidateBEEF for /broadcast) parse it
// with transaction.NewBeefFromBytes, which reads it in one linear pass, and
// normalize it with package beefnorm: they keep the subject and the ancestry
// its verification reads, with one canonical BUMP per block, and everything
// after works on that. go-sdk v1.7.7 takes no context in any of it, and some
// of its costs are not linear in the bytes it reads:
//
//   - MerklePath.Extract, which beefnorm runs once per BUMP an entry names,
//     trims its result with a scan of a level for each node it drops
//     (merklepath.go:697-760): extracting k txids from a path of d levels
//     costs about k^2 * d. ComputeRoot, which spv.Verify (twice: the guard
//     and the engine) and Beef.Verify run for each proven transaction over
//     its block's canonical path, scans each level for the node it needs
//     (merklepath.go:100-122): k roots over a path of k txids cost about
//     k^2 * d too.
//   - Beef.Verify validates unproven entries in passes over those still
//     waiting (beef.go:1220-1256).
//   - NewTransactionFromBEEF on an Atomic BEEF, which the lookup services run
//     on the normalized one, asks every BUMP about every entry without a BUMP
//     index (beef.go:741-797).
//   - Plain counts expand too: the parser keeps hundreds of bytes for each
//     ten-byte empty transaction, and a 64 MiB V2 BEEF of them holds 1.28 GB.
//
// No route runs transaction.ParseBeef on a V1 BEEF, Transaction.BEEF or
// AtomicBEEF, or merges an untrusted BEEF into another, any more: each of
// those combines the proofs of one block in turn, superlinearly, and the
// combine and root costs Check charged for them up to v3.4.0 are gone.
//
// Scan walks the bytes without allocating from any declared count and reports
// the shape; Check refuses a shape over Default. Neither judges whether a BEEF
// is well formed: a malformed BEEF passes unless what precedes its first bad
// byte is already over a limit, and the parser then reports the fault. The
// one exception is a shape go-sdk accepts and then crashes on when it combines
// paths: BUMPs of one block that declare different numbers of levels (see
// Shape.MixedLevels).
package beefscan

import (
	"errors"
	"fmt"
)

// Code is the error code routes return, with status 400, when Check refuses a
// BEEF.
const Code = "ERR_BEEF_TOO_COMPLEX"

// ErrTooComplex is wrapped by every refusal from Check.
var ErrTooComplex = errors.New("BEEF too complex")

// Shape is what Scan found. Counts cover only the bytes actually present: a
// walk stops at the first byte the layout cannot account for, never before
// the point where go-sdk's parser would fail.
type Shape struct {
	// Version is BEEF_V1 or BEEF_V2, after any Atomic prefix; 0 if unreadable.
	Version uint32
	// Atomic reports an Atomic (BRC-95) prefix.
	Atomic bool
	// BUMPs counts the BUMPs read.
	BUMPs int
	// Leaves counts path elements across all BUMPs, duplicates included.
	Leaves int
	// Txs counts transaction entries, txid-only ones included.
	Txs int
	// Inputs counts inputs across all transactions.
	Inputs int
	// Outputs counts outputs across all transactions.
	Outputs int
	// ProofCost bounds, to a constant factor, the proof work beefnorm and the
	// calls on its BEEF do, in path nodes visited: sum over block heights h
	// of K_h^2 * (D_h + 1), for K_h entries naming BUMPs at h by index and D_h
	// the most levels any of those BUMPs has, declared or needed by its
	// widest level-0 offset (Extract and ComputeRoot climb that many). The
	// canonical path beefnorm makes for h holds at most the K_h named txids
	// and their siblings at each level, at most 2 * K_h nodes on any level,
	// so:
	//   - Extract's trim scans a level of at most 2 * K_h nodes for each of
	//     at most K_h * (D_h + 1) it drops, over every BUMP at h;
	//   - each of the K_h roots spv.Verify and Beef.Verify compute (one for
	//     each kept txid, which is all that is flagged) scans level 0 three
	//     times and each other level once, and finds every node it needs
	//     there, so it rebuilds none.
	// The work on a BUMP's own leaves before it is extracted is linear in
	// them (Extract's root over them, its index and its climbs, memoized),
	// which the leaves cap bounds.
	ProofCost uint64
	// ChainCost bounds Beef.Verify's validation of unproven entries, in
	// entries and inputs visited: E * (E + Inputs), for E entries that carry a
	// transaction. ValidateTransactions passes over the entries still waiting
	// until a pass validates none; each pass validates at least one, so there
	// are at most E passes, each over at most E entries and their inputs. An
	// entry with a BUMP index waits too when its txid is not in that BUMP,
	// which only hashing it could rule out, so E counts those entries as well.
	ChainCost uint64
	// FindCost bounds NewTransactionFromBEEF's proof search on an Atomic BEEF,
	// in BUMPs visited: U * BUMPs, for U entries that carry a transaction but
	// no BUMP index. FindAtomicTransactionByHash asks every BUMP whether it
	// proves each such entry it reaches.
	FindCost uint64
	// MixedLevels counts block heights whose BUMPs declare different numbers
	// of levels. Check refuses any. go-sdk v1.7.7 computes a path's root over
	// as many levels as its widest level-0 offset needs, its declared levels
	// or more (MerklePath.ComputeRoot, merklepath.go:394-405; a single-level
	// compound path holds a whole block's leaves at level 0), so paths of one
	// block that declare different levels can share a root; combining the
	// taller into the shorter then indexes past the shorter's levels and
	// panics (combineVerified, merklepath.go:468-480). V1 ParseBeef,
	// Transaction.BEEF, AtomicBEEF and MergeBeef all combine the paths of one
	// block. beefnorm extracts every path before it combines any, and refuses
	// extracted paths of one block of different heights, so this refusal is
	// a second line. Honest BEEFs never mix: go-sdk's own BEEF builders would
	// panic on them, and ts-sdk keeps one BUMP per block. Not counted when
	// the heights were not all kept.
	MixedLevels int
}

// Limits caps a Shape. A zero field allows none of what it counts; Default
// sets every field.
type Limits struct {
	Txs, Inputs, Outputs, BUMPs, Leaves int
	ProofCost, ChainCost, FindCost      uint64
}

// Default caps what an untrusted BEEF may contain, calibrated against go-sdk
// v1.7.7 on the release machine (16 cores, shared with other test runs). Each
// time below is the slowest of three runs on the worst accepted shape for
// that cap: of TestCalibrateCaps for the counts and the chain and find costs,
// measured in v3.4.0 with ParseBeef, which does all the NewBeefFromBytes the
// routes now run does, and Verify and NewTransactionFromBEEF on the BEEF as
// received, which beefnorm only shrinks; and of beefnorm's
// TestCalibrateProofCost and TestCalibrateRawPaths for the proof cost and
// the leaves. The slowest go-sdk call on any of them took 0.44 s (Verify at
// the chain cap), inside the 1 s target. Each margin is over the largest
// value among the legitimate fixtures, in V1, V2 and Atomic form
// (fixtures_test.go). TestCalibrateHeap holds the heap measurements.
var Default = Limits{
	// 10x the largest fixture (1,001). The costs do not count txid-only
	// entries, so only this bounds them: ParseBeef holds 198 B for each
	// 33-byte one. At the cap: 10,000 empty transactions, ParseBeef 4.2 ms.
	Txs: 10000,
	// 50x the largest fixture (2,000). At the cap ParseBeef takes 27 ms and
	// holds 21.0 MB.
	Inputs: 100000,
	// 125x the largest fixture (2,001). At the cap ParseBeef takes 22 ms and
	// holds 18.5 MB.
	Outputs: 250000,
	// 10x the largest fixture (1,000, one per block). At the cap, at distinct
	// heights, MergeBeef's scan of the BUMPs merged so far takes 25 ms in
	// all and Verify 33 ms.
	BUMPs: 10000,
	// 9.5x the largest fixture (21,000). At the cap, in one single-level
	// BUMP naming 1 or 1,256 txids, beefnorm.Parse takes 0.22 s, nearly all
	// of it Extract's root over the raw leaves, and peaks at 66 MB, 8.8 times
	// the body; as duplicate marks over 255 levels they hold 27.8 MB, the
	// canonical copy included, 39 times their 0.7 MB body.
	Leaves: 200000,
	// 1,000 parents of one block pass at any height a block reaches: 1,000^2
	// * 21 for 2^20 transactions, and up to 2^29 within the cap; v3.4.0's
	// combine cost refused 300. At the cap, over blocks of 2^11 to 2^255
	// transactions in five layouts, the slowest call was Parse, 96 ms (3.2 ns
	// a unit, 255 levels, a BUMP per parent); spv.Verify and Beef.Verify on
	// the canonical paths took at most 25 ms. That is 10 times inside the
	// target, for the second verification and a shared machine.
	ProofCost: 30000000,
	// 33x the largest fixture (3,004,001). At the cap, a chain of 7,070,
	// Verify takes 0.44 s, about 4.4 ns per unit.
	ChainCost: 100000000,
	// 10,000x the largest fixture (1,000). At the cap, 1,000 unproven
	// transactions over 10,000 BUMPs, NewTransactionFromBEEF takes 0.17 s.
	FindCost: 10000000,
}

// Scan reports the shape of b. It never allocates from a declared count: its
// only allocation is a table of 16-byte entries for the BUMPs actually read,
// which starts at 16 entries, doubles as it fills and never passes 1 MiB.
func Scan(b []byte) Shape {
	w := &walker{b: b}
	w.walk()
	return w.shape
}

// Check is Default.Check(b).
func Check(b []byte) error { return Default.Check(b) }

// Inspect is Default.Inspect(b).
func Inspect(b []byte) (Shape, error) { return Default.Inspect(b) }

// Check returns nil when b's shape is within l, or an error wrapping
// ErrTooComplex that names the first limit exceeded, with the value found and
// the cap. A count is refused as soon as the walk passes its cap, so its value
// is the cap plus one; the costs are refused once the walk is complete.
func (l Limits) Check(b []byte) error {
	_, err := l.Inspect(b)
	return err
}

// Inspect is Check, returning the shape too: what Scan reports when b is
// within l, and otherwise what the walk had found when it stopped.
func (l Limits) Inspect(b []byte) (Shape, error) {
	w := &walker{b: b, limited: true, caps: l}
	w.walk()
	if w.over == nil {
		switch s := w.shape; {
		case s.ProofCost > l.ProofCost:
			w.over = &exceeded{name: "proof cost", value: s.ProofCost, cap: l.ProofCost}
		case s.ChainCost > l.ChainCost:
			w.over = &exceeded{name: "chain cost", value: s.ChainCost, cap: l.ChainCost}
		case s.FindCost > l.FindCost:
			w.over = &exceeded{name: "find cost", value: s.FindCost, cap: l.FindCost}
		case s.MixedLevels > 0:
			w.over = &exceeded{name: "heights with BUMPs of mixed levels", value: uint64(s.MixedLevels), cap: 0} //nolint:gosec // a count
		}
	}
	if w.over != nil {
		return w.shape, fmt.Errorf("%w: %s %d over the cap of %d", ErrTooComplex, w.over.name, w.over.value, w.over.cap)
	}
	return w.shape, nil
}
