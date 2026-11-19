// Package beefscan refuses BEEFs whose structure would make go-sdk's parse or
// serialization do more work than a request may cost, before any of it runs.
//
// go-sdk v1.7.7's transaction.ParseBeef takes no context, so once it starts
// nothing can stop it. Its cost is not linear in the bytes it reads:
//
//   - For a V1 BEEF, NewBeefFromTransaction (beef.go:427-468) combines the
//     proof of every ancestor whose BUMP is at a block height it has already
//     seen into the first proof at that height, a proof that shares its BUMP
//     with an earlier ancestor included, so a path then combines with itself.
//     Each MerklePath.Combine (merklepath.go:446-500) computes both roots and
//     rebuilds and sorts the accumulated path, so the work is about
//     sum over heights h of (k_h - 1) * L_h, for k_h transactions with a BUMP
//     at h and L_h leaves at h.
//   - Transaction.BEEF (beef.go:577-622) and AtomicBEEF (transaction.go:
//     681-730) run the same loop over a parsed subject's ancestry, whichever
//     version it was parsed from.
//   - Beef.Verify (beef.go:1095) computes a root for every level-0 leaf flagged
//     as a txid, each over its whole BUMP.
//   - Plain counts expand too: the parser keeps hundreds of bytes for each
//     ten-byte empty transaction, and a 64 MiB V2 BEEF of them holds 1.28 GB.
//
// Scan walks the bytes without allocating from any declared count and reports
// the shape; Check refuses a shape over Default. Neither judges whether a BEEF
// is well formed: a malformed BEEF passes unless what precedes its first bad
// byte is already over a limit, and the parser then reports the fault. The
// one exception is a shape go-sdk accepts and then crashes on: BUMPs of one
// block that declare different numbers of levels (see Shape.MixedLevels).
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
	// CombineCost bounds the MerklePath.Combine work, in leaves visited, of
	// NewBeefFromTransaction (which ParseBeef runs on a V1 BEEF), of
	// Transaction.BEEF and AtomicBEEF on any parsed subject, and of
	// Beef.MergeBeef merging the parsed BEEF into one of its own. Group the
	// BUMPs by block height h: b_h BUMPs with L_h leaves among them, named by
	// k_h entries' BUMP indexes. Each Combine at h visits at most the
	// accumulated path and the incoming one, both within L_h. The ancestry
	// loops combine at most k_h - 1 times at h; MergeBeef combines at most
	// b_h - 1 BUMPs, then each indexed entry's proof once more. So the work
	// is within sum_h (k_h + b_h - 1) * L_h. An entry with no BUMP index can
	// still be given a proof after parsing, by NewTransactionFromBEEF on an
	// Atomic BEEF or by Beef.MergeBump, so each such entry adds the widest
	// L_h as well. The bound holds for V1, V2 and Atomic alike: the
	// serializers run on whatever was parsed. It also covers Beef.Verify's
	// checks that each indexed entry's txid is in its BUMP, k_h scans of at
	// most L_h leaves.
	CombineCost uint64
	// RootCost bounds Beef.Verify's root computations, in leaves visited:
	// sum_h T_h * L_h, for T_h level-0 leaves at height h that carry a hash
	// and the txid flag. Verify computes one root per such leaf, over its
	// BUMP, which is within L_h whether or not the BUMPs at h were combined.
	RootCost uint64
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
	// block. Honest BEEFs never mix: go-sdk's own BEEF builders would panic
	// on them. Not counted when the heights were not all kept.
	MixedLevels int
}

// Limits caps a Shape. A zero field allows none of what it counts; Default
// sets every field.
type Limits struct {
	Txs, Inputs, Outputs, BUMPs, Leaves        int
	CombineCost, RootCost, ChainCost, FindCost uint64
}

// Default caps what an untrusted BEEF may contain, calibrated against go-sdk
// v1.7.7 on the release machine (16 cores, shared with other test runs). Each
// time below is the slowest of three runs of TestCalibrateCaps on the worst
// accepted shape for that cap; the slowest go-sdk call on any of them took
// 0.69 s, inside the 1 s target. Each margin is over the largest value among
// the legitimate fixtures, in V1, V2 and Atomic form (fixtures_test.go).
// TestCalibrateHeap holds the heap measurements.
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
	// 9.5x the largest fixture (21,000). At the cap, in one BUMP, Verify's
	// root over all of them takes 50 ms; as duplicates they hold 8.8 MB.
	Leaves: 200000,
	// 6.35x the largest fixture (157,459: 100 inputs from one block). At the
	// cap, one 16,385-leaf BUMP named by 60 parents, the V1 parse, BEEF and
	// AtomicBEEF each take 0.66 to 0.69 s, about 0.69 us per unit.
	CombineCost: 1000000,
	// 12.8x the largest fixture (155,900). At the cap Verify takes 0.34 s
	// (1,414 txids over 1,414 leaves) and 0.48 s (100 over 20,000).
	RootCost: 2000000,
	// 33x the largest fixture (3,004,001). At the cap, a chain of 7,070,
	// Verify takes 0.44 s, about 4.4 ns per unit.
	ChainCost: 100000000,
	// 10,000x the largest fixture (1,000). At the cap, 1,000 unproven
	// transactions over 10,000 BUMPs, NewTransactionFromBEEF takes 0.17 s.
	FindCost: 10000000,
}

// Scan reports the shape of b. It never allocates from a declared count: its
// only allocation is a table of 32-byte entries for the BUMPs actually read,
// which starts at 16 entries, doubles as it fills and never passes 2 MiB.
func Scan(b []byte) Shape {
	w := &walker{b: b}
	w.walk()
	return w.shape
}

// Check is Default.Check(b).
func Check(b []byte) error { return Default.Check(b) }

// Check returns nil when b's shape is within l, or an error wrapping
// ErrTooComplex that names the first limit exceeded, with the value found and
// the cap. A count is refused as soon as the walk passes its cap, so its value
// is the cap plus one; the costs are refused once the walk is complete.
func (l Limits) Check(b []byte) error {
	w := &walker{b: b, limited: true, caps: l}
	w.walk()
	if w.over == nil {
		switch s := w.shape; {
		case s.CombineCost > l.CombineCost:
			w.over = &exceeded{name: "combine cost", value: s.CombineCost, cap: l.CombineCost}
		case s.RootCost > l.RootCost:
			w.over = &exceeded{name: "root cost", value: s.RootCost, cap: l.RootCost}
		case s.ChainCost > l.ChainCost:
			w.over = &exceeded{name: "chain cost", value: s.ChainCost, cap: l.ChainCost}
		case s.FindCost > l.FindCost:
			w.over = &exceeded{name: "find cost", value: s.FindCost, cap: l.FindCost}
		case s.MixedLevels > 0:
			w.over = &exceeded{name: "heights with BUMPs of mixed levels", value: uint64(s.MixedLevels), cap: 0} //nolint:gosec // a count
		}
	}
	if w.over != nil {
		return fmt.Errorf("%w: %s %d over the cap of %d", ErrTooComplex, w.over.name, w.over.value, w.over.cap)
	}
	return nil
}
