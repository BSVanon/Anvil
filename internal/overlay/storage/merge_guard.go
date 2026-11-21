package storage

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// Merging stored BEEFs. Every BEEF in the store passed admission on its own,
// but two of them can still prove the same block with paths that declare
// different numbers of levels. go-sdk v1.7.7's Beef.MergeBump combines two
// proofs of one block (beef.go:828), and that combine panics
// (merklepath.go:480, index out of range) when the proof merged in declares
// more levels than the one already held. go-sdk
// v1.2.23 matched proofs by pointer and never combined them, so the panic is
// new with v1.7.7. Normalizing each stored ancillary with beefnorm's
// canonical proofs before it is ever merged (normalizedBeefFromBytes) fixes
// old (pre-v3.4.1) stored data at this boundary, so a merge over stored
// BEEFs is also still guarded per item: a BEEF that cannot be parsed,
// normalized or merged is skipped, and the BEEF it was merged into is put
// back as it was before that one merge, whatever order the items merge in.

// ancillaryMerge merges a sequence of stored ancillary BEEFs into one target,
// taking exactly one snapshot of the target however many ancillaries it
// merges or how many of them fail: merging them one at a
// time by calling a self-contained per-item merge, each snapshotting the
// target itself before its own attempt, costs as much as the target's
// current size on every call, and the target grows with every success, so
// the total cost over k ancillaries is O(k^2), not O(k). ancillaryMerge
// takes its one snapshot before the first blob, and a failed merge rebuilds
// the target from that snapshot plus the blobs already merged successfully
// (rebuild), rather than from a fresh snapshot of the grown target. It keeps
// successful raw blobs, so this is the only snapshot in a merge sequence.
type ancillaryMerge struct {
	target   **transaction.Beef
	original []byte   // the target's bytes before the first blob, taken once
	good     [][]byte // blobs merged successfully so far, in merge order
}

// newAncillaryMerge starts a merge into *target, which must not be nil,
// taking its one snapshot.
func newAncillaryMerge(target **transaction.Beef) (*ancillaryMerge, error) {
	original, err := snapshotBEEF(*target)
	if err != nil {
		return nil, fmt.Errorf("copy the BEEF before merging ancillaries into it: %w", err)
	}
	return &ancillaryMerge{target: target, original: original}, nil
}

// merge parses blob, normalizes it with beefnorm's canonical proofs, and
// merges the result into the target. On a parse, normalization or merge
// failure the target is left as it was after the last successful merge (or
// as it started, if none has succeeded yet): a merge that panics part-way
// may already have combined or appended some of blob's proofs, so a failed
// merge rebuilds the target from the one snapshot taken at the start plus
// every blob merge already known good, rather than from a snapshot of the
// target taken for this attempt. Re-normalization is paid only if a rebuild
// is required.
func (m *ancillaryMerge) merge(blob []byte) error {
	other, err := normalizedBeefFromBytes(blob)
	if err != nil {
		return err
	}
	if err := guardedMergeBeef(*m.target, other); err != nil {
		rebuilt, rerr := m.rebuild()
		if rerr != nil {
			return fmt.Errorf("%w; restoring the previously merged ancillaries also failed: %v", err, rerr)
		}
		*m.target = rebuilt
		return err
	}
	m.good = append(m.good, append([]byte(nil), blob...))
	return nil
}

// rebuild re-parses the snapshot taken at the start and re-merges every blob
// already known good, in the order it was merged the first time. Each of
// those merges is expected to succeed exactly as it did before, since it
// merges the same blob into the same sequence of prior state; the merge is
// still guarded, not assumed.
func (m *ancillaryMerge) rebuild() (*transaction.Beef, error) {
	beef, err := safeNewBeefFromBytes(m.original)
	if err != nil {
		return nil, err
	}
	for _, blob := range m.good {
		other, err := normalizedBeefFromBytes(blob)
		if err != nil {
			return nil, fmt.Errorf("re-normalize a previously merged ancillary: %w", err)
		}
		if err := guardedMergeBeef(beef, other); err != nil {
			return nil, fmt.Errorf("re-merge a previously merged ancillary: %w", err)
		}
	}
	return beef, nil
}

// guardedMergeBeef runs target.MergeBeef(other), turning a panic into an
// error.
func guardedMergeBeef(target, other *transaction.Beef) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("BEEF merge panicked: %v", r)
		}
	}()
	return target.MergeBeef(other)
}

// snapshotBEEF serialises beef the way the store does (storableBeefBytes),
// turning a panic into an error, so that safeNewBeefFromBytes can rebuild it.
func snapshotBEEF(beef *transaction.Beef) (b []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			b, err = nil, fmt.Errorf("BEEF serialisation panicked: %v", r)
		}
	}()
	return snapshotBytes(beef)
}

// snapshotBytes is storableBeefBytes, as a variable so that a test can make
// it panic: no BEEF known today does.
var snapshotBytes = storableBeefBytes
