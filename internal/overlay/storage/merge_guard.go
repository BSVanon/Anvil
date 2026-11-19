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
// more levels than the one already held (cold-review round 3, B3). go-sdk
// v1.2.23 matched proofs by pointer and never combined them, so the panic is
// new with v1.7.7. One stored item must never fail a whole lookup answer, so
// a merge over stored BEEFs is guarded per item: a BEEF that cannot be parsed
// or merged is skipped, and the BEEF it was merged into is put back as it was.

// mergeStoredBEEF merges the stored BEEF blob into *target. When the blob
// cannot be parsed, or the merge fails or panics, it returns the error and
// leaves *target as it was before the call: a merge that panics part-way may
// already have combined or appended some of the blob's proofs, so *target is
// then replaced by a copy taken before the merge. *target must not be nil.
func mergeStoredBEEF(target **transaction.Beef, blob []byte) error {
	other, err := safeNewBeefFromBytes(blob)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	before, err := snapshotBEEF(*target)
	if err != nil {
		return fmt.Errorf("copy the BEEF it would merge into: %w", err)
	}
	if err := guardedMergeBeef(*target, other); err != nil {
		restored, perr := safeNewBeefFromBytes(before)
		if perr != nil {
			return fmt.Errorf("%w; restoring the BEEF it was merged into also failed: %v", err, perr)
		}
		*target = restored
		return err
	}
	return nil
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
