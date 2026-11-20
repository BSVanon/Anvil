package gateway

import "fmt"

// Versions resolves an origin's version history: which outpoint is
// currently the tip (what a public ordinals gateway's seq=-1 means) and
// which outpoint sits at a given sequence number (0 = the origin itself).
// This is decision 9's second seam.
//
// DefaultVersions, B7a's implementation, does no tip tracking at all:
// every origin's latest version IS the origin (decision 5). B8 (BRC-159
// tip tracking, requirement P1-C) constructs its own Versions backed by
// persisted version history, and cmd/anvil's gateway wiring swaps it in —
// nothing here, in Router or in SiteHandler needs to change, since they
// only ever call this interface.
type Versions interface {
	// Latest returns the outpoint currently serving as origin's tip.
	Latest(origin string) (outpoint string, err error)
	// At returns the outpoint at version seq (0 = the origin itself).
	At(origin string, seq int) (outpoint string, err error)
}

// DefaultVersions is B7a's placeholder Versions (decision 5): the origin
// itself, always at seq 0.
type DefaultVersions struct{}

// Latest implements Versions.
func (DefaultVersions) Latest(origin string) (string, error) { return origin, nil }

// At implements Versions.
func (DefaultVersions) At(origin string, seq int) (string, error) {
	if seq != 0 {
		return "", fmt.Errorf("version %d not tracked", seq)
	}
	return origin, nil
}
