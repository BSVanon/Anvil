package gateway

import "fmt"

// Versions resolves an origin's version history: which outpoint is
// currently the latest version (what a public ordinals gateway's seq=-1
// means) and which outpoint sits at a given sequence number (0 = the
// origin itself).
//
// DefaultVersions does no tracking at all: every origin's latest version
// IS the origin. The node's version tracker (internal/ordtrack) implements
// Versions from its persisted version history, and cmd/anvil's gateway
// wiring passes it in. A Versions that is also a content.VersionResolver
// serves /content/<origin>?seq= on site hosts; one that also keeps a
// History roots a site's content scope at each of its versions.
type Versions interface {
	// Latest returns the outpoint currently serving as origin's tip.
	Latest(origin string) (outpoint string, err error)
	// At returns the outpoint at version seq (0 = the origin itself).
	At(origin string, seq int) (outpoint string, err error)
}

// DefaultVersions is the Versions of a node that tracks no versions: the
// origin itself, always at seq 0.
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
