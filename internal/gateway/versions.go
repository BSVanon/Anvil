package gateway

import "fmt"

// Versions resolves an origin's tracked history. Latest returns the effective
// content outpoint; At returns the location at a spend sequence (0 = origin).
//
// DefaultVersions does no tracking at all: every origin's latest version
// IS the origin. The node's version tracker (internal/ordtrack) implements
// Versions from its persisted version history, and cmd/anvil's gateway
// wiring passes it in. A Versions that is also a content.VersionResolver
// serves /content/<origin>?seq= on site hosts; one that also keeps a
// History roots a site's content scope at each of its versions.
type Versions interface {
	// Latest returns the effective content outpoint at the current location.
	Latest(origin string) (outpoint string, err error)
	// At returns the location at spend sequence seq (0 = the origin itself).
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
