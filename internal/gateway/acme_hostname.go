package gateway

// The one place this package turns an externally-influenced name into a
// filesystem path inside the acme cache directory, and the shared
// syntax checks that gate both that path and ApplyReceived's keys. See
// acmecache.go's RecordIssuanceError/SiteCertState (the path) and
// ApplyReceived (the key checks) for the callers.

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/BSVanon/Anvil/internal/sitesfile"
)

var (
	// errInvalidHostname is errorNotePath's refusal for a name that
	// isn't a syntactically valid hostname — never built into a path.
	errInvalidHostname = errors.New("gateway: not a valid hostname")
	// errPathEscapesDir is errorNotePath's second, independent guard:
	// even after isValidHostname passes and the anchoring runs, the
	// result must still resolve inside dir.
	errPathEscapesDir = errors.New("gateway: path escapes the cache directory")
)

// errorNotePath returns the path RecordIssuanceError/SiteCertState use
// for domain's "+lasterror" note — the one place this package builds a
// filesystem path from a value that can originate directly from an
// unauthenticated TLS ClientHello's SNI (wrapGetCertificate, tls.go).
// Every such path goes through this one function.
//
// domain must be a syntactically valid hostname (isValidHostname) in any
// case; the path is always built from its normalised (lowercase) form,
// never from domain as given, so two callers that differ only in case
// always agree on one file. Anything that fails isValidHostname is
// refused before any path is built.
//
// The result is anchored the same way autocert.DirCache anchors every
// key it's given — filepath.Join(dir, filepath.Clean("/"+name)), which
// can't climb above dir, since Clean collapses ".." against a leading
// "/" rather than resolving it against dir's actual parent on disk. Cite
// golang.org/x/crypto@v0.59.0/acme/autocert/cache.go:43 (DirCache.Get);
// the identical pattern repeats at :84 (Put) and :98 (Delete). The
// result is then independently checked to still be inside dir, a second
// guard against the anchoring ever being built wrong.
func errorNotePath(dir, domain string) (string, error) {
	normalized, ok := isValidHostname(domain)
	if !ok {
		return "", fmt.Errorf("%w: %q", errInvalidHostname, domain)
	}
	cleanDir := filepath.Clean(dir)
	anchored := filepath.Clean(string(filepath.Separator) + normalized + "+lasterror")
	joined := filepath.Join(cleanDir, anchored)
	if joined != cleanDir && !strings.HasPrefix(joined, cleanDir+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %q", errPathEscapesDir, domain)
	}
	return joined, nil
}

// isValidHostname reports whether name is a syntactically valid
// hostname in any case, and returns it normalised to the one canonical
// (lowercase) spelling every other use of a hostname in this gateway
// shares. The label shape (letters/digits/hyphens, 1-63 characters, no
// leading or trailing hyphen, 253 characters overall) is
// internal/sitesfile.ValidateDomain's own rule — reused here rather than
// re-implemented, since a sites-file domain entry and a certificate
// domain must agree on what a hostname looks like. The one rule this
// function adds on top is "at least one dot": ValidateDomain alone would
// accept a bare single-label name like "localhost", which must never be
// treated as a hostname a certificate path or ApplyReceived's domain
// check can be built from.
func isValidHostname(name string) (string, bool) {
	normalized, ok := sitesfile.ValidateDomain(name)
	if !ok || !strings.Contains(normalized, ".") {
		return "", false
	}
	return normalized, true
}

// isValidACMEToken reports whether token is a syntactically valid ACME
// challenge token: non-empty and drawn only from the base64url character
// set (letters, digits, '-', '_'). RFC 8555 §8.3 ties the HTTP-01
// challenge token to exactly that character set — a real token is never
// built from anything else, so this rejects '/', '..', NUL, whitespace,
// and any other byte that has no business in a replicated cache key
// before that key is ever used to look anything up or store anything.
// This checks the character set only, not that the string decodes as a
// complete base64 group (a short alphabetic string like "tok" is valid
// base64url text without being a "whole" base64 encoding, and real ACME
// tokens are not padded) — matching what RFC 8555 actually constrains.
// The length cap (128) is generous headroom over any real token
// (autocert/RFC 8555 tokens are on the order of 22-43 characters) while
// still refusing an absurdly long string before it's used to build a
// cache key.
func isValidACMEToken(token string) bool {
	if token == "" || len(token) > 128 {
		return false
	}
	for i := 0; i < len(token); i++ {
		c := token[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}
