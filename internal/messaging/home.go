package messaging

// Decision 2 (B6 messaging-privacy spec): the Home Rule. For a recipient
// identity, HomeResolver answers whether THIS node is one of the hosts
// the recipient has currently advertised via a canonical tm_messagebox
// record, by querying ls_messagebox (internal/overlay/lookups/messagebox.go).
//
// B10 will extend adverts with certificates (bu_b6_spec.md "Neighbour
// bricks"); HomeResolver's job is limited to reading adverts, so its one
// dependency — AdvertSource — is the seam B10 extends, exactly as
// decision 4's ForwardPeerFilter is the seam for certified peers.

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// HomeState is the three-way answer decision 2 defines.
type HomeState int

const (
	// Unadvertised: there are no current qualifying adverts for the
	// recipient at all. Today's behaviour (no HomeResolver wired, or the
	// recipient has never anointed a host) always answers this.
	Unadvertised HomeState = iota
	// Home: at least one current qualifying advert names one of this
	// node's own hosts.
	Home
	// Elsewhere: there are current qualifying adverts, but none of them
	// names this node.
	Elsewhere
)

// String renders the state for logs/tests.
func (s HomeState) String() string {
	switch s {
	case Home:
		return "home"
	case Elsewhere:
		return "elsewhere"
	default:
		return "unadvertised"
	}
}

// Resolution is what HomeResolver answers for one recipient. State is
// the three-way decision-2 answer; HasOtherHost is extra information
// decision 3's "Forward received, Home" row needs (relay only when the
// recipient ALSO advertises a host that isn't this node) — meaningful
// only when State == Home, so callers must not read it otherwise.
type Resolution struct {
	State        HomeState
	HasOtherHost bool
}

// HomeResolver answers the Home Rule for a recipient identity key (hex).
type HomeResolver interface {
	Resolve(recipientIdentityHex string) (Resolution, error)
}

// Advert is the minimal shape HomeResolver needs from an ls_messagebox
// record: the raw (un-normalised) host field of one current advert.
type Advert struct {
	Host string
}

// AdvertSource fetches every current advert's host for a recipient
// identity. Implemented, in production, over
// lookups.MessageBoxLookupService.CurrentHosts by the cmd/anvil wiring —
// kept as a plain function type so this package has no dependency on
// the overlay/lookups package. A nil AdvertSource (or one that always
// returns no hosts) makes every Resolve answer Unadvertised — "when this
// node doesn't host the topic" (decision 2's last bullet), e.g. overlay
// disabled or the engine not yet constructed.
type AdvertSource func(recipientIdentityHex string) ([]Advert, error)

// AlwaysUnadvertised is a HomeResolver that answers Unadvertised for
// every recipient, with no error — today's behaviour, and the safe
// default when no resolver is wired (nil HomeResolver fields fall back
// to this at Store/Manager construction, so calling code never needs a
// nil check).
var AlwaysUnadvertised HomeResolver = alwaysUnadvertisedResolver{}

type alwaysUnadvertisedResolver struct{}

func (alwaysUnadvertisedResolver) Resolve(string) (Resolution, error) {
	return Resolution{State: Unadvertised}, nil
}

// lookupHomeResolver is the production HomeResolver: current adverts
// from AdvertSource, filtered through the canonical client's host rules
// and compared against this node's own normalised hosts.
type lookupHomeResolver struct {
	hosts  []string // this node's own hosts, pre-normalised
	source AdvertSource
}

// NewHomeResolver builds a HomeResolver over ownHosts (this node's
// `[node] public_url` plus `[messaging] home_hosts`, per decision 2) and
// source. ownHosts entries that don't pass the qualifying-host rules
// (https only, no loopback/.local/.example.com/.test/.invalid/.localhost)
// are dropped at construction — an operator's own non-qualifying
// public_url (e.g. plain http, or a dev loopback) can never match a
// qualifying remote advert, so it would never contribute to a Home
// answer anyway; dropping it up front just avoids redoing the check per
// call.
func NewHomeResolver(ownHosts []string, source AdvertSource) HomeResolver {
	normalised := make([]string, 0, len(ownHosts))
	for _, h := range ownHosts {
		if nh, ok := qualifyAndNormalise(h); ok {
			normalised = append(normalised, nh)
		}
	}
	return &lookupHomeResolver{hosts: normalised, source: source}
}

// Resolve implements HomeResolver.
func (r *lookupHomeResolver) Resolve(recipientIdentityHex string) (Resolution, error) {
	if r == nil || r.source == nil {
		return Resolution{State: Unadvertised}, nil
	}
	adverts, err := r.source(recipientIdentityHex)
	if err != nil {
		return Resolution{}, err
	}

	hasAny := false
	isHome := false
	hasOther := false
	seen := make(map[string]bool, len(adverts)) // K6: dedupe hosts after normalisation
	for _, a := range adverts {
		nh, ok := qualifyAndNormalise(a.Host)
		if !ok {
			// Only adverts that pass the canonical client's host filter
			// count (decision 2, "Which adverts count").
			continue
		}
		if seen[nh] {
			// K6: two raw advert forms (differing only by case, a
			// trailing slash, or textual IPv4/IDN encoding — see
			// qualifyAndNormalise) can normalise to the same qualifying
			// host; count each distinct host once.
			continue
		}
		seen[nh] = true
		hasAny = true
		if r.ownsHost(nh) {
			isHome = true
		} else {
			hasOther = true
		}
	}

	switch {
	case isHome:
		return Resolution{State: Home, HasOtherHost: hasOther}, nil
	case hasAny:
		return Resolution{State: Elsewhere}, nil
	default:
		return Resolution{State: Unadvertised}, nil
	}
}

func (r *lookupHomeResolver) ownsHost(normalisedHost string) bool {
	for _, h := range r.hosts {
		if h == normalisedHost {
			return true
		}
	}
	return false
}

// qualifyAndNormalise applies the canonical client's host filter
// (host.ts:43-59 isLocalHostname, reached through
// normalizeOverlayMessageBoxHost at host.ts:102-111 — https only, and
// none of localhost, 127.0.0.1, 0.0.0.0, ::1, *.local, *.example.com,
// *.test, or *.invalid, or *.localhost) and, if it passes, returns the
// normalised form: lowercase scheme and host, default port dropped,
// trailing slash dropped, path kept. Returns ("", false) for a host that
// fails the filter, isn't valid UTF-8 (N4 — see below), or doesn't parse
// as a URL.
//
// N4: a host whose bytes aren't valid UTF-8 is never counted, full stop
// — this is now the ONLY place that checks it. Admission used to refuse
// such a host outright (topics/messagebox.go); it no longer does,
// matching canon's own non-fatal decode, so an adversarial advert with a
// garbled host is admitted and findable via Lookup like any other, but
// can never qualify as a Home or Elsewhere advert here.
//
// K8 (review's host-filter table, proved against Node 22's WHATWG `URL`)
// closes three divergences from the canonical client, which normalises
// every host through a real WHATWG `URL` before this package's exclusion
// checks ever run:
//
//   - IPv4 numeric forms ("127.1", "0x7f000001", "2130706433", octal
//     parts): WHATWG's host parser recognises a hostname that "ends in a
//     number" and re-parses the WHOLE hostname through its IPv4 parser,
//     so all three example forms arrive as the literal string
//     "127.0.0.1" before canon's own exclusion check runs — hand-ported
//     below as parseWHATWGIPv4/parseWHATWGIPv4Number
//     (url.spec.whatwg.org #ends-in-a-number-checker,
//     #concept-ipv4-parser, #ipv4-number-parser, collapsed into one pass:
//     see parseWHATWGIPv4's own comment for why a separate
//     "ends in a number" pre-check isn't needed here). No Go stdlib
//     function or existing dependency implements this —
//     net.ParseIP rejects every one of these forms.
//   - Ports: "the default port, written with a leading zero" (":0443")
//     must drop exactly like ":443" does — parsed as a number, not
//     string-compared (normalisedPort, below).
//   - IDN hosts: converted to ASCII (punycode) via golang.org/x/net/idna's
//     Lookup profile (already a direct dependency at v0.62.0, so this
//     needs no go.mod/go.sum change) — "the recommended profile for
//     looking up domain names, according to Section 5 of RFC 5891"
//     (idna.go:266-271), non-transitional since Go 1.18 per
//     transitionalLookup's own comment (idna.go:264-266) — UTS #46
//     non-transitional processing, the closest match to WHATWG's own
//     domain-to-ASCII step (both are UTS #46, non-transitional). Matching
//     the real host parser's order (url.spec.whatwg.org
//     #concept-host-parser steps 5 and 8), IDNA conversion runs before
//     the numeric-IPv4 attempt, not after — an already-ASCII numeric
//     label passes through idna.Lookup.ToASCII unchanged (digits and
//     lowercase hex letters are valid LDH characters), so running it
//     unconditionally first never disturbs the three IPv4 forms above.
//
// A hostname that "ends in a number" but fails the full WHATWG IPv4
// parse (too many parts, a part over 255, or the last part too wide —
// e.g. "1.2.3.4.5.6") hard-fails the ENTIRE URL under the real standard;
// this port instead just falls back to treating it as an ordinary
// domain, same as the current behaviour for a bare string of letters.
// That's a deliberate, narrow leniency, not a loophole: every host that
// WOULD parse to a loopback/private form under WHATWG still does here
// (the three table rows above), and a malformed numeric-looking label
// was never going to coincidentally equal "127.0.0.1" or match an
// exclusion suffix either way.
//
// `[::1]` stays excluded here, a deliberate divergence from a canon bug
// (isLocalHostname's own IPv6 check strips any leading `[` or trailing
// `]` from its OWN variable before comparing, host.ts:28-29 — but
// normalizeMessageBoxHost's caller passes it the bracketed
// `url.hostname`, which for `new URL("https://[::1]")` is NOT
// bracket-stripped by WHATWG's URL serializer, so the comparison this
// package's canon actually runs against never fires; see the claims'
// divergence table). Go's own url.URL.Hostname() already strips brackets
// before this function ever sees the hostname, so "::1" matches the
// existing switch case with no extra code either way.
func qualifyAndNormalise(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", false
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Host == "" {
		return "", false
	}
	// The filter is case-insensitive on scheme/hostname only (canon
	// lowercases the whole string before this check — MessageBoxClient.ts
	// :511 — but since the exclusion list only ever tests scheme/
	// hostname, lowercasing just those two is behaviourally identical and
	// lets the comparison below keep the path's original case, per
	// decision 2: "Lowercase the scheme and the host ... and keep the
	// path").
	if strings.ToLower(u.Scheme) != "https" {
		return "", false
	}
	rawHostname := u.Hostname()
	if !utf8.ValidString(rawHostname) {
		// N4: admission no longer refuses an invalid-UTF8 host (matching
		// canon's own non-fatal decode — see topics/messagebox.go's
		// header comment) — so this is the layer that keeps such a host
		// from being usable: it's stored and findable via Lookup, same
		// as canon, but never counted as a qualifying advert here.
		return "", false
	}
	hostname := strings.ToLower(rawHostname)
	isIPv6 := strings.Contains(hostname, ":") // bracket-stripped by Hostname(), so ':' only ever appears in an IPv6 literal
	if !isIPv6 {
		// K8: IDNA first, matching the real host parser's step order —
		// then attempt the numeric-IPv4 re-parse on its (possibly
		// unchanged) ASCII result.
		if ascii, err := idna.Lookup.ToASCII(hostname); err == nil {
			hostname = ascii
		}
		if dotted, ok := parseWHATWGIPv4(hostname); ok {
			hostname = dotted
		}
	}
	switch hostname {
	case "localhost", "127.0.0.1", "0.0.0.0", "::1":
		return "", false
	}
	for _, suffix := range []string{".local", ".example.com", ".test", ".invalid", ".localhost"} {
		if strings.HasSuffix(hostname, suffix) {
			return "", false
		}
	}

	// Drop the default port (443 for https) and a trailing slash; keep
	// the path exactly as given (case preserved — URL paths are
	// conventionally case-sensitive, unlike scheme/host). K8: re-bracket
	// an IPv6 host, so "[a::1]:8443" and "[a::1:8443]" stay distinct
	// instead of colliding once the brackets are gone.
	host := hostname
	if isIPv6 {
		host = "[" + host + "]"
	}
	if port := normalisedPort(u); port != "" {
		host = host + ":" + port
	}
	path := strings.TrimSuffix(u.Path, "/")
	return "https://" + host + path, true
}

// normalisedPort returns u's port, or "" when it's absent or equal to
// the default https port (443) once parsed AS A NUMBER (K8: ":0443" is
// the default port written with a leading zero, and must drop exactly
// like ":443" — a string compare against the literal "443" misses it).
// A port that fails to parse as a number at all (shouldn't happen —
// net/url already validates the port is digits-only) is kept as-is.
func normalisedPort(u *url.URL) string {
	p := u.Port()
	if p == "" {
		return ""
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return p
	}
	if n == 443 {
		return ""
	}
	return p
}

// parseWHATWGIPv4 re-parses host as an IPv4 address exactly the way the
// WHATWG URL Standard's host parser does for a domain that "ends in a
// number" (url.spec.whatwg.org/#concept-ipv4-parser), returning its
// canonical dotted-quad form. ok is false if host has more than four
// dot-separated parts, any part fails parseWHATWGIPv4Number, a non-last
// part exceeds 255, or the last part is too wide for the bits its
// position leaves it (256^(5-numParts) — a single bare part like
// "2130706433" leaves all 4 bytes/32 bits, four explicit parts leave
// just the last 8 bits, and so on).
//
// The real standard first runs a separate "ends in a number" checker
// (url.spec.whatwg.org/#ends-in-a-number-checker) on just the LAST part,
// and only attempts this full parse if that returns true; a plain
// domain label fails that checker before ever reaching here. This port
// collapses the two into one pass: attempting the full parse directly
// and reporting ok=false on any failure reaches an identical place
// (treat host as an ordinary domain) for every input that matters here,
// without a hostname ever being misread as numeric when it isn't — the
// per-part parseWHATWGIPv4Number call is exactly as strict as the
// checker's own "contains only ASCII digits, or itself parses as an
// IPv4 number" test, just run eagerly on every part instead of only the
// last.
func parseWHATWGIPv4(host string) (string, bool) {
	parts := strings.Split(host, ".")
	if len(parts) > 1 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1] // a trailing "." (absolute FQDN notation)
	}
	if len(parts) == 0 || len(parts) > 4 {
		return "", false
	}
	numbers := make([]uint64, len(parts))
	for i, p := range parts {
		n, ok := parseWHATWGIPv4Number(p)
		if !ok {
			return "", false
		}
		numbers[i] = n
	}
	for i := 0; i < len(numbers)-1; i++ {
		if numbers[i] > 255 {
			return "", false
		}
	}
	last := numbers[len(numbers)-1]
	maxLast := uint64(1) << uint(8*(5-len(numbers)))
	if last >= maxLast {
		return "", false
	}
	ipv4 := last
	for i := 0; i < len(numbers)-1; i++ {
		ipv4 += numbers[i] << uint(8*(3-i))
	}
	return fmt.Sprintf("%d.%d.%d.%d", byte(ipv4>>24), byte(ipv4>>16), byte(ipv4>>8), byte(ipv4)), true
}

// parseWHATWGIPv4Number parses one dot-separated part per the WHATWG URL
// Standard's IPv4 number parser (#ipv4-number-parser): a leading "0x" or
// "0X" selects hex, a leading "0" (with more digits following) selects
// octal, otherwise decimal. ok is false if what remains after stripping
// a radix prefix contains a digit invalid for that radix (ASCII hex
// digits for 0-15, exactly as the standard specifies).
func parseWHATWGIPv4Number(part string) (uint64, bool) {
	if part == "" {
		return 0, false
	}
	radix := 10
	switch {
	case len(part) >= 2 && (part[:2] == "0x" || part[:2] == "0X"):
		part, radix = part[2:], 16
	case len(part) >= 2 && part[0] == '0':
		part, radix = part[1:], 8
	}
	if part == "" {
		return 0, true // a bare "0", or "0x"/"0X" with nothing after — the standard returns (0, true), not failure
	}
	n, err := strconv.ParseUint(part, radix, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}
