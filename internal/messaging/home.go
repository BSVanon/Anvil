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
	"net/url"
	"strings"
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
	for _, a := range adverts {
		nh, ok := qualifyAndNormalise(a.Host)
		if !ok {
			// Only adverts that pass the canonical client's host filter
			// count (decision 2, "Which adverts count").
			continue
		}
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
// (MessageBoxClient.ts:507-531 — https only, and none of localhost,
// 127.0.0.1, 0.0.0.0, ::1, *.local, *.example.com, *.test, *.invalid, or
// *.localhost) and, if it passes, returns the normalised form: lowercase
// scheme and host, default port dropped, trailing slash dropped, path
// kept. Returns ("", false) for a host that fails the filter or doesn't
// parse as a URL.
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
	hostname := strings.ToLower(u.Hostname())
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
	// conventionally case-sensitive, unlike scheme/host).
	host := hostname
	if port := u.Port(); port != "" && port != "443" {
		host = host + ":" + port
	}
	path := strings.TrimSuffix(u.Path, "/")
	return "https://" + host + path, true
}
