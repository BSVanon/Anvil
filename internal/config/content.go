package config

import (
	"fmt"
	"strconv"
	"strings"
)

// ContentConfig configures version tracking for /content: the BRC-159
// token chains this node follows from a set of origins, so that
// /content/<origin>?seq= can serve each origin's versions. A node that sets
// no track_origins and does not run [gateway] tracks nothing, and serves
// /content and POST /broadcast exactly as a node without this section.
type ContentConfig struct {
	// TrackOrigins lists the origin outpoints ("txid_vout" or "txid.vout")
	// this node follows. A gateway also follows the origins its sites file
	// allows. Load normalizes each to "txid_vout" and refuses one that is
	// not an outpoint.
	TrackOrigins []string `toml:"track_origins"`

	// MaxTrackedOrigins caps the tracked set; origins past it are not
	// tracked. 0 or unset: 1000.
	MaxTrackedOrigins int `toml:"max_tracked_origins"`

	// MaxWatchedOutpoints caps the outpoints the spend watch follows at
	// once. 0 or unset: 10000.
	MaxWatchedOutpoints int `toml:"max_watched_outpoints"`

	// SpendPollInterval is how often, in seconds, each watched outpoint is
	// looked up on WhatsOnChain, with ±20% jitter; every lookup shares one
	// limit of 1 request a second. 0 or unset: 600.
	SpendPollInterval int `toml:"spend_poll_interval"`

	// TipPendingTimeout is how long, in seconds, a verified but unmined tip
	// may stay unmined before it, and every link after it, is rolled back.
	// 0 or unset: 86400.
	TipPendingTimeout int `toml:"tip_pending_timeout"`
}

const (
	defaultContentMaxTrackedOrigins   = 1000
	defaultContentMaxWatchedOutpoints = 10000
	defaultContentSpendPollInterval   = 600   // 10m
	defaultContentTipPendingTimeout   = 86400 // 24h
)

// finalizeContent applies [content]'s defaults and checks its origins.
func finalizeContent(c *ContentConfig) error {
	if c.MaxTrackedOrigins <= 0 {
		c.MaxTrackedOrigins = defaultContentMaxTrackedOrigins
	}
	if c.MaxWatchedOutpoints <= 0 {
		c.MaxWatchedOutpoints = defaultContentMaxWatchedOutpoints
	}
	if c.SpendPollInterval <= 0 {
		c.SpendPollInterval = defaultContentSpendPollInterval
	}
	if c.TipPendingTimeout <= 0 {
		c.TipPendingTimeout = defaultContentTipPendingTimeout
	}
	for i, o := range c.TrackOrigins {
		n, ok := normalizeOutpoint(strings.TrimSpace(o))
		if !ok {
			return fmt.Errorf(`invalid [content] track_origins entry %q: want "txid_vout" or "txid.vout"`, o)
		}
		c.TrackOrigins[i] = n
	}
	return nil
}

// normalizeOutpoint returns "txid_vout" with a lowercase txid, from either
// of BRC-159's two string forms.
func normalizeOutpoint(s string) (string, bool) {
	i := strings.LastIndexAny(s, "_.")
	if i != 64 {
		return "", false
	}
	for _, c := range s[:i] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return "", false
		}
	}
	vout, err := strconv.ParseUint(s[i+1:], 10, 32)
	if err != nil {
		return "", false
	}
	return strings.ToLower(s[:i]) + "_" + strconv.FormatUint(vout, 10), true
}
