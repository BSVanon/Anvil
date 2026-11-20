package config

// Decisions 2-5 (B6 messaging-privacy spec): defaults and validation for
// [messaging] forward_copy_ttl, forward_peers, operator_reads_all_boxes
// and home_hosts.
//
// ForwardCopyTTLSeconds and OperatorReadsAllBoxes are pointers for the
// same reason internal/gossip's MessagingPolicy and internal/api's
// Server fields are (decisions 3 and 5): a bare zero value can't tell
// "the operator explicitly chose this" apart from "the key is absent
// from the TOML file" — forward_copy_ttl=0 and operator_reads_all_boxes
// =false are both real, meaningful, different-from-default choices.
// BurntSushi/toml decodes an absent key to a nil pointer and a present
// key (even one explicitly set to its zero value) to a non-nil pointer,
// which is exactly the distinction normalizeMessagingPrivacy needs to
// apply the real default (86400 / true) only when a key was never set.
// ForwardPeers and HomeHosts need no such treatment: an empty list IS
// their correct default ("every connected peer" / "no extra hosts"),
// with no other meaning for a bare zero-length slice to be confused with.

// defaultForwardCopyTTLSeconds is decision 3's "the default is 24 hours."
const defaultForwardCopyTTLSeconds = int64(24 * 60 * 60)

// normalizeMessagingPrivacy applies decisions 2-5's defaults and
// validation to cfg in place. Called once from Load, after cfg's other
// Messaging fields (TTLSeconds etc.) have already been defaulted, since
// forward_copy_ttl's validation depends on the final TTLSeconds value.
func normalizeMessagingPrivacy(cfg *MessagingConfig) {
	if cfg.ForwardCopyTTLSeconds == nil {
		ttl := defaultForwardCopyTTLSeconds
		cfg.ForwardCopyTTLSeconds = &ttl
	}
	// "It must be below ttl_seconds" (decision 3). Clamp rather than
	// fail startup, matching this file's existing clamp-not-error style
	// for every other [messaging] key.
	if *cfg.ForwardCopyTTLSeconds >= cfg.TTLSeconds {
		clamped := cfg.TTLSeconds - 1
		if clamped < 0 {
			clamped = 0
		}
		cfg.ForwardCopyTTLSeconds = &clamped
	}
	if cfg.OperatorReadsAllBoxes == nil {
		allow := true
		cfg.OperatorReadsAllBoxes = &allow
	}
}

// ForwardCopyTTL returns the configured forward_copy_ttl, defaulting to
// defaultForwardCopyTTLSeconds if Load's normalization was bypassed
// (e.g. a MessagingConfig built directly, outside Load — tests only;
// every real node config goes through Load).
func (c MessagingConfig) ForwardCopyTTL() int64 {
	if c.ForwardCopyTTLSeconds == nil {
		return defaultForwardCopyTTLSeconds
	}
	return *c.ForwardCopyTTLSeconds
}

// OperatorReadsAll returns the configured operator_reads_all_boxes,
// defaulting to true if Load's normalization was bypassed.
func (c MessagingConfig) OperatorReadsAll() bool {
	if c.OperatorReadsAllBoxes == nil {
		return true
	}
	return *c.OperatorReadsAllBoxes
}
