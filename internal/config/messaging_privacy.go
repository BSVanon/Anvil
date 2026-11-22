package config

// Defaults and validation for [messaging] forward_copy_ttl,
// forward_peers, operator_reads_all_boxes and home_hosts.
//
// ForwardCopyTTLSeconds and OperatorReadsAllBoxes are pointers for the
// same reason internal/gossip's MessagingPolicy and internal/api's
// Server fields are: a bare zero value can't tell
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

import (
	"encoding/hex"
	"fmt"
	"log"
)

type MessagingConfig struct {
	TTLSeconds       int64 `toml:"ttl_seconds"`
	MaxPairMessages  int64 `toml:"max_pair_messages"`
	MaxPairBytes     int64 `toml:"max_pair_bytes"`
	MaxStoreMessages int64 `toml:"max_store_messages"`
	MaxStoreBytes    int64 `toml:"max_store_bytes"`
	MaxInboxMessages int64 `toml:"max_inbox_messages"`
	MaxInboxBytes    int64 `toml:"max_inbox_bytes"`
	// Defaults/validation for the fields below are in this file.
	ForwardCopyTTLSeconds *int64   `toml:"forward_copy_ttl"`
	ForwardPeers          []string `toml:"forward_peers"`
	OperatorReadsAllBoxes *bool    `toml:"operator_reads_all_boxes"`
	HomeHosts             []string `toml:"home_hosts"`
	PrivateHomes          bool     `toml:"private_homes"`
	PrivateHomeMaxMembers int      `toml:"private_home_max_members"`
	PrivateHomeMaxTTL     int64    `toml:"private_home_max_ttl"`
}

func defaultMessagingConfig() MessagingConfig {
	return MessagingConfig{
		TTLSeconds:            604800,
		MaxPairMessages:       1000,
		MaxPairBytes:          64 << 20,
		MaxStoreMessages:      1000000,
		MaxStoreBytes:         2 << 30,
		PrivateHomeMaxMembers: 10000,
		PrivateHomeMaxTTL:     2592000,
	}
}

func validatePrivateHomeNetwork(cfg *MessagingConfig, mesh *MeshConfig) error {
	if cfg.PrivateHomes && len(mesh.AllowedPeers) == 0 {
		return fmt.Errorf("messaging.private_homes requires non-empty mesh.allowed_peers")
	}
	return nil
}

// defaultForwardCopyTTLSeconds is the forward_copy_ttl default: 24 hours.
const defaultForwardCopyTTLSeconds = int64(24 * 60 * 60)

// normalizeMessagingPrivacy applies the [messaging] section's defaults
// and validation to cfg in place. Called once from Load, after cfg's
// other Messaging fields (TTLSeconds etc.) have already been defaulted,
// since forward_copy_ttl's validation depends on the final TTLSeconds
// value.
//
// Returns an error for a value Load should refuse to start on,
// rather than silently reinterpreting the operator's intent the way
// this file's other clamps do:
//   - a negative forward_copy_ttl used to be accepted and then behave
//     like 0 downstream (the store-gate everywhere else is `ttl > 0`)
//     with no indication why;
//   - a forward_peers entry that isn't a valid compressed public key in
//     hex would otherwise silently never match any real peer,
//     making the allow-list quietly useless instead of visibly wrong.
//
// The ttl_seconds clamp below stays a clamp, not an error (matching
// every other [messaging] key's style), but now logs when it actually
// fires — previously a small ttl_seconds override could turn a
// node relay-only with no line in the log saying so.
func normalizeMessagingPrivacy(cfg *MessagingConfig) error {
	if cfg.PrivateHomeMaxMembers < 1 || cfg.PrivateHomeMaxMembers > 1_000_000 {
		return fmt.Errorf("messaging.private_home_max_members must be in 1..1000000, got %d", cfg.PrivateHomeMaxMembers)
	}
	if cfg.PrivateHomeMaxTTL < 3600 || cfg.PrivateHomeMaxTTL > 7_776_000 {
		return fmt.Errorf("messaging.private_home_max_ttl must be in 3600..7776000, got %d", cfg.PrivateHomeMaxTTL)
	}
	if cfg.ForwardCopyTTLSeconds == nil {
		ttl := defaultForwardCopyTTLSeconds
		cfg.ForwardCopyTTLSeconds = &ttl
	} else if *cfg.ForwardCopyTTLSeconds < 0 {
		return fmt.Errorf("messaging.forward_copy_ttl must not be negative, got %d", *cfg.ForwardCopyTTLSeconds)
	}
	// forward_copy_ttl must be below ttl_seconds.
	if *cfg.ForwardCopyTTLSeconds >= cfg.TTLSeconds {
		clamped := cfg.TTLSeconds - 1
		if clamped < 0 {
			clamped = 0
		}
		log.Printf("config: messaging.forward_copy_ttl (%d) must be below ttl_seconds (%d); clamped to %d",
			*cfg.ForwardCopyTTLSeconds, cfg.TTLSeconds, clamped)
		cfg.ForwardCopyTTLSeconds = &clamped
	}
	if cfg.OperatorReadsAllBoxes == nil {
		allow := true
		cfg.OperatorReadsAllBoxes = &allow
	}
	for _, peer := range cfg.ForwardPeers {
		if !isCompressedPubKeyHex(peer) {
			return fmt.Errorf("messaging.forward_peers: %q is not a valid compressed public key in hex", peer)
		}
	}
	return nil
}

// isCompressedPubKeyHex reports whether value has the shape of a
// compressed secp256k1 public key in hex: 66 characters, a "02" or "03"
// prefix, valid hex throughout. Mirrors internal/gossip's
// isCompressedKeyHex (handlers_msg.go) exactly; duplicated rather than
// imported, since internal/config has no dependency on internal/gossip
// and this is a six-line shape check, not shared logic worth a new seam
// for.
func isCompressedPubKeyHex(value string) bool {
	if len(value) != 66 || value[0] != '0' || (value[1] != '2' && value[1] != '3') {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
