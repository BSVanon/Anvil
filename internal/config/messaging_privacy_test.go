package config

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

// testCompressedKey1/2 are syntactically valid (shape-only) compressed
// secp256k1 public keys in hex for forward_peers fixtures — not real
// curve points, matching isCompressedPubKeyHex's own shape-only check
// (66 hex characters, a "02" or "03" prefix; it mirrors
// internal/gossip's isCompressedKeyHex exactly, which is equally
// shape-only). Deliberately mixed case, so the round-trip test below
// also confirms Load does not normalise case.
const (
	testCompressedKey1 = "02AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testCompressedKey2 = "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// TestMessagingPrivacyDefaultsAndOverrides covers decisions 2-5's four
// new [messaging] keys directly: default-when-absent (at the *default*
// ttl_seconds, where forward_copy_ttl's own default does NOT need
// clamping — the clamp-at-small-ttl_seconds case is
// TestMessagingPrivacy_ClampAgainstSmallTTLSeconds below), explicit
// overrides including the meaningful zero/false values, the
// forward_copy_ttl>=ttl_seconds clamp on an EXPLICIT (not defaulted)
// value, and forward_peers/home_hosts TOML list round-tripping verbatim
// (case-folding/normalisation happens downstream in
// gossip.NewForwardPeerFilter and messaging.HomeResolver, not at config
// load). Moved out of config_test.go (F7 — that file was over the
// 600-line cap).
func TestMessagingPrivacyDefaultsAndOverrides(t *testing.T) {
	// Absent [messaging] section entirely: every default applies,
	// including forward_copy_ttl's default 24h against the default
	// ttl_seconds=604800 (no clamp triggered).
	f, _ := os.CreateTemp("", "anvil-cfg-msgpriv-absent-*.toml")
	f.WriteString("[node]\nname = \"test\"\n")
	f.Close()
	defer os.Remove(f.Name())
	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if got := *cfg.Messaging.ForwardCopyTTLSeconds; got != defaultForwardCopyTTLSeconds {
		t.Fatalf("forward_copy_ttl default = %d, want %d", got, defaultForwardCopyTTLSeconds)
	}
	if !*cfg.Messaging.OperatorReadsAllBoxes {
		t.Fatal("operator_reads_all_boxes default = false, want true")
	}
	if len(cfg.Messaging.ForwardPeers) != 0 || len(cfg.Messaging.HomeHosts) != 0 {
		t.Fatalf("forward_peers/home_hosts should default empty: %+v / %+v", cfg.Messaging.ForwardPeers, cfg.Messaging.HomeHosts)
	}

	// Explicit forward_copy_ttl=0 ("never store but still relay" per
	// decision 3) must be preserved, not treated as absent-and-defaulted.
	f2, _ := os.CreateTemp("", "anvil-cfg-msgpriv-zero-*.toml")
	f2.WriteString("[messaging]\nforward_copy_ttl = 0\noperator_reads_all_boxes = false\n")
	f2.Close()
	defer os.Remove(f2.Name())
	cfg, err = Load(f2.Name())
	if err != nil {
		t.Fatal(err)
	}
	if got := *cfg.Messaging.ForwardCopyTTLSeconds; got != 0 {
		t.Fatalf("explicit forward_copy_ttl=0 = %d, want 0", got)
	}
	if *cfg.Messaging.OperatorReadsAllBoxes {
		t.Fatal("explicit operator_reads_all_boxes=false was not preserved")
	}

	// Explicit forward_copy_ttl >= ttl_seconds (not the defaulted value)
	// is clamped to ttl_seconds-1, per decision 3's "must be below
	// ttl_seconds".
	f3, _ := os.CreateTemp("", "anvil-cfg-msgpriv-clamp-*.toml")
	f3.WriteString("[messaging]\nttl_seconds = 50\nforward_copy_ttl = 100\n")
	f3.Close()
	defer os.Remove(f3.Name())
	cfg, err = Load(f3.Name())
	if err != nil {
		t.Fatal(err)
	}
	if got := *cfg.Messaging.ForwardCopyTTLSeconds; got != 49 {
		t.Fatalf("explicit forward_copy_ttl=100 with ttl_seconds=50 clamped to %d, want 49", got)
	}

	// forward_peers / home_hosts round-trip verbatim from TOML.
	f4, _ := os.CreateTemp("", "anvil-cfg-msgpriv-lists-*.toml")
	f4.WriteString("[messaging]\nforward_peers = [\"" + testCompressedKey1 + "\", \"" + testCompressedKey2 + "\"]\n" +
		"home_hosts = [\"https://Example.ORG\", \"https://foo.test\"]\n")
	f4.Close()
	defer os.Remove(f4.Name())
	cfg, err = Load(f4.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Messaging.ForwardPeers) != 2 || cfg.Messaging.ForwardPeers[0] != testCompressedKey1 || cfg.Messaging.ForwardPeers[1] != testCompressedKey2 {
		t.Fatalf("forward_peers did not round-trip verbatim: %+v", cfg.Messaging.ForwardPeers)
	}
	if len(cfg.Messaging.HomeHosts) != 2 || cfg.Messaging.HomeHosts[0] != "https://Example.ORG" || cfg.Messaging.HomeHosts[1] != "https://foo.test" {
		t.Fatalf("home_hosts did not round-trip verbatim: %+v", cfg.Messaging.HomeHosts)
	}
}

// TestMessagingPrivacy_ClampAgainstSmallTTLSeconds is the interaction
// case moved out of TestMessagingDefaultsAndOverrides in config_test.go
// (F7): forward_copy_ttl's DEFAULT (24h) clamps below an explicitly
// overridden, small ttl_seconds, exactly as an explicit forward_copy_ttl
// value would.
func TestMessagingPrivacy_ClampAgainstSmallTTLSeconds(t *testing.T) {
	f, _ := os.CreateTemp("", "anvil-cfg-msgpriv-smallttl-*.toml")
	f.WriteString("[messaging]\nttl_seconds = 60\n")
	f.Close()
	defer os.Remove(f.Name())
	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if got := *cfg.Messaging.ForwardCopyTTLSeconds; got != 59 {
		t.Fatalf("forward_copy_ttl default+clamp against ttl_seconds=60 = %d, want 59", got)
	}
	if !*cfg.Messaging.OperatorReadsAllBoxes {
		t.Fatal("operator_reads_all_boxes default = false, want true")
	}
	if len(cfg.Messaging.ForwardPeers) != 0 || len(cfg.Messaging.HomeHosts) != 0 {
		t.Fatalf("forward_peers/home_hosts should default empty: %+v / %+v", cfg.Messaging.ForwardPeers, cfg.Messaging.HomeHosts)
	}
}

// TestMessagingPrivacy_NegativeForwardCopyTTLIsConfigError (N5): a
// negative forward_copy_ttl used to be silently accepted and then
// behave like 0 downstream (every store-gate is `ttl > 0`), with no
// indication why. Load now refuses it outright.
func TestMessagingPrivacy_NegativeForwardCopyTTLIsConfigError(t *testing.T) {
	f, _ := os.CreateTemp("", "anvil-cfg-msgpriv-negative-*.toml")
	f.WriteString("[messaging]\nforward_copy_ttl = -1\n")
	f.Close()
	defer os.Remove(f.Name())
	if _, err := Load(f.Name()); err == nil {
		t.Fatal("expected an error for a negative forward_copy_ttl")
	}
}

// TestMessagingPrivacy_ClampLogsAWarning (N5): the forward_copy_ttl>=
// ttl_seconds clamp now logs a warning line when it actually fires,
// instead of silently reinterpreting the operator's intent (the
// previously-unannounced path to an accidental relay-only node).
func TestMessagingPrivacy_ClampLogsAWarning(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	f, _ := os.CreateTemp("", "anvil-cfg-msgpriv-clamplog-*.toml")
	f.WriteString("[messaging]\nttl_seconds = 50\nforward_copy_ttl = 100\n")
	f.Close()
	defer os.Remove(f.Name())
	if _, err := Load(f.Name()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "forward_copy_ttl") {
		t.Fatalf("expected a warning line naming forward_copy_ttl when the clamp fires, got log output: %q", buf.String())
	}
}

// TestMessagingPrivacy_InvalidForwardPeerIsConfigError (K5): an entry
// that isn't a valid compressed public key in hex refuses the whole
// config at load with a clear message, rather than silently never
// matching any real peer (a quietly-useless allow-list).
func TestMessagingPrivacy_InvalidForwardPeerIsConfigError(t *testing.T) {
	f, _ := os.CreateTemp("", "anvil-cfg-msgpriv-badpeer-*.toml")
	f.WriteString("[messaging]\nforward_peers = [\"not-a-key\"]\n")
	f.Close()
	defer os.Remove(f.Name())
	_, err := Load(f.Name())
	if err == nil {
		t.Fatal("expected an error for an invalid forward_peers entry")
	}
	if !strings.Contains(err.Error(), "forward_peers") {
		t.Fatalf("expected the error to name forward_peers, got: %v", err)
	}
}
