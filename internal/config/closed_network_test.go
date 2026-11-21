package config

import (
	"os"
	"strings"
	"testing"
)

// Tests for the closed-network settings ([mesh] allowed_peers,
// [overlay] named_peers) and the header-fallback suppression they imply.
// Split out of config_test.go to keep that file under the project's
// line-count cap; TestEnsureHeaderFallbackPeers and
// TestFilterTrustedHeaderPeers (which predate this brick) stay there.

// TestHeaderFallbackPeers_SuppressedByNamedPeers: a closed-network node
// ([overlay] named_peers set) never gets the baked-in default header peer
// appended, even though header_fallback_disabled is false (the self-heal
// isn't "disabled", it just never reaches outside the named peers). An
// operator's own header_fallback_peers still survive unchanged.
func TestHeaderFallbackPeers_SuppressedByNamedPeers(t *testing.T) {
	f, _ := os.CreateTemp("", "anvil-cfg-hfp-named-*.toml")
	f.WriteString("[overlay]\nnamed_peers = [\"https://gateway-a.internal\"]\n")
	f.Close()
	defer os.Remove(f.Name())
	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.BSV.HeaderFallbackPeers) != 0 {
		t.Fatalf("named_peers set should suppress the baked-in header fallback default, got %v", cfg.BSV.HeaderFallbackPeers)
	}

	f2, _ := os.CreateTemp("", "anvil-cfg-hfp-named2-*.toml")
	f2.WriteString("[overlay]\nnamed_peers = [\"https://gateway-a.internal\"]\n[bsv]\nheader_fallback_peers = [\"https://my.trusted.node\"]\n")
	f2.Close()
	defer os.Remove(f2.Name())
	cfg2, err := Load(f2.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !bsvNodesEqual(cfg2.BSV.HeaderFallbackPeers, []string{"https://my.trusted.node"}) {
		t.Fatalf("operator header_fallback_peers should survive named_peers suppression unchanged, got %v", cfg2.BSV.HeaderFallbackPeers)
	}
}

// TestMeshAllowedPeersConfig: [mesh] allowed_peers parses into
// cfg.Mesh.AllowedPeers and is empty by default (the hard constraint: unset
// means today's behaviour). A mutated toml tag or an accidental default
// value would be caught here.
func TestMeshAllowedPeersConfig(t *testing.T) {
	f, _ := os.CreateTemp("", "anvil-cfg-allowedpeers-*.toml")
	f.WriteString("[node]\nname = \"x\"\n")
	f.Close()
	defer os.Remove(f.Name())
	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Mesh.AllowedPeers) != 0 {
		t.Fatalf("allowed_peers should be empty by default, got %v", cfg.Mesh.AllowedPeers)
	}

	f2, _ := os.CreateTemp("", "anvil-cfg-allowedpeers2-*.toml")
	one := "02" + strings.Repeat("a", 64)
	two := "03" + strings.Repeat("b", 64)
	f2.WriteString("[mesh]\nallowed_peers = [\"" + one + "\", \"" + two + "\"]\n")
	f2.Close()
	defer os.Remove(f2.Name())
	cfg2, err := Load(f2.Name())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{one, two}
	if !bsvNodesEqual(cfg2.Mesh.AllowedPeers, want) {
		t.Fatalf("allowed_peers = %v, want %v", cfg2.Mesh.AllowedPeers, want)
	}
}

// TestOverlayNamedPeersConfig: [overlay] named_peers parses into
// cfg.Overlay.NamedPeers and is empty by default (the hard constraint: unset
// means today's behaviour).
func TestOverlayNamedPeersConfig(t *testing.T) {
	f, _ := os.CreateTemp("", "anvil-cfg-namedpeers-*.toml")
	f.WriteString("[node]\nname = \"x\"\n")
	f.Close()
	defer os.Remove(f.Name())
	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Overlay.NamedPeers) != 0 {
		t.Fatalf("named_peers should be empty by default, got %v", cfg.Overlay.NamedPeers)
	}

	f2, _ := os.CreateTemp("", "anvil-cfg-namedpeers2-*.toml")
	f2.WriteString("[overlay]\nnamed_peers = [\"https://gateway-a.internal\", \"https://gateway-b.internal\"]\n")
	f2.Close()
	defer os.Remove(f2.Name())
	cfg2, err := Load(f2.Name())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://gateway-a.internal", "https://gateway-b.internal"}
	if !bsvNodesEqual(cfg2.Overlay.NamedPeers, want) {
		t.Fatalf("named_peers = %v, want %v", cfg2.Overlay.NamedPeers, want)
	}
}

// TestEnsureHeaderFallbackPeers_SuppressDefault unit-tests the named_peers
// closed-network case: the baked-in default is never appended, but the
// operator's own header_fallback_peers still apply unchanged. suppressDefault
// is independent of (and weaker than) disabled: disabled still wins and
// returns nil even when suppressDefault is also true.
func TestEnsureHeaderFallbackPeers_SuppressDefault(t *testing.T) {
	if got := ensureHeaderFallbackPeers(nil, "", false, true); len(got) != 0 {
		t.Fatalf("suppressDefault with no operator peers = %v, want empty (no baked-in default)", got)
	}
	got := ensureHeaderFallbackPeers([]string{"https://my.trusted.node"}, "", false, true)
	if !bsvNodesEqual(got, []string{"https://my.trusted.node"}) {
		t.Fatalf("suppressDefault should keep operator peers unchanged, got %v", got)
	}
	if got := ensureHeaderFallbackPeers([]string{"https://a.example"}, "", true, true); got != nil {
		t.Fatalf("disabled must still win over suppressDefault, got %v", got)
	}
}
