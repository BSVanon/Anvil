package config

import "testing"

func TestDefaultHeaderFallbackPeers_MatchesTheInternalList(t *testing.T) {
	got := DefaultHeaderFallbackPeers()
	if len(got) != len(defaultHeaderFallbackPeers) {
		t.Fatalf("got %d peers, want %d", len(got), len(defaultHeaderFallbackPeers))
	}
	for i := range got {
		if got[i] != defaultHeaderFallbackPeers[i] {
			t.Errorf("peer %d = %q, want %q", i, got[i], defaultHeaderFallbackPeers[i])
		}
	}

	// The returned slice must be a copy: mutating it must not reach back
	// into the package's own canonical list.
	if len(got) > 0 {
		got[0] = "mutated"
		if defaultHeaderFallbackPeers[0] == "mutated" {
			t.Error("DefaultHeaderFallbackPeers returned the live slice, not a copy")
		}
	}
}

func TestIsDefaultHeaderFallbackPeer(t *testing.T) {
	for _, p := range defaultHeaderFallbackPeers {
		if !IsDefaultHeaderFallbackPeer(p) {
			t.Errorf("IsDefaultHeaderFallbackPeer(%q) = false, want true", p)
		}
	}
	if IsDefaultHeaderFallbackPeer("https://not-a-default.example") {
		t.Error("IsDefaultHeaderFallbackPeer(a non-default) = true, want false")
	}
}
