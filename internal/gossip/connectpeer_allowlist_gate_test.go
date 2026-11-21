package gossip

import (
	"strings"
	"testing"
)

// TestConnectPeer_OutboundAllowlistGate exercises outboundAllowlistGate --
// ConnectPeer's defense-in-depth [mesh] allowed_peers check -- directly,
// in the one state it exists to guard: a peers-map entry already keyed by
// the remote's identity hex (as establishAndAuthorizePeer's own re-key
// would leave it) but with establishAndAuthorizePeer's own checkAllowedPeer
// call not yet having run.
//
// The production race this defends against is go-sdk's
// ListenForGeneralMessages callback firing for a peer's first message
// before establishAndAuthorizePeer (ConnectPeer's primary check) returns --
// go-sdk documents no ordering guarantee either way. That race has no
// deterministic reproduction available outside go-sdk's internals: the
// registered callback is stored in an unexported map
// (onGeneralMessageReceivedCallbacks) with no exported way to invoke or
// race it from a test, and the window between establishAndAuthorizePeer's
// re-key and its own checkAllowedPeer call is a few consecutive statements
// with no I/O in between, so it cannot be reliably forced over a real
// connection either. This test calls the gate the same way the callback
// does instead, proving the check's own logic is correct independent of
// when it runs.
func TestConnectPeer_OutboundAllowlistGate(t *testing.T) {
	walletA, _ := newIdentity(t)
	_, strangerPkHex := newIdentity(t) // not on A's allowlist
	_, listedPkHex := newIdentity(t)   // on A's allowlist

	m := newAllowlistTestManager(t, "gate-a", walletA, []string{listedPkHex})

	// Simulate the state establishAndAuthorizePeer's re-key leaves before
	// its own checkAllowedPeer call runs: an entry keyed by identity hex,
	// not yet bond-checked.
	m.mu.Lock()
	m.peers[strangerPkHex] = &MeshPeer{Endpoint: "ws://peer.invalid", Direction: "outbound"}
	m.peers[listedPkHex] = &MeshPeer{Endpoint: "ws://peer.invalid", Direction: "outbound"}
	m.mu.Unlock()

	if err := m.outboundAllowlistGate(true, strangerPkHex, "ws://peer.invalid"); err == nil {
		t.Fatal("outboundAllowlistGate(needsBondCheck=true, unlisted identity): got nil error, want a refusal")
	} else if !strings.Contains(err.Error(), "not in allowed_peers") {
		t.Fatalf("outboundAllowlistGate error = %q, want it to mention allowed_peers", err.Error())
	}
	if _, stillPresent := m.peers[strangerPkHex]; stillPresent {
		t.Error("refused identity must be removed from m.peers by checkAllowedPeer, but it is still present")
	}

	if err := m.outboundAllowlistGate(true, listedPkHex, "ws://peer.invalid"); err != nil {
		t.Fatalf("outboundAllowlistGate(needsBondCheck=true, listed identity): got error %v, want nil", err)
	}
	if _, stillPresent := m.peers[listedPkHex]; !stillPresent {
		t.Error("allowed identity must not be removed from m.peers")
	}

	// needsBondCheck=false must always pass through with no decision made,
	// regardless of allowlist membership -- this is the case for every
	// message after a peer's first, where establishAndAuthorizePeer (or an
	// earlier call to this same gate) has already decided.
	if err := m.outboundAllowlistGate(false, strangerPkHex, "ws://peer.invalid"); err != nil {
		t.Fatalf("outboundAllowlistGate(needsBondCheck=false): got error %v, want nil", err)
	}
}
