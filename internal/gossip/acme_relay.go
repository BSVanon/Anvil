package gossip

// MsgACMEChallenge relay: a thin dispatch/send layer for the gateway's
// replicated ACME challenge cache. This file deliberately knows nothing
// about ACME, autocert, or [mesh] allowed_peers — it only
// encodes/decodes the wire payload and moves bytes to/from connected
// peers. Every policy decision (which peers to trust, which domains to
// accept, how long an entry lives) belongs to the caller,
// internal/gateway/acmecache.go, reached through cmd/anvil's gateway
// wiring — see that file's doc comment for the full replication
// contract.

import (
	"context"
	"encoding/json"
	"time"
)

// SetACMEChallengeHook registers the callback invoked for each decoded
// MsgACMEChallenge received from a peer. Unlike SetOnEnvelopeHook, this
// is a plain setter rather than an accumulating wrapper: nothing else in
// this package observes these messages, and cmd/anvil's gateway wiring
// is the only caller, exactly once, when [gateway] is enabled.
func (m *Manager) SetACMEChallengeHook(fn func(senderPKHex, key string, value []byte, expires time.Time)) {
	m.onACMEChallengeHook = fn
}

// onACMEChallenge decodes an incoming MsgACMEChallenge and hands it to
// the registered hook. With no hook set — gateway mode off, or this
// node's own gateway wiring not reached yet — the message is decoded (so a
// malformed payload is still just logged-and-dropped, never a decode
// panic) and then silently discarded, the same "ignore what nothing is
// listening for" outcome an older peer gets from handlers.go's dispatch
// default case for a message type it doesn't know at all.
func (m *Manager) onACMEChallenge(senderPKHex string, raw json.RawMessage) error {
	if m.onACMEChallengeHook == nil {
		return nil
	}
	var payload ACMEChallengePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil
	}
	if payload.Key == "" || payload.Expires <= 0 {
		return nil
	}
	m.onACMEChallengeHook(senderPKHex, payload.Key, payload.Value, time.Unix(payload.Expires, 0))
	return nil
}

// BroadcastACMEChallenge sends one ACME challenge cache entry to every
// currently connected mesh peer, point-to-point — never relayed further
// by a receiver (acmecache.go never forwards what it applies).
//
// No allowed_peers filter runs here: peer admission already enforces
// [mesh] allowed_peers at connection time for both directions
// (checkAllowedPeer, establishAndAuthorizePeer in allowlist.go), so every
// entry in m.peers has already passed it whenever the allowlist is
// active. The caller owns the one case that check can't cover — an
// allowlist that is configured empty, meaning no restriction at all — by
// not calling this method then; see acmecache.go's Put.
//
// Returns how many peers it actually sent to (ToPeer returning no
// error), mirroring ForwardMessage's own return convention.
func (m *Manager) BroadcastACMEChallenge(key string, value []byte, expires time.Time) int {
	payload, err := Encode(MsgACMEChallenge, ACMEChallengePayload{
		Key:     key,
		Value:   value,
		Expires: expires.Unix(),
	})
	if err != nil {
		m.logger.Warn("failed to encode ACME challenge for replication", "error", err)
		return 0
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	sent := 0
	for _, peer := range m.peers {
		if peer.Peer == nil {
			continue
		}
		if err := peer.Peer.ToPeer(context.Background(), payload, peer.IdentityPK, 5000); err == nil {
			sent++
		}
	}
	return sent
}
