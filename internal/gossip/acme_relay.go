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
	"sync"
	"sync/atomic"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
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

// acmeChallengeEligiblePeer is BroadcastACMEChallenge's own snapshot of
// one peer eligible to receive a replicated entry: the two fields of
// *MeshPeer it needs, copied out while m.mu is held, so the send loop
// below never touches m.peers or needs the lock again.
type acmeChallengeEligiblePeer struct {
	conn *auth.Peer
	id   *ec.PublicKey
}

// BroadcastACMEChallenge sends one ACME challenge cache entry to every
// currently connected, identified, allowed mesh peer, point-to-point —
// never relayed further by a receiver (acmecache.go never forwards what
// it applies).
//
// A peer is eligible only if both hold, checked here directly rather
// than assumed from connection-time admission having already run:
//
//   - its identity is known (IdentityPK != nil). An inbound peer that
//     has completed the transport-level connection but never sent its
//     first application message is already in m.peers — AcceptPeer adds
//     it under a temporary key before any message arrives — but stays
//     unidentified until that reactive re-keying happens (manager.go's
//     AcceptPeer, allowlist.go's establishAndAuthorizePeer). Such a peer
//     must never receive a challenge entry just for having connected.
//   - that identity is in [mesh] allowed_peers (m.allowlist.allows,
//     nil-receiver-safe and vacuously true for everyone when no
//     allowlist is configured at all — the one case left for the
//     caller to gate, by not calling this method in the first place;
//     see acmecache.go's NewCache/Put, which only wires a non-nil send
//     func when its own allowedPeers is non-empty).
//
// The eligible set is copied out of m.peers while m.mu is held, then the
// lock is released before any send: no network I/O ever happens while
// m.mu is held, so a slow or unresponsive peer can never stall an
// unrelated operation that needs the lock. Sends then run concurrently,
// one goroutine per eligible peer, each bounded by the same 5000ms
// per-send timeout as before — so the total time this call can block is
// bounded by that one timeout, not by timeout times peer count.
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
	eligible := make([]acmeChallengeEligiblePeer, 0, len(m.peers))
	for pkHex, peer := range m.peers {
		if peer.Peer == nil || peer.IdentityPK == nil {
			continue
		}
		if !m.allowlist.allows(pkHex) {
			continue
		}
		eligible = append(eligible, acmeChallengeEligiblePeer{conn: peer.Peer, id: peer.IdentityPK})
	}
	m.mu.RUnlock()

	var sent atomic.Int32
	var wg sync.WaitGroup
	wg.Add(len(eligible))
	for _, p := range eligible {
		go func(p acmeChallengeEligiblePeer) {
			defer wg.Done()
			if err := p.conn.ToPeer(context.Background(), payload, p.id, 5000); err == nil {
				sent.Add(1)
			}
		}(p)
	}
	wg.Wait()
	return int(sent.Load())
}
