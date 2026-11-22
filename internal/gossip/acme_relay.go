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
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// acmeChallengeMaxPayloadBytes bounds the wire-encoded MsgACMEChallenge
// payload (the Message.Data bytes handed to onACMEChallenge, below —
// ACMEChallengePayload's own JSON: key, base64 value, expires) this
// node will even attempt to json.Unmarshal. Sized from the largest
// entry this message type ever legitimately carries: a tls-alpn-01
// token certificate with its private key — autocert's own cache value
// for a "+token" key (golang.org/x/crypto/acme/autocert@v0.59.0's
// cachePut, autocert.go:517-549): PEM(private key) + PEM(one
// self-signed certificate, never a chain).
//
// TLSALPN01ChallengeCert (acme/acme.go:611) always generates a fresh
// ECDSA P-256 key unless a WithKey option is passed — which nothing in
// this codebase's ACME client call does — so every entry this node
// actually produces measures (measured directly, a self-signed cert
// built the same way): ~797 raw PEM bytes, ~1131 bytes once wrapped in
// this message's own JSON. An RSA-2048 key — not produced by this exact
// code path today, measured anyway as a margin against a future
// change — comes to ~2782 raw / ~3779 wire bytes. 16 KiB is a little
// over 4x that RSA figure: comfortably clear of any entry this protocol
// can legitimately produce, while still refusing — for the cost of a
// length check, before spending anything on parsing it — a payload
// many times too large to be one.
const acmeChallengeMaxPayloadBytes = 16 * 1024

// acmeOversizeDropped counts how many MsgACMEChallenge payloads
// onACMEChallenge has refused for being over
// acmeChallengeMaxPayloadBytes, before json.Unmarshal ever runs on
// them. A package-level counter rather than a new Manager field —
// manager.go is at its line budget, and this file's existing practice
// (see BroadcastACMEChallenge's own doc comment) is to keep this one
// message type's state local to itself. Tests read the delta this
// causes across a single call, the same way any counter is read from
// outside across one unit of work, so sharing it across every *Manager
// in a test binary carries no cross-test pollution risk.
var acmeOversizeDropped atomic.Int64

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
// node's own gateway wiring not reached yet — the message is dropped
// before any decode even runs, the same "ignore what nothing is
// listening for" outcome an older peer gets from handlers.go's dispatch
// default case for a message type it doesn't know at all.
//
// Two guards run before any of that decoding: a size check against
// acmeChallengeMaxPayloadBytes, refusing anything over it for the cost
// of a length comparison rather than a json.Unmarshal; and the same
// per-peer rate limit onData already applies to incoming gossip
// envelopes (allowPeerMessage, manager_seed.go) — a shared bucket
// rather than a second one just for this message type, so a peer can't
// get a free extra allowance by sending challenge entries instead of
// envelopes.
func (m *Manager) onACMEChallenge(senderPKHex string, raw json.RawMessage) error {
	if m.onACMEChallengeHook == nil {
		return nil
	}
	if len(raw) > acmeChallengeMaxPayloadBytes {
		acmeOversizeDropped.Add(1)
		return nil
	}
	if !m.allowPeerMessage(senderPKHex) {
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
// A peer is eligible only if all hold, checked here directly rather
// than assumed from connection-time admission having already run:
//
//   - application admission completed for this exact socket;
//   - its identity is known (IdentityPK != nil). An inbound peer that
//     has completed the transport-level connection but never sent its
//     first application message is already in m.peers — AcceptPeer adds
//     it under a temporary key before any message arrives — but stays
//     unidentified until that reactive re-keying happens (manager.go's
//     AcceptPeer, allowlist.go's establishAndAuthorizePeer). Such a peer
//     must never receive a challenge entry just for having connected.
//   - that identity's own hex — fmt.Sprintf("%x", peer.IdentityPK.Compressed()),
//     computed here directly rather than reused from the m.peers map
//     key the range loop below iterates over — is in [mesh]
//     allowed_peers (m.allowlist.allows, nil-receiver-safe and
//     vacuously true for everyone when no allowlist is configured at
//     all — the one case left for the caller to gate, by not calling
//     this method in the first place; see acmecache.go's NewCache/Put,
//     which only wires a non-nil send func when its own allowedPeers is
//     non-empty). The map key equals this same hex by construction
//     (AcceptPeer's reactive re-key, establishAndAuthorizePeer's
//     proactive one — manager.go, allowlist.go — both set it that way),
//     but checking the identity itself, independently, means this
//     method's own safety never depends on that construction holding.
//   - it is the primary map entry for that identity, so a compatibility
//     socket retained during a rolling upgrade does not receive duplicates.
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
	for identity, peer := range m.peers {
		if !admittedPrimaryLocked(identity, peer) {
			continue
		}
		identityHex := fmt.Sprintf("%x", peer.IdentityPK.Compressed())
		if !m.allowlist.allows(identityHex) {
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
