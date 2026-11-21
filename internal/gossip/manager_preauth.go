package gossip

import (
	"fmt"
	"net/http"

	"golang.org/x/net/websocket"
)

// This file groups the mesh's pre-authentication defenses with the
// inbound entry point they protect: outboundAllowlistGate (ConnectPeer's
// defense-in-depth allowed_peers check), the maxUnauthenticatedConns
// bound, and MeshHandler, the http.Handler that accepts every inbound
// WebSocket connection and is where that bound is enforced. Split out of
// manager.go to keep it under this project's line-count cap.

// outboundAllowlistGate is ConnectPeer's defense-in-depth [mesh]
// allowed_peers check: called from the ListenForGeneralMessages callback
// there with needsBondCheck already determined, it reports an error when
// pkHex's first message must not proceed to the bond check or
// handleMessage. Returns nil when needsBondCheck is false (this peer's
// first message already passed, or ConnectPeer's primary check in
// establishAndAuthorizePeer owns the decision this time) or when pkHex is
// allowed.
func (m *Manager) outboundAllowlistGate(needsBondCheck bool, pkHex, endpoint string) error {
	if needsBondCheck && !m.checkAllowedPeer(pkHex, "outbound", endpoint) {
		return fmt.Errorf("peer identity not in allowed_peers")
	}
	return nil
}

// maxUnauthenticatedConns bounds how many inbound mesh connections may be
// open at once without having completed BRC-31 authentication and this
// node's own allowed_peers/bond checks. Without it, a flood of
// connections that never authenticate — each holding a goroutine, a
// socket, and up to preAuthMaxFrameBytes of read buffer — could grow
// without limit; a connection that never sends anything, or never
// finishes a handshake, never frees its slot on its own. Authenticated
// peers are not counted here and have no such limit: this bounds the
// pending/unverified set, not total mesh connectivity. 64 is generous
// headroom above any legitimate reconnect burst (a mesh of a few dozen
// peers restarting at once) while still bounding the worst case to a
// small, fixed multiple of one connection's resource cost.
const maxUnauthenticatedConns = 64

// reserveUnauthConn claims one of maxUnauthenticatedConns slots, reporting
// whether it succeeded. A caller that gets false must not proceed with
// the connection it was about to accept. A caller that gets true must
// eventually release the slot — see MeshHandler, which does so the moment
// the connection either authenticates (transport.Authorized()) or closes
// without ever doing so (transport.Done()), whichever comes first.
func (m *Manager) reserveUnauthConn() bool {
	if m.unauthConns.Add(1) > maxUnauthenticatedConns {
		m.unauthConns.Add(-1)
		return false
	}
	return true
}

// MeshHandler returns an http.Handler that accepts inbound WebSocket
// connections for mesh peering. Mount this on the mesh listen address.
//
// The maxUnauthenticatedConns check runs before the WebSocket upgrade
// (wrapping the inner websocket.Handler rather than checking inside it),
// so a connection over the limit is refused with a plain HTTP response —
// no upgrade, no auth.Peer, no transport — instead of paying the upgrade
// cost first and only then dropping it.
func (m *Manager) MeshHandler() http.Handler {
	inner := websocket.Handler(func(conn *websocket.Conn) {
		transport := NewServerWSTransport(conn)
		peerKey, err := m.AcceptPeer(transport)
		if err != nil {
			m.unauthConns.Add(-1)
			m.logger.Warn("inbound peer accept failed", "error", err)
			return
		}

		// Release this connection's unauthenticated-slot reservation the
		// moment it either authenticates or closes without ever doing so,
		// whichever happens first — not only at the end, which would hold
		// the slot for a long-lived authenticated peer's entire connected
		// lifetime and eventually starve new connections of all 64 of
		// them. Then keep blocking until the connection actually closes,
		// as before, to run the existing cleanup.
		select {
		case <-transport.Authorized():
			m.unauthConns.Add(-1)
			<-transport.Done()
		case <-transport.Done():
			m.unauthConns.Add(-1)
		}
		m.removePeerWithReason(peerKey, "transport_closed")
		m.logger.Info("inbound peer disconnected, cleaned up", "key", truncate(peerKey))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.reserveUnauthConn() {
			m.logger.Warn("inbound mesh connection refused: too many unauthenticated connections",
				"limit", maxUnauthenticatedConns)
			http.Error(w, "too many unauthenticated connections", http.StatusServiceUnavailable)
			return
		}
		inner.ServeHTTP(w, r)
	})
}
