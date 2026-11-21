package gossip

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"golang.org/x/net/websocket"
)

// validMarkerFrame returns a JSON AuthMessage small enough to never be
// affected by either frame-size cap, but that actually unmarshals
// successfully -- AuthMessage.UnmarshalJSON (go-sdk auth/types.go)
// requires identityKey to parse as a real public key even for a
// messageType carrying no other meaning, so a trivial payload like "{}"
// always fails to unmarshal and would never reach OnData regardless of
// the frame cap, making it useless as a marker.
func validMarkerFrame(t *testing.T) []byte {
	t.Helper()
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("generate marker key: %v", err)
	}
	return []byte(fmt.Sprintf(`{"identityKey":"%x","messageType":"general"}`, key.PubKey().Compressed()))
}

// serverTransportPair dials an httptest server running a bare
// ServerWSTransport (no auth.Peer, no Manager) and returns the server
// side's transport, the client's raw *websocket.Conn, and a channel that
// receives a value every time the server side successfully decodes a
// frame as JSON and dispatches it through OnData. When preAuthorized is
// true, MarkAuthorized is called on the transport before it is published
// to the test or StartReceive begins -- in the same goroutine and
// strictly before either, so there is no window where StartReceive's
// loop could run its first iteration without yet observing it (calling
// MarkAuthorized from the test goroutine after receiving the transport
// back would race StartReceive's own goroutine for exactly that window).
//
// This package's standard test pattern for a connection pair
// (allowlist_transport_test.go's rawCountingPeer) goes through a real
// auth.Peer, which only ever sends JSON-encoded AuthMessage envelopes at
// handshake-appropriate sizes -- it has no way to put an arbitrarily
// large or arbitrarily timed raw frame on the wire. Testing the
// pre-auth frame cap itself needs exactly that, so this drives
// ServerWSTransport directly.
func serverTransportPair(t *testing.T, preAuthorized bool) (serverTransport *ServerWSTransport, clientConn *websocket.Conn, onData chan struct{}) {
	t.Helper()
	resultCh := make(chan *ServerWSTransport, 1)
	onDataCh := make(chan struct{}, 8)
	handler := websocket.Handler(func(conn *websocket.Conn) {
		st := NewServerWSTransport(conn)
		if preAuthorized {
			st.MarkAuthorized()
		}
		_ = st.OnData(func(context.Context, *auth.AuthMessage) error {
			onDataCh <- struct{}{}
			return nil
		})
		resultCh <- st
		st.StartReceive() // this handler's own goroutine; blocks until the connection ends
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	wsURL := "ws" + ts.URL[len("http"):]

	client, err := websocket.Dial(wsURL, "", "http://localhost")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	select {
	case st := <-resultCh:
		return st, client, onDataCh
	case <-time.After(5 * time.Second):
		t.Fatal("server handler never ran")
		return nil, nil, nil
	}
}

// TestPreAuthFrameCap_OversizedFrameEndsTheConnection proves the pre-auth
// cap itself: a single frame larger than preAuthMaxFrameBytes, sent
// before MarkAuthorized is ever called, ends the connection instead of
// being buffered and delivered. Proven by sending the oversized frame
// immediately followed by a small, well-formed marker frame (validMarkerFrame,
// which does successfully unmarshal and would fire onData if reached): if
// the oversized frame were accepted, StartReceive's loop would still be
// going and would reach the marker; this asserts it never does, and that
// the connection ends instead.
func TestPreAuthFrameCap_OversizedFrameEndsTheConnection(t *testing.T) {
	serverTransport, client, onData := serverTransportPair(t, false)

	oversized := make([]byte, preAuthMaxFrameBytes+1)
	_ = websocket.Message.Send(client, oversized) // a client-side send error is fine; Done() below is what this test asserts on

	_ = websocket.Message.Send(client, validMarkerFrame(t))

	select {
	case <-onData:
		t.Fatal("the marker frame was processed -- the oversized pre-auth frame should have ended the connection before this point")
	case <-serverTransport.Done():
		// expected: StartReceive ended the read loop on the oversized frame
	case <-time.After(5 * time.Second):
		t.Fatal("neither the marker was processed nor did the connection end within 5s")
	}
}

// TestPreAuthFrameCap_SameSizeFrameAcceptedOnceAuthorized is the positive
// control: the exact frame size the test above proves is refused pre-auth
// must be accepted once MarkAuthorized has been called first -- "the
// authenticated frame size stays as it is" (the library default, 32 MiB),
// not permanently capped at preAuthMaxFrameBytes. Proven the same way, in
// reverse: StartReceive must still reach, and dispatch, the marker frame
// sent right after the oversized one.
func TestPreAuthFrameCap_SameSizeFrameAcceptedOnceAuthorized(t *testing.T) {
	serverTransport, client, onData := serverTransportPair(t, true)

	oversized := make([]byte, preAuthMaxFrameBytes+1)
	if err := websocket.Message.Send(client, oversized); err != nil {
		t.Fatalf("client send (within the library default once authorized): %v", err)
	}
	if err := websocket.Message.Send(client, validMarkerFrame(t)); err != nil {
		t.Fatalf("client send (marker): %v", err)
	}

	select {
	case <-onData:
		// expected: both frames were read and the loop reached the marker
	case <-serverTransport.Done():
		t.Fatal("connection ended -- the same-sized frame was rejected even though MarkAuthorized was called first")
	case <-time.After(5 * time.Second):
		t.Fatal("marker frame was never processed within 5s")
	}
}

// TestReserveUnauthConn_BoundsConcurrentUnauthenticatedConnections unit
// tests the counting/limit logic MeshHandler relies on: exactly
// maxUnauthenticatedConns reservations succeed, the next one is refused,
// and releasing one slot (as MeshHandler does on authorize or close)
// frees capacity for exactly one more.
func TestReserveUnauthConn_BoundsConcurrentUnauthenticatedConnections(t *testing.T) {
	walletA, _ := newIdentity(t)
	m := newAllowlistTestManager(t, "unauth-bound", walletA, nil)

	for i := 0; i < maxUnauthenticatedConns; i++ {
		if !m.reserveUnauthConn() {
			t.Fatalf("reserveUnauthConn() refused reservation %d of %d, want all to succeed", i+1, maxUnauthenticatedConns)
		}
	}
	if m.reserveUnauthConn() {
		t.Fatalf("reserveUnauthConn() succeeded past the %d limit, want refusal", maxUnauthenticatedConns)
	}

	m.unauthConns.Add(-1) // simulate MeshHandler releasing one slot
	if !m.reserveUnauthConn() {
		t.Fatal("reserveUnauthConn() refused after a slot was released, want success")
	}
	if m.reserveUnauthConn() {
		t.Fatal("reserveUnauthConn() succeeded past the limit again after only one slot was released")
	}
}

// TestMeshHandler_RefusesOverTheUnauthenticatedConnectionLimit is the
// end-to-end proof for MeshHandler's use of the limit above: with the
// limit already saturated, a real WebSocket upgrade attempt against
// MeshHandler's own http.Handler is refused at the HTTP level (503, no
// upgrade), and once a slot is released, the next attempt succeeds.
func TestMeshHandler_RefusesOverTheUnauthenticatedConnectionLimit(t *testing.T) {
	walletB, _ := newIdentity(t)
	m := newAllowlistTestManager(t, "unauth-bound-e2e", walletB, nil)
	ts := httptest.NewServer(m.MeshHandler())
	defer ts.Close()
	wsURL := "ws" + ts.URL[len("http"):]

	for i := 0; i < maxUnauthenticatedConns; i++ {
		if !m.reserveUnauthConn() {
			t.Fatalf("reserveUnauthConn() refused reservation %d of %d while saturating the limit", i+1, maxUnauthenticatedConns)
		}
	}

	if _, err := websocket.Dial(wsURL, "", "http://localhost"); err == nil {
		t.Fatal("websocket.Dial succeeded against a saturated MeshHandler, want the upgrade refused")
	}

	m.unauthConns.Add(-1) // release one slot, as MeshHandler does on authorize or close

	// Only the upgrade needs to succeed here; the handshake itself (and
	// MarkAuthorized's effect on it) is exercised elsewhere
	// (allowlist_test.go, preauth cap tests above).
	conn, err := websocket.Dial(wsURL, "", "http://localhost")
	if err != nil {
		t.Fatalf("websocket.Dial failed after a slot was released, want it to succeed: %v", err)
	}
	_ = conn.Close()
}
