package gossip

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/bond"
	"github.com/bsv-blockchain/go-sdk/auth"
	"golang.org/x/net/websocket"
)

func TestOutboundBondRejectionSendsNothingAndKeepsFrameCap(t *testing.T) {
	bondAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":[]}`))
	}))
	defer bondAPI.Close()

	tests := []struct {
		name string
		opts connectPeerOptions
	}{
		{name: "configured seed", opts: connectPeerOptions{seed: true}},
		{name: "learned exchange peer", opts: connectPeerOptions{exchange: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			localWallet, _ := newIdentity(t)
			remoteWallet, _ := newIdentity(t)
			remoteCh := make(chan *rawCountingPeer, 1)
			handler := websocket.Handler(func(conn *websocket.Conn) {
				transport := NewServerWSTransport(conn)
				remoteCh <- newRawCountingPeerOn(t, transport, auth.PeerOptions{
					Wallet: remoteWallet, Transport: transport,
				})
				<-transport.Done()
			})
			server := httptest.NewServer(handler)
			defer server.Close()

			mgr := NewManager(ManagerConfig{
				Wallet: localWallet, BondChecker: bond.NewChecker(1, bondAPI.URL),
				LocalInterests: []string{""},
			})
			defer mgr.Stop()
			test.opts.dialTimeout = time.Second
			_, transport, _, err := mgr.connectPeer(t.Context(), websocketURL(server.URL), test.opts)
			if !errors.Is(err, errBondRejected) {
				t.Fatalf("connect error = %v, want errBondRejected", err)
			}
			if transport == nil {
				t.Fatal("connect did not return its transport")
			}
			select {
			case <-transport.Authorized():
				t.Fatal("bond-rejected transport was marked authorized")
			default:
			}

			var remote *rawCountingPeer
			select {
			case remote = <-remoteCh:
			case <-time.After(5 * time.Second):
				t.Fatal("remote peer was not started")
			}
			time.Sleep(200 * time.Millisecond)
			if got := remote.received.Load(); got != 0 {
				t.Fatalf("bond-rejected peer received %d application messages, want 0", got)
			}
			if mgr.PeerCount() != 0 {
				t.Fatalf("bond-rejected peer remains in map: count=%d", mgr.PeerCount())
			}
		})
	}
}
