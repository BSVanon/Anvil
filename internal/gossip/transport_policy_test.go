package gossip

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"golang.org/x/net/websocket"

	"github.com/BSVanon/Anvil/internal/envelope"
)

func receivingTransport(t *testing.T, receive func(*websocket.Conn) error) (*ServerWSTransport, <-chan error) {
	t.Helper()
	result := make(chan error, 1)
	release := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(websocket.Handler(func(conn *websocket.Conn) {
		result <- receive(conn)
		<-release
	}))
	transport, err := NewWSTransportAdapter(websocketURL(server.URL))
	if err != nil {
		once.Do(func() { close(release) })
		server.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = transport.Close()
		once.Do(func() { close(release) })
		server.Close()
	})
	return transport, result
}

func TestTransportIdleFrameLargerThanHardBoundIsDelivered(t *testing.T) {
	message, encodedSize := largeTransportMessage(t, 1<<20)
	transport, received := receivingTransport(t, func(conn *websocket.Conn) error {
		var raw []byte
		if err := websocket.Message.Receive(conn, &raw); err != nil {
			return err
		}
		if len(raw) != encodedSize {
			return fmt.Errorf("received %d bytes, want %d", len(raw), encodedSize)
		}
		return nil
	})
	transport.writeMu.Lock()
	transport.queueMaxBytes = encodedSize - 1
	transport.writeMu.Unlock()

	if err := transport.Send(context.Background(), message); err != nil {
		t.Fatalf("Send idle oversized frame: %v", err)
	}
	select {
	case err := <-received:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("writer did not deliver idle frame above hard bound")
	}
	if got := transport.CloseReason(); got != "" {
		t.Fatalf("transport closed after deliverable frame: %s", got)
	}
}

func TestTransportOverCapFrameIsRejectedWithoutClosing(t *testing.T) {
	transport, cleanup := stalledTransport(t)
	defer cleanup()
	message, encodedSize := largeTransportMessage(t, 8<<20)
	if encodedSize <= websocket.DefaultMaxPayloadBytes {
		t.Fatalf("test frame is %d bytes, want over %d", encodedSize, websocket.DefaultMaxPayloadBytes)
	}
	if err := transport.Send(context.Background(), message); !errors.Is(err, errFrameTooLarge) {
		t.Fatalf("Send error = %v, want %v", err, errFrameTooLarge)
	}
	transport.writeMu.Lock()
	queuedFrames, queuedBytes := len(transport.writeQueue), transport.queuedBytes
	transport.writeMu.Unlock()
	if queuedFrames != 0 || queuedBytes != 0 {
		t.Fatalf("rejected frame was queued: frames=%d bytes=%d", queuedFrames, queuedBytes)
	}
	if got := transport.CloseReason(); got != "" {
		t.Fatalf("over-cap frame closed transport: %s", got)
	}
}

func TestTransportSlowFrameGetsSizeBasedDeadline(t *testing.T) {
	message, encodedSize := largeTransportMessage(t, 1<<20)
	transport, received := receivingTransport(t, func(conn *websocket.Conn) error {
		buf := make([]byte, 32<<10)
		read := 0
		for read < encodedSize {
			n, err := conn.Read(buf)
			if err != nil {
				return err
			}
			read += n
			time.Sleep(time.Duration(n) * time.Second / (2 << 20))
		}
		return nil
	})
	transport.writeMu.Lock()
	transport.writeTimeout = 100 * time.Millisecond
	transport.minWriteRate = 1 << 20
	transport.writeMu.Unlock()

	if err := transport.Send(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-received:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("slow reader did not receive frame within size-based deadline")
	}
	if got := transport.CloseReason(); got != "" {
		t.Fatalf("slow live link closed: %s", got)
	}
}

func TestBurstySlowPeerDropsDataWithoutDisconnecting(t *testing.T) {
	var receivedMu sync.Mutex
	var received []int
	managerKey, _ := ec.NewPrivateKey()
	manager := managerWithKey(t, managerKey, ManagerConfig{RatePerSec: 10000, RateBurst: 1000})
	defer manager.Stop()
	server := httptest.NewServer(manager.MeshHandler())
	defer server.Close()

	receiverKey, _ := ec.NewPrivateKey()
	receiver := managerWithKey(t, receiverKey, ManagerConfig{
		RatePerSec: 10000,
		RateBurst:  1000,
		OnEnvelope: func(env *envelope.Envelope) {
			sequence, err := strconv.Atoi(env.Payload[len(env.Payload)-4:])
			if err == nil {
				receivedMu.Lock()
				received = append(received, sequence)
				receivedMu.Unlock()
			}
			time.Sleep(10 * time.Millisecond)
		},
	})
	defer receiver.Stop()
	if err := receiver.ConnectPeer(t.Context(), websocketURL(server.URL)); err != nil {
		t.Fatal(err)
	}
	receiverIdentity := fmt.Sprintf("%x", receiverKey.PubKey().Compressed())
	waitForMesh(t, 3*time.Second, func() bool {
		return manager.PeerCount() == 1 && len(manager.Interests()[receiverIdentity]) == 1
	})
	transport := managerTransportFor(t, manager, receiverIdentity)

	publisher, _ := ec.NewPrivateKey()
	const total = 320
	for i := 0; i < total; i++ {
		manager.BroadcastEnvelope(meshBurstEnvelope(t, publisher, i))
	}
	accepted := int(manager.Activity().EnvsSent)
	dropped := int(manager.SendDropped())
	if dropped == 0 {
		t.Fatal("bursty slow peer produced no soft-backlog drops")
	}
	if accepted+dropped != total {
		t.Fatalf("accepted %d + dropped %d = %d, want %d", accepted, dropped, accepted+dropped, total)
	}
	waitForMesh(t, 20*time.Second, func() bool {
		receivedMu.Lock()
		defer receivedMu.Unlock()
		return len(received) == accepted
	})

	receivedMu.Lock()
	delivered := append([]int(nil), received...)
	receivedMu.Unlock()
	for i := 1; i < len(delivered); i++ {
		if delivered[i] <= delivered[i-1] {
			t.Fatalf("accepted frames delivered out of order at %d: %d then %d", i, delivered[i-1], delivered[i])
		}
	}
	if got := transport.CloseReason(); got != "" {
		t.Fatalf("bursty slow peer transport closed: %s", got)
	}
	if got := manager.PeerCount(); got != 1 {
		t.Fatalf("peer count = %d, want 1", got)
	}
}
