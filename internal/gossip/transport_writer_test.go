package gossip

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"golang.org/x/net/websocket"
)

func largeTransportMessage(t *testing.T, size int) (*auth.AuthMessage, int) {
	t.Helper()
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	message := &auth.AuthMessage{IdentityKey: key.PubKey()}
	payload := reflect.ValueOf(message).Elem().FieldByName("Payload")
	if !payload.IsValid() || !payload.CanSet() || payload.Kind() != reflect.Slice || payload.Type().Elem().Kind() != reflect.Uint8 {
		t.Fatal("auth.AuthMessage.Payload is not a settable byte slice")
	}
	payload.SetBytes(bytes.Repeat([]byte{'x'}, size))
	encoded, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) < size {
		t.Fatalf("large auth message encoded to only %d bytes", len(encoded))
	}
	return message, len(encoded)
}

func stalledTransport(t *testing.T) (*ServerWSTransport, func()) {
	t.Helper()
	release := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(websocket.Handler(func(*websocket.Conn) {
		<-release
	}))
	config, err := websocket.NewConfig(websocketURL(server.URL), "http://localhost")
	if err != nil {
		once.Do(func() { close(release) })
		server.Close()
		t.Fatal(err)
	}
	rawConn, err := net.DialTimeout("tcp", config.Location.Host, time.Second)
	if err == nil {
		if tcpConn, ok := rawConn.(*net.TCPConn); ok {
			err = tcpConn.SetWriteBuffer(16 << 10)
		}
	}
	if err != nil {
		if rawConn != nil {
			_ = rawConn.Close()
		}
		once.Do(func() { close(release) })
		server.Close()
		t.Fatal(err)
	}
	conn, err := websocket.NewClient(config, rawConn)
	if err != nil {
		_ = rawConn.Close()
		once.Do(func() { close(release) })
		server.Close()
		t.Fatal(err)
	}
	transport := NewServerWSTransport(conn)
	cleanup := func() {
		_ = transport.Close()
		once.Do(func() { close(release) })
		server.Close()
	}
	return transport, cleanup
}

func waitForTransportWrite(t *testing.T, transport *ServerWSTransport) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		transport.writeMu.Lock()
		queued := transport.queuedBytes > 0
		transport.writeMu.Unlock()
		if queued {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("transport writer did not start")
		case <-ticker.C:
		}
	}
}

func TestTransportSendReturnsWhileRemoteDoesNotRead(t *testing.T) {
	transport, cleanup := stalledTransport(t)
	defer cleanup()
	message, _ := largeTransportMessage(t, 128<<10)
	returned := make(chan error, 1)
	go func() { returned <- transport.Send(context.Background(), message) }()
	select {
	case err := <-returned:
		if err != nil {
			t.Fatalf("Send: %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Send blocked on a non-reading remote")
	}
}

func TestNilTransportStartsNoWriterAndRejectsSend(t *testing.T) {
	transport := NewServerWSTransport(nil)
	select {
	case <-transport.writerDone:
	default:
		t.Fatal("nil transport started a writer")
	}
	if err := transport.Send(context.Background(), &auth.AuthMessage{}); err == nil {
		t.Fatal("nil transport accepted Send")
	}
	if err := transport.Close(); err != nil {
		t.Fatalf("Close nil transport: %v", err)
	}
}

func TestTransportQueueOverflowClosesWithReason(t *testing.T) {
	transport, cleanup := stalledTransport(t)
	defer cleanup()
	message, encodedSize := largeTransportMessage(t, 128<<10)
	transport.writeMu.Lock()
	transport.queueMaxBytes = encodedSize - 1
	transport.writeTimeout = 30 * time.Second
	transport.writeMu.Unlock()
	if err := transport.Send(context.Background(), message); err != nil {
		t.Fatalf("first Send: %v", err)
	}
	waitForTransportWrite(t, transport)
	time.Sleep(20 * time.Millisecond)
	overflowMessage, _ := largeTransportMessage(t, 1<<10)
	started := time.Now()
	if err := transport.Send(context.Background(), overflowMessage); !errors.Is(err, errSendQueueFull) {
		t.Fatalf("overflowing Send error = %v, want %v", err, errSendQueueFull)
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("overflowing Send took %v, want at most 200ms", elapsed)
	}
	select {
	case <-transport.Done():
	case <-time.After(time.Second):
		t.Fatal("queue overflow did not close transport")
	}
	if got := transport.CloseReason(); got != transportCloseQueueFull {
		t.Fatalf("close reason = %q, want %q", got, transportCloseQueueFull)
	}
}

func TestTransportWriteTimeoutClosesWithReason(t *testing.T) {
	transport, cleanup := stalledTransport(t)
	defer cleanup()
	transport.writeMu.Lock()
	transport.writeTimeout = 50 * time.Millisecond
	transport.minWriteRate = 1 << 30
	transport.writeMu.Unlock()
	message, _ := largeTransportMessage(t, 128<<10)
	started := time.Now()
	if err := transport.Send(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	select {
	case <-transport.Done():
	case <-time.After(time.Second):
		t.Fatal("write deadline did not close transport")
	}
	if elapsed := time.Since(started); elapsed > 300*time.Millisecond {
		t.Fatalf("stalled small frame closed after %v, want at most 300ms", elapsed)
	}
	if got := transport.CloseReason(); got != transportCloseTimeout {
		t.Fatalf("close reason = %q, want %q", got, transportCloseTimeout)
	}
}

func TestTransportCloseUnblocksWriterAndRejectsLaterSend(t *testing.T) {
	transport, cleanup := stalledTransport(t)
	defer cleanup()
	message, _ := largeTransportMessage(t, 128<<10)
	transport.writeMu.Lock()
	transport.writeTimeout = 30 * time.Second
	transport.writeMu.Unlock()
	if err := transport.Send(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	waitForTransportWrite(t, transport)
	time.Sleep(20 * time.Millisecond)
	started := time.Now()
	if err := transport.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("Close took %v, want at most 200ms", elapsed)
	}
	select {
	case <-transport.writerDone:
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock writer")
	}
	if got := transport.CloseReason(); got != transportCloseOwner {
		t.Fatalf("close reason = %q, want %q", got, transportCloseOwner)
	}
	if err := transport.Send(context.Background(), &auth.AuthMessage{}); err == nil {
		t.Fatal("Send after Close returned nil")
	}
	if err := transport.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestTransportWriterGoroutinesExit(t *testing.T) {
	baseline := runtime.NumGoroutine()
	release := make(chan struct{})
	server := httptest.NewServer(websocket.Handler(func(*websocket.Conn) { <-release }))
	transports := make([]*ServerWSTransport, 8)
	for i := range transports {
		transport, err := NewWSTransportAdapter(websocketURL(server.URL))
		if err != nil {
			t.Fatal(err)
		}
		transports[i] = transport
	}
	for _, transport := range transports {
		_ = transport.Close()
		select {
		case <-transport.writerDone:
		case <-time.After(time.Second):
			t.Fatal("writer goroutine did not exit")
		}
	}
	close(release)
	server.Close()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for runtime.NumGoroutine() > baseline+2 {
		select {
		case <-deadline.C:
			t.Fatalf("goroutines did not return near baseline: before=%d after=%d", baseline, runtime.NumGoroutine())
		case <-ticker.C:
			runtime.GC()
		}
	}
}
