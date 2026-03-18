package gossip

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/bsv-blockchain/go-sdk/auth"
	"golang.org/x/net/websocket"
)

// --- Outbound (client-side) transport ---

// NewWSTransportAdapter dials a WebSocket endpoint and returns a
// ServerWSTransport (which works for both client and server — it's just
// a conn wrapper). This replaces the SDK's WebSocketTransport so we
// own the conn and can close it cleanly.
func NewWSTransportAdapter(endpoint string) (*ServerWSTransport, error) {
	conn, err := websocket.Dial(endpoint, "", "http://localhost")
	if err != nil {
		return nil, fmt.Errorf("websocket dial %s: %w", endpoint, err)
	}
	return NewServerWSTransport(conn), nil
}

// --- Inbound (server-side) transport ---

// ServerWSTransport wraps an already-accepted *websocket.Conn to satisfy
// auth.Transport for inbound mesh peers. The read loop is started by
// StartReceive and runs until the connection closes.
type ServerWSTransport struct {
	conn       *websocket.Conn
	mu         sync.Mutex
	onDataFunc func(context.Context, *auth.AuthMessage) error
	done       chan struct{} // closed when the read loop exits
}

// NewServerWSTransport wraps an accepted WebSocket connection.
func NewServerWSTransport(conn *websocket.Conn) *ServerWSTransport {
	return &ServerWSTransport{conn: conn, done: make(chan struct{})}
}

// Done returns a channel that is closed when the connection is lost.
func (s *ServerWSTransport) Done() <-chan struct{} { return s.done }

// Close closes the underlying WebSocket connection, causing StartReceive to exit.
func (s *ServerWSTransport) Close() error { return s.conn.Close() }

// Send implements auth.Transport.Send.
func (s *ServerWSTransport) Send(_ context.Context, message *auth.AuthMessage) error {
	data, err := json.Marshal(message)
	if err != nil {
		return err
	}
	return websocket.Message.Send(s.conn, data)
}

// OnData implements auth.Transport.OnData.
func (s *ServerWSTransport) OnData(callback func(context.Context, *auth.AuthMessage) error) error {
	s.mu.Lock()
	s.onDataFunc = callback
	s.mu.Unlock()
	return nil
}

// GetRegisteredOnData implements auth.Transport.GetRegisteredOnData.
func (s *ServerWSTransport) GetRegisteredOnData() (func(context.Context, *auth.AuthMessage) error, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.onDataFunc, nil
}

// StartReceive runs the read loop, dispatching incoming messages to the
// OnData callback. Blocks until the connection closes or errors.
// When the connection is lost, the done channel is closed.
func (s *ServerWSTransport) StartReceive() {
	defer close(s.done)
	for {
		var raw []byte
		if err := websocket.Message.Receive(s.conn, &raw); err != nil {
			return // connection closed
		}
		var msg auth.AuthMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue
		}
		s.mu.Lock()
		fn := s.onDataFunc
		s.mu.Unlock()
		if fn != nil {
			fn(context.Background(), &msg)
		}
	}
}
