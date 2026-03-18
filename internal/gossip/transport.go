package gossip

import (
	"context"
	"sync"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/transports"
)

// WSTransportAdapter wraps go-sdk's WebSocketTransport to satisfy auth.Transport.
// The WebSocketTransport has Send(msg) and OnData(func(msg)), while auth.Transport
// requires Send(ctx, msg) and OnData(func(ctx, msg)) plus GetRegisteredOnData().
// This adapter bridges the gap with ~20 lines of glue.
type WSTransportAdapter struct {
	ws         *transports.WebSocketTransport
	mu         sync.Mutex
	onDataFunc func(context.Context, *auth.AuthMessage) error
}

// NewWSTransportAdapter creates an adapter wrapping a WebSocketTransport.
func NewWSTransportAdapter(endpoint string) (*WSTransportAdapter, error) {
	ws, err := transports.NewWebSocketTransport(&transports.WebSocketTransportOptions{
		BaseURL: endpoint,
	})
	if err != nil {
		return nil, err
	}
	adapter := &WSTransportAdapter{ws: ws}

	// Bridge the non-context callback to the context-aware one
	ws.OnData(func(msg *auth.AuthMessage) error {
		adapter.mu.Lock()
		fn := adapter.onDataFunc
		adapter.mu.Unlock()
		if fn != nil {
			return fn(context.Background(), msg)
		}
		return nil
	})

	return adapter, nil
}

// Send implements auth.Transport.Send.
func (a *WSTransportAdapter) Send(_ context.Context, message *auth.AuthMessage) error {
	return a.ws.Send(message)
}

// OnData implements auth.Transport.OnData.
func (a *WSTransportAdapter) OnData(callback func(context.Context, *auth.AuthMessage) error) error {
	a.mu.Lock()
	a.onDataFunc = callback
	a.mu.Unlock()
	return nil
}

// GetRegisteredOnData implements auth.Transport.GetRegisteredOnData.
func (a *WSTransportAdapter) GetRegisteredOnData() (func(context.Context, *auth.AuthMessage) error, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.onDataFunc, nil
}
