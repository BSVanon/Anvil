package gossip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	"golang.org/x/net/websocket"
)

// preAuthMaxFrameBytes caps the size of a single WebSocket frame this
// transport will accept before its peer has completed BRC-31
// authentication and this node's own allowed_peers/bond checks
// (MarkAuthorized). golang.org/x/net/websocket's own default
// (DefaultMaxPayloadBytes, 32 MiB) otherwise applies from the first frame
// of every connection, authenticated or not — letting an unauthenticated
// sender force up to 32 MiB of read buffer per connection before it has
// proven anything about who it is. The handshake messages that establish
// identity are small (BRC-31 initial request/response, certificates), so
// this never affects a legitimate peer; MarkAuthorized raises the limit
// back to the library default once this connection no longer needs the
// smaller one.
const preAuthMaxFrameBytes = 64 << 10 // 64 KiB

// --- Outbound (client-side) transport ---

// NewWSTransportAdapter dials a WebSocket endpoint and returns a
// ServerWSTransport (which works for both client and server — it's just
// a conn wrapper). This replaces the SDK's WebSocketTransport so we
// own the conn and can close it cleanly.
func NewWSTransportAdapter(endpoint string) (*ServerWSTransport, error) {
	return newWSTransportAdapter(endpoint, 10*time.Second, false)
}

var allowLoopbackExchangeDial atomic.Bool

func newWSTransportAdapter(endpoint string, timeout time.Duration, guardPrivate bool) (*ServerWSTransport, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	config, err := websocket.NewConfig(endpoint, "http://localhost")
	if err != nil {
		return nil, fmt.Errorf("websocket config %s: %w", endpoint, err)
	}
	dialer := &net.Dialer{Timeout: timeout}
	if guardPrivate {
		dialer.Control = exchangeDialControl
	}
	config.Dialer = dialer
	dialCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := config.DialContext(dialCtx)
	if err != nil {
		return nil, fmt.Errorf("websocket dial %s: %w", endpoint, err)
	}
	return NewServerWSTransport(conn), nil
}

func exchangeDialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("peer exchange remote address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("peer exchange remote address is not an IP")
	}
	if ip.IsLoopback() && allowLoopbackExchangeDial.Load() {
		return nil
	}
	if isUnsafeExchangeIP(ip) {
		return fmt.Errorf("peer exchange refused non-public address %s", ip)
	}
	return nil
}

func isUnsafeExchangeIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		return v4[0] == 0 || v4[0] == 127 ||
			(v4[0] == 100 && v4[1]&0xc0 == 64) ||
			v4.IsPrivate() || v4.IsLinkLocalUnicast() ||
			v4.IsLinkLocalMulticast() || v4.IsMulticast() || v4.IsUnspecified()
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
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

	authorized chan struct{} // closed by MarkAuthorized
	authOnce   sync.Once
}

// NewServerWSTransport wraps an accepted or dialled WebSocket connection,
// capping its per-frame size at preAuthMaxFrameBytes until MarkAuthorized
// is called.
func NewServerWSTransport(conn *websocket.Conn) *ServerWSTransport {
	if conn != nil {
		conn.MaxPayloadBytes = preAuthMaxFrameBytes
	}
	return &ServerWSTransport{conn: conn, done: make(chan struct{}), authorized: make(chan struct{})}
}

// Done returns a channel that is closed when the connection is lost.
func (s *ServerWSTransport) Done() <-chan struct{} { return s.done }

// MarkAuthorized signals that this connection's remote peer has completed
// BRC-31 authentication and passed this node's own allowed_peers/bond
// checks. Idempotent and safe to call from any goroutine. Its one
// deferred effect — raising the per-frame size cap back to the library
// default — happens inside StartReceive's own loop (see there), which is
// the only code that ever touches conn.MaxPayloadBytes after
// construction, so that write is never concurrent with this call.
func (s *ServerWSTransport) MarkAuthorized() {
	s.authOnce.Do(func() { close(s.authorized) })
}

// Authorized returns a channel that is closed once MarkAuthorized has
// been called for this connection.
func (s *ServerWSTransport) Authorized() <-chan struct{} { return s.authorized }

// raiseFrameLimitIfAuthorized raises the receive cap only from StartReceive's
// goroutine. It reports whether authorization was already observed.
func (s *ServerWSTransport) raiseFrameLimitIfAuthorized() bool {
	select {
	case <-s.authorized:
		s.conn.MaxPayloadBytes = 0
		return true
	default:
		return false
	}
}

func (s *ServerWSTransport) RemoteAddr() string {
	if s.conn == nil {
		return ""
	}
	addr := s.conn.RemoteAddr()
	if addr == nil {
		return ""
	}
	return addr.String()
}

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
	raised := false
	for {
		if !raised {
			raised = s.raiseFrameLimitIfAuthorized()
		}
		var raw []byte
		if err := websocket.Message.Receive(s.conn, &raw); err != nil {
			// Receive reads the frame header before it checks MaxPayloadBytes.
			// Authorization can therefore close between the check at the top of
			// this loop and that size check. Retry this frame with the raised
			// limit when that happened; the codec retains the frame for the next
			// Receive call, so no bytes are lost or accepted pre-authorization.
			if !raised && errors.Is(err, websocket.ErrFrameTooLarge) && s.raiseFrameLimitIfAuthorized() {
				raised = true
				continue
			}
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
			_ = fn(context.Background(), &msg)
		}
	}
}
