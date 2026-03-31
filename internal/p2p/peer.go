package p2p

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
)

const (
	protocolVersion    = 70016
	userAgent          = "/Anvil:0.1.0/"
	readTimeout        = 30 * time.Second
	readTimeoutLargeTx = 120 * time.Second // large inscriptions need more time
	writeTimeout       = 10 * time.Second
)

// Peer is a raw Bitcoin P2P connection that handles the wire protocol
// for header synchronization. We use go-p2p/wire for message serialization
// but manage the TCP connection directly because go-p2p's PeerHandlerI
// doesn't route headers messages.
type Peer struct {
	conn    net.Conn
	network wire.BitcoinNet
	addr    string
	logger  *slog.Logger
	mu      sync.Mutex
}

// Connect opens a TCP connection and performs the Bitcoin P2P handshake.
func Connect(address string, network wire.BitcoinNet, logger *slog.Logger) (*Peer, error) {
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", address, err)
	}

	p := &Peer{
		conn:    conn,
		network: network,
		addr:    address,
		logger:  logger,
	}

	if err := p.handshake(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("handshake %s: %w", address, err)
	}

	return p, nil
}

// handshake performs the version/verack exchange.
func (p *Peer) handshake() error {
	// Send version
	us := wire.NewNetAddress(&net.TCPAddr{IP: net.IPv4zero, Port: 0}, 0)
	them := wire.NewNetAddress(&net.TCPAddr{IP: net.IPv4zero, Port: 0}, wire.SFNodeNetwork)

	ver := wire.NewMsgVersion(us, them, nonce(), 0)
	ver.UserAgent = userAgent
	ver.ProtocolVersion = int32(protocolVersion)
	ver.DisableRelayTx = true

	if err := p.writeMsg(ver); err != nil {
		return fmt.Errorf("send version: %w", err)
	}

	// Read version
	msg, err := p.readMsg()
	if err != nil {
		return fmt.Errorf("read version: %w", err)
	}
	if _, ok := msg.(*wire.MsgVersion); !ok {
		return fmt.Errorf("expected version, got %s", msg.Command())
	}

	// Send verack
	if err := p.writeMsg(wire.NewMsgVerAck()); err != nil {
		return fmt.Errorf("send verack: %w", err)
	}

	// Read verack (may get other messages first)
	for {
		msg, err = p.readMsg()
		if err != nil {
			return fmt.Errorf("read verack: %w", err)
		}
		if msg.Command() == wire.CmdVerAck {
			break
		}
		// Ignore sendheaders, sendcmpct, feefilter, etc.
		p.logger.Debug("handshake: ignoring", "cmd", msg.Command())
	}

	p.logger.Info("connected", "peer", p.addr)
	return nil
}

// RequestHeaders sends a getheaders message.
func (p *Peer) RequestHeaders(locators []*chainhash.Hash, hashStop *chainhash.Hash) error {
	msg := wire.NewMsgGetHeaders()
	msg.ProtocolVersion = protocolVersion
	for _, loc := range locators {
		if err := msg.AddBlockLocatorHash(loc); err != nil {
			return err
		}
	}
	if hashStop != nil {
		msg.HashStop = *hashStop
	}
	return p.writeMsg(msg)
}

// ReadHeaders reads messages until it gets a headers response.
// Returns the block headers, or nil if the peer sent an empty headers message.
func (p *Peer) ReadHeaders() ([]*wire.BlockHeader, error) {
	for {
		msg, err := p.readMsg()
		if err != nil {
			return nil, err
		}
		switch m := msg.(type) {
		case *wire.MsgHeaders:
			return m.Headers, nil
		case *wire.MsgPing:
			// Respond to pings during sync
			pong := wire.NewMsgPong(m.Nonce)
			_ = p.writeMsg(pong)
		default:
			// Ignore inv, addr, sendheaders, etc.
			p.logger.Debug("sync: ignoring", "cmd", msg.Command())
		}
	}
}

// RequestTransaction sends a getdata message requesting a specific transaction by hash.
func (p *Peer) RequestTransaction(txHash *chainhash.Hash) error {
	msg := wire.NewMsgGetData()
	inv := wire.NewInvVect(wire.InvTypeTx, txHash)
	if err := msg.AddInvVect(inv); err != nil {
		return err
	}
	return p.writeMsg(msg)
}

// ReadTransaction reads messages until it gets a tx response matching the requested hash.
// Uses extended timeout for large inscription transactions.
func (p *Peer) ReadTransaction(targetHash *chainhash.Hash) (*wire.MsgTx, error) {
	for {
		msg, err := p.readMsgLarge()
		if err != nil {
			return nil, err
		}
		switch m := msg.(type) {
		case *wire.MsgTx:
			// Verify this is the tx we requested
			gotHash := m.TxHash()
			if gotHash.IsEqual(targetHash) {
				return m, nil
			}
			p.logger.Debug("tx: ignoring unexpected", "got", gotHash.String(), "want", targetHash.String())
		case *wire.MsgPing:
			pong := wire.NewMsgPong(m.Nonce)
			_ = p.writeMsg(pong)
		case *wire.MsgNotFound:
			return nil, fmt.Errorf("transaction not found by peer")
		default:
			p.logger.Debug("tx: ignoring", "cmd", msg.Command())
		}
	}
}

// Close closes the connection.
func (p *Peer) Close() error {
	return p.conn.Close()
}

func (p *Peer) writeMsg(msg wire.Message) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	return wire.WriteMessage(p.conn, msg, protocolVersion, p.network)
}

func (p *Peer) readMsg() (wire.Message, error) {
	return p.readMsgTimeout(readTimeout)
}

func (p *Peer) readMsgLarge() (wire.Message, error) {
	return p.readMsgTimeout(readTimeoutLargeTx)
}

func (p *Peer) readMsgTimeout(timeout time.Duration) (wire.Message, error) {
	_ = p.conn.SetReadDeadline(time.Now().Add(timeout))
	msg, _, err := wire.ReadMessage(p.conn, protocolVersion, p.network)
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("peer disconnected")
		}
		return nil, err
	}
	return msg, nil
}

var nonceCounter uint64
var nonceMu sync.Mutex

func nonce() uint64 {
	nonceMu.Lock()
	defer nonceMu.Unlock()
	nonceCounter++
	return nonceCounter
}
