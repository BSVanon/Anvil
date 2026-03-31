package p2p

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
)

const (
	// Max inv vectors per getdata message (wire protocol limit).
	maxGetDataPerMsg = 50000
	// Batch window: accumulate inv vectors before sending getdata.
	batchInterval = 50 * time.Millisecond
	// Read timeout for the long-lived monitor connection.
	monitorReadTimeout = 5 * time.Minute
)

// MonitorStats holds counters for the mempool monitor.
type MonitorStats struct {
	InvSeen     int64 `json:"inv_seen"`
	InvFiltered int64 `json:"inv_filtered"`
	TxReceived  int64 `json:"tx_received"`
	Connected   bool  `json:"connected"`
}

// MempoolMonitor maintains a long-lived P2P connection that listens for
// transaction inventory announcements and selectively fetches transactions
// matching a coverage filter (first byte of txid).
type MempoolMonitor struct {
	addr     string
	network  wire.BitcoinNet
	logger   *slog.Logger
	coverage   map[byte]struct{}
	maxTxSize  int // skip txs larger than this (0 = no limit)
	onTx       func(txHash chainhash.Hash, raw []byte)

	conn   net.Conn
	connMu sync.Mutex

	// Batch buffer for getdata
	batch   []chainhash.Hash
	batchMu sync.Mutex

	// Pending getdata requests (for timeout detection)
	pending   map[chainhash.Hash]time.Time
	pendingMu sync.Mutex

	// Stats
	invSeen     atomic.Int64
	invFiltered atomic.Int64
	txReceived  atomic.Int64
	connected   atomic.Bool

	cancel context.CancelFunc
	done   chan struct{}
}

// NewMempoolMonitor creates a monitor that connects to a BSV peer and listens
// for transaction announcements. The coverage map determines which txid prefix
// bytes to fetch (nil or empty = fetch nothing, act as observer only).
func NewMempoolMonitor(addr string, network wire.BitcoinNet, coverage map[byte]struct{}, maxTxSize int, onTx func(chainhash.Hash, []byte), logger *slog.Logger) *MempoolMonitor {
	return &MempoolMonitor{
		addr:      addr,
		network:   network,
		logger:    logger,
		coverage:  coverage,
		maxTxSize: maxTxSize,
		onTx:      onTx,
		pending:   make(map[chainhash.Hash]time.Time),
		done:      make(chan struct{}),
	}
}

// Start connects to the BSV peer and begins monitoring. Non-blocking.
func (m *MempoolMonitor) Start(ctx context.Context) error {
	conn, err := net.DialTimeout("tcp", m.addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial %s: %w", m.addr, err)
	}
	m.conn = conn

	if err := m.handshake(); err != nil {
		_ = conn.Close()
		return fmt.Errorf("handshake %s: %w", m.addr, err)
	}

	ctx, m.cancel = context.WithCancel(ctx)
	go m.readLoop(ctx)
	go m.batchLoop(ctx)
	m.connected.Store(true)
	return nil
}

// Stop shuts down the monitor.
func (m *MempoolMonitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.connMu.Lock()
	if m.conn != nil {
		_ = m.conn.Close()
	}
	m.connMu.Unlock()
	<-m.done
}

// Stats returns monitoring counters.
func (m *MempoolMonitor) Stats() MonitorStats {
	return MonitorStats{
		InvSeen:     m.invSeen.Load(),
		InvFiltered: m.invFiltered.Load(),
		TxReceived:  m.txReceived.Load(),
		Connected:   m.connected.Load(),
	}
}

// handshake performs version/verack with DisableRelayTx=false so the peer
// sends unsolicited inv messages for new transactions.
func (m *MempoolMonitor) handshake() error {
	us := wire.NewNetAddress(&net.TCPAddr{IP: net.IPv4zero, Port: 0}, 0)
	them := wire.NewNetAddress(&net.TCPAddr{IP: net.IPv4zero, Port: 0}, wire.SFNodeNetwork)

	ver := wire.NewMsgVersion(us, them, nonce(), 0)
	ver.UserAgent = userAgent
	ver.ProtocolVersion = int32(protocolVersion)
	ver.DisableRelayTx = false // THE KEY DIFFERENCE: receive tx inv

	if err := m.writeMsg(ver); err != nil {
		return fmt.Errorf("send version: %w", err)
	}

	msg, err := m.readMsg(30 * time.Second)
	if err != nil {
		return fmt.Errorf("read version: %w", err)
	}
	if _, ok := msg.(*wire.MsgVersion); !ok {
		return fmt.Errorf("expected version, got %s", msg.Command())
	}

	if err := m.writeMsg(wire.NewMsgVerAck()); err != nil {
		return fmt.Errorf("send verack: %w", err)
	}

	for {
		msg, err = m.readMsg(30 * time.Second)
		if err != nil {
			return fmt.Errorf("read verack: %w", err)
		}
		if msg.Command() == wire.CmdVerAck {
			break
		}
	}

	m.logger.Info("mempool monitor connected", "peer", m.addr)
	return nil
}

// readLoop is the main async message processing loop.
func (m *MempoolMonitor) readLoop(ctx context.Context) {
	defer close(m.done)
	defer m.connected.Store(false)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg, err := m.readMsg(monitorReadTimeout)
		if err != nil {
			if ctx.Err() != nil {
				return // shutdown
			}
			m.logger.Warn("mempool monitor read error", "error", err)
			return
		}

		switch msg := msg.(type) {
		case *wire.MsgInv:
			m.handleInv(msg)
		case *wire.MsgTx:
			m.handleTx(msg)
		case *wire.MsgPing:
			_ = m.writeMsg(wire.NewMsgPong(msg.Nonce))
		case *wire.MsgNotFound:
			m.handleNotFound(msg)
		default:
			// Ignore addr, sendheaders, feefilter, etc.
		}
	}
}

// handleInv processes an inventory message, filtering by coverage.
func (m *MempoolMonitor) handleInv(msg *wire.MsgInv) {
	for _, iv := range msg.InvList {
		if iv.Type != wire.InvTypeTx {
			continue
		}
		m.invSeen.Add(1)

		// Coverage filter: check first byte of txid
		if _, covered := m.coverage[iv.Hash[0]]; !covered {
			m.invFiltered.Add(1)
			continue
		}

		// Already pending?
		m.pendingMu.Lock()
		if _, exists := m.pending[iv.Hash]; exists {
			m.pendingMu.Unlock()
			continue
		}
		m.pending[iv.Hash] = time.Now()
		m.pendingMu.Unlock()

		// Add to batch
		m.batchMu.Lock()
		m.batch = append(m.batch, iv.Hash)
		m.batchMu.Unlock()
	}
}

// handleTx processes a received transaction.
func (m *MempoolMonitor) handleTx(msg *wire.MsgTx) {
	hash := msg.TxHash()
	m.txReceived.Add(1)

	m.pendingMu.Lock()
	delete(m.pending, hash)
	m.pendingMu.Unlock()

	if m.onTx != nil {
		var buf []byte
		w := &byteWriter{buf: &buf}
		if err := msg.Serialize(w); err != nil {
			return
		}
		// Enforce max tx size — skip large inscriptions/data txs
		if m.maxTxSize > 0 && len(buf) > m.maxTxSize {
			return
		}
		m.onTx(hash, buf)
	}
}

// handleNotFound clears txids that the peer doesn't have.
func (m *MempoolMonitor) handleNotFound(msg *wire.MsgNotFound) {
	m.pendingMu.Lock()
	for _, iv := range msg.InvList {
		delete(m.pending, iv.Hash)
	}
	m.pendingMu.Unlock()
}

// batchLoop sends accumulated getdata requests at regular intervals.
func (m *MempoolMonitor) batchLoop(ctx context.Context) {
	ticker := time.NewTicker(batchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.flushBatch()
		}
	}
}

func (m *MempoolMonitor) flushBatch() {
	m.batchMu.Lock()
	if len(m.batch) == 0 {
		m.batchMu.Unlock()
		return
	}
	hashes := m.batch
	m.batch = nil
	m.batchMu.Unlock()

	// Send in chunks of maxGetDataPerMsg
	for i := 0; i < len(hashes); i += maxGetDataPerMsg {
		end := i + maxGetDataPerMsg
		if end > len(hashes) {
			end = len(hashes)
		}
		msg := wire.NewMsgGetData()
		for _, h := range hashes[i:end] {
			h := h
			_ = msg.AddInvVect(wire.NewInvVect(wire.InvTypeTx, &h))
		}
		_ = m.writeMsg(msg)
	}
}

func (m *MempoolMonitor) writeMsg(msg wire.Message) error {
	m.connMu.Lock()
	defer m.connMu.Unlock()
	if m.conn == nil {
		return fmt.Errorf("not connected")
	}
	_ = m.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	return wire.WriteMessage(m.conn, msg, protocolVersion, m.network)
}

func (m *MempoolMonitor) readMsg(timeout time.Duration) (wire.Message, error) {
	_ = m.conn.SetReadDeadline(time.Now().Add(timeout))
	msg, _, err := wire.ReadMessage(m.conn, protocolVersion, m.network)
	return msg, err
}

// byteWriter is a minimal io.Writer that appends to a byte slice.
type byteWriter struct {
	buf *[]byte
}

func (w *byteWriter) Write(p []byte) (int, error) {
	*w.buf = append(*w.buf, p...)
	return len(p), nil
}
