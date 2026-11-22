package gossip

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/websocket"
)

const (
	transportSendQueueFrames = 4096
	transportSoftQueueBytes  = 8 << 20
	transportSendQueueBytes  = 32 << 20
	transportNodeQueueBytes  = 256 << 20
	transportWriteTimeout    = 15 * time.Second
	transportMinWriteRate    = 64 << 10
)

const (
	transportCloseQueueFull     = "send_queue_full"
	transportCloseNodeQueueFull = "node_queue_full"
	transportCloseTimeout       = "write_timeout"
	transportCloseWriteError    = "write_error"
	transportCloseOwner         = "closed_by_owner"
	transportCloseRemote        = "remote_closed"
)

var (
	errTransportClosed = errors.New("mesh transport closed")
	errSendQueueFull   = errors.New("mesh transport send queue full")
	errNodeQueueFull   = errors.New("mesh node send queue full")
	errFrameTooLarge   = errors.New("mesh transport frame exceeds receive cap")
)

// One catch-up response carries at most 100 envelopes. At the default 65,536
// byte envelope payload cap that is 6.25 MiB, or about 8.34 MiB after the
// auth message's base64 expansion, plus JSON/signature overhead. The soft
// limit skips ordinary data once that response-sized backlog accumulates; the
// 32 MiB hard limit and 4,096-frame cap still admit control and catch-up
// traffic. [envelopes] max_durable_size is operator-configurable, so changing
// it scales catch-up response sizes proportionally.
type transportFrame struct {
	data []byte
}

func (s *ServerWSTransport) enqueueFrame(data []byte) error {
	if len(data) > websocket.DefaultMaxPayloadBytes {
		return fmt.Errorf("%w: bytes=%d max=%d", errFrameTooLarge, len(data), websocket.DefaultMaxPayloadBytes)
	}
	for {
		s.writeMu.Lock()
		if s.closed {
			reason := s.closeReason
			s.writeMu.Unlock()
			return fmt.Errorf("%w: %s", errTransportClosed, reason)
		}
		// A single receivable frame is always admitted to an idle writer even
		// when a test or future configuration sets the per-connection bound below it.
		if len(s.writeQueue) > 0 &&
			(len(s.writeQueue)+1 > s.queueMaxFrames || s.queuedBytes+len(data) > s.queueMaxBytes) {
			attemptedFrames := len(s.writeQueue) + 1
			attemptedBytes := s.queuedBytes + len(data)
			s.markClosedLocked(transportCloseQueueFull)
			s.writeMu.Unlock()
			s.finishClose()
			return fmt.Errorf("%w: frames=%d bytes=%d", errSendQueueFull, attemptedFrames, attemptedBytes)
		}
		victim := s.reserveNodeBytesLocked(len(data))
		if victim == nil {
			s.writeQueue = append(s.writeQueue, transportFrame{data: data})
			s.queuedBytes += len(data)
			s.writeCond.Signal()
			s.writeMu.Unlock()
			return nil
		}
		s.writeMu.Unlock()

		// Never hold one transport's writeMu while closing another transport.
		evicted := victim.evictForNodeQueue(s, len(data))
		if victim == s && evicted {
			return fmt.Errorf("%w: bytes=%d", errNodeQueueFull, len(data))
		}
	}
}

func (s *ServerWSTransport) writeLoop() {
	defer close(s.writerDone)
	for {
		s.writeMu.Lock()
		for len(s.writeQueue) == 0 && !s.closed {
			s.writeCond.Wait()
		}
		if s.closed {
			s.writeMu.Unlock()
			return
		}
		frame := s.writeQueue[0]
		timeout := s.writeTimeout
		minWriteRate := s.minWriteRate
		if minWriteRate <= 0 {
			minWriteRate = transportMinWriteRate
		}
		timeout += time.Duration(len(frame.data)) * time.Second / time.Duration(minWriteRate)
		err := s.conn.SetWriteDeadline(time.Now().Add(timeout))
		s.writeMu.Unlock()

		if err == nil {
			err = websocket.Message.Send(s.conn, frame.data)
		}

		s.writeMu.Lock()
		if len(s.writeQueue) > 0 {
			s.writeQueue[0] = transportFrame{}
			s.writeQueue = s.writeQueue[1:]
			s.queuedBytes -= len(frame.data)
			s.releaseNodeBytesLocked(len(frame.data))
		}
		s.writeMu.Unlock()
		if err == nil {
			continue
		}
		reason := transportCloseWriteError
		var netErr net.Error
		if (errors.As(err, &netErr) && netErr.Timeout()) || errors.Is(err, os.ErrDeadlineExceeded) {
			reason = transportCloseTimeout
		}
		s.closeWithReason(reason)
		return
	}
}

func (s *ServerWSTransport) closeWithReason(reason string) error {
	s.writeMu.Lock()
	if !s.closed {
		s.markClosedLocked(reason)
	}
	s.writeMu.Unlock()
	return s.finishClose()
}

func (s *ServerWSTransport) markClosedLocked(reason string) {
	s.closed = true
	s.closeReason = reason
	s.writeQueue = nil
	s.queuedBytes = 0
	s.releaseAllNodeBytesLocked()
	s.writeCond.Broadcast()
}

func (s *ServerWSTransport) finishClose() (err error) {
	s.finishOnce.Do(func() {
		s.closeDone()
		if s.conn != nil {
			_ = s.conn.SetDeadline(time.Now())
			closeErr := s.conn.Close()
			var netErr net.Error
			if closeErr != nil &&
				!((errors.As(closeErr, &netErr) && netErr.Timeout()) || errors.Is(closeErr, os.ErrDeadlineExceeded)) {
				err = closeErr
			}
		}
	})
	return err
}

func (s *ServerWSTransport) closeDone() {
	s.doneOnce.Do(func() { close(s.done) })
}

// CloseReason reports the first reason this transport closed.
func (s *ServerWSTransport) CloseReason() string {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.closeReason
}

// Backlogged reports whether queued plus in-flight bytes exceed the soft
// forwarding bound.
func (s *ServerWSTransport) Backlogged() bool {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.queuedBytes > s.queueSoftBytes
}
