package gossip

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

func queueOnlyTransport() *ServerWSTransport {
	transport := &ServerWSTransport{
		done:           make(chan struct{}),
		authorized:     make(chan struct{}),
		writerDone:     make(chan struct{}),
		queueMaxFrames: transportSendQueueFrames,
		queueMaxBytes:  transportSendQueueBytes,
		queueSoftBytes: transportSoftQueueBytes,
		writeTimeout:   transportWriteTimeout,
		minWriteRate:   transportMinWriteRate,
	}
	transport.writeCond = sync.NewCond(&transport.writeMu)
	return transport
}

func setNodeQueueBudget(t *testing.T, manager *Manager, limit int) {
	t.Helper()
	manager.transports.budget.mu.Lock()
	manager.transports.budget.maxBytes = limit
	manager.transports.budget.mu.Unlock()
}

func TestNodeQueueBudgetEvictsLargestTransport(t *testing.T) {
	manager := NewManager(ManagerConfig{})
	setNodeQueueBudget(t, manager, 4<<20)
	transports := []*ServerWSTransport{queueOnlyTransport(), queueOnlyTransport(), queueOnlyTransport()}
	for _, transport := range transports {
		manager.attachTransport(transport)
	}

	if err := transports[0].enqueueFrame(make([]byte, 2<<20)); err != nil {
		t.Fatal(err)
	}
	if err := transports[1].enqueueFrame(make([]byte, 1800<<10)); err != nil {
		t.Fatal(err)
	}
	if err := transports[2].enqueueFrame(make([]byte, 1500<<10)); err != nil {
		t.Fatal(err)
	}

	if got := transports[0].CloseReason(); got != transportCloseNodeQueueFull {
		t.Fatalf("largest transport close reason = %q, want %q", got, transportCloseNodeQueueFull)
	}
	if got := transports[1].CloseReason(); got != "" {
		t.Fatalf("second transport unexpectedly closed: %s", got)
	}
	if got := transports[2].CloseReason(); got != "" {
		t.Fatalf("enqueuing transport unexpectedly closed: %s", got)
	}
	if got := manager.transports.budget.total(); got > 4<<20 {
		t.Fatalf("node queue total = %d, want at most %d", got, 4<<20)
	}
	for _, transport := range transports {
		_ = transport.Close()
	}
	if got := manager.transports.budget.total(); got != 0 {
		t.Fatalf("node queue total after close = %d, want 0", got)
	}
}

func TestNodeQueueBudgetCountsAttemptBeforeChoosingVictim(t *testing.T) {
	manager := NewManager(ManagerConfig{})
	setNodeQueueBudget(t, manager, 5)
	healthy := queueOnlyTransport()
	attacker := queueOnlyTransport()
	manager.attachTransport(healthy)
	manager.attachTransport(attacker)
	if err := healthy.enqueueFrame(make([]byte, 3)); err != nil {
		t.Fatal(err)
	}
	if err := attacker.enqueueFrame(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}

	err := attacker.enqueueFrame(make([]byte, 2))
	if !errors.Is(err, errNodeQueueFull) {
		t.Fatalf("attacker enqueue error = %v, want %v", err, errNodeQueueFull)
	}
	if got := attacker.CloseReason(); got != transportCloseNodeQueueFull {
		t.Fatalf("attacker close reason = %q, want %q", got, transportCloseNodeQueueFull)
	}
	if got := healthy.CloseReason(); got != "" {
		t.Fatalf("healthy transport unexpectedly closed: %s", got)
	}
	_ = healthy.Close()
}

func TestNodeQueueBudgetRechecksPressureBeforeEviction(t *testing.T) {
	manager := NewManager(ManagerConfig{})
	setNodeQueueBudget(t, manager, 2)
	victim := queueOnlyTransport()
	sender := queueOnlyTransport()
	manager.attachTransport(victim)
	manager.attachTransport(sender)
	if err := victim.enqueueFrame(make([]byte, 2)); err != nil {
		t.Fatal(err)
	}

	victim.writeMu.Lock()
	result := make(chan error, 1)
	go func() { result <- sender.enqueueFrame(make([]byte, 1)) }()
	select {
	case err := <-result:
		victim.writeMu.Unlock()
		t.Fatalf("enqueue returned before selected victim was unlocked: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	victim.writeQueue = nil
	victim.queuedBytes = 0
	victim.releaseNodeBytesLocked(2)
	victim.writeMu.Unlock()

	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("enqueue did not retry after queue pressure drained")
	}
	if got := victim.CloseReason(); got != "" {
		t.Fatalf("drained transport unexpectedly closed: %s", got)
	}
	_ = victim.Close()
	_ = sender.Close()
}

func TestNodeQueueBudgetKeepsDrainingTransport(t *testing.T) {
	manager := NewManager(ManagerConfig{})
	setNodeQueueBudget(t, manager, 5<<20)
	stalled := queueOnlyTransport()
	manager.attachTransport(stalled)
	if err := stalled.enqueueFrame(make([]byte, 3<<20)); err != nil {
		t.Fatal(err)
	}

	message, _ := largeTransportMessage(t, 1<<20)
	healthy, received := receivingTransport(t, func(conn *websocket.Conn) error {
		var raw []byte
		return websocket.Message.Receive(conn, &raw)
	})
	manager.attachTransport(healthy)
	if err := healthy.Send(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-received:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("healthy transport did not drain")
	}
	if got := stalled.CloseReason(); got != transportCloseNodeQueueFull {
		t.Fatalf("stalled transport close reason = %q, want %q", got, transportCloseNodeQueueFull)
	}
	if got := healthy.CloseReason(); got != "" {
		t.Fatalf("healthy transport unexpectedly closed: %s", got)
	}
	deadline := time.Now().Add(time.Second)
	for manager.transports.budget.total() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := manager.transports.budget.total(); got != 0 {
		t.Fatalf("node queue total after drain = %d, want 0", got)
	}
	_ = healthy.Close()
}

func TestNodeQueueBudgetCountsBytesQueuedBeforeAttach(t *testing.T) {
	manager := NewManager(ManagerConfig{})
	transport := queueOnlyTransport()
	const queued = 512 << 10
	if err := transport.enqueueFrame(make([]byte, queued)); err != nil {
		t.Fatal(err)
	}
	manager.attachTransport(transport)
	if got := manager.transports.budget.total(); got != queued {
		t.Fatalf("attached queue total = %d, want %d", got, queued)
	}
	_ = transport.Close()
	if got := manager.transports.budget.total(); got != 0 {
		t.Fatalf("node queue total after close = %d, want 0", got)
	}
}

func TestNodeQueueBudgetDoesNotAttachClosedTransport(t *testing.T) {
	manager := NewManager(ManagerConfig{})
	transport := queueOnlyTransport()
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}

	manager.attachTransport(transport)

	manager.transports.budget.mu.Lock()
	retained := len(manager.transports.budget.transports)
	total := manager.transports.budget.queuedBytes
	manager.transports.budget.mu.Unlock()
	if retained != 0 {
		t.Fatalf("closed transports retained by budget = %d, want 0", retained)
	}
	if total != 0 {
		t.Fatalf("node queue total = %d, want 0", total)
	}
}

func TestNodeQueueBudgetRejectsOversizedIdleFrame(t *testing.T) {
	manager := NewManager(ManagerConfig{})
	setNodeQueueBudget(t, manager, 1<<20)
	transport := queueOnlyTransport()
	manager.attachTransport(transport)
	err := transport.enqueueFrame(make([]byte, 2<<20))
	if !errors.Is(err, errNodeQueueFull) {
		t.Fatalf("enqueue error = %v, want %v", err, errNodeQueueFull)
	}
	if got := transport.CloseReason(); got != transportCloseNodeQueueFull {
		t.Fatalf("close reason = %q, want %q", got, transportCloseNodeQueueFull)
	}
	if got := manager.transports.budget.total(); got != 0 {
		t.Fatalf("node queue total = %d, want 0", got)
	}
}

func TestNodeQueueBudgetConcurrentEnqueueAndClose(t *testing.T) {
	manager := NewManager(ManagerConfig{})
	setNodeQueueBudget(t, manager, 1<<20)
	transport := queueOnlyTransport()
	manager.attachTransport(transport)

	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for range 500 {
				_ = transport.enqueueFrame(make([]byte, 4<<10))
			}
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		<-start
		_ = transport.Close()
	}()
	close(start)
	workers.Wait()
	if got := manager.transports.budget.total(); got != 0 {
		t.Fatalf("node queue total after concurrent close = %d, want 0", got)
	}
}
