package gossip

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConnectionLogRecordsRecentEvents(t *testing.T) {
	dir, err := os.MkdirTemp("", "anvil-connlog-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	logPath := filepath.Join(dir, "connections.jsonl")
	log, err := NewConnectionLog(logPath, 5)
	if err != nil {
		t.Fatal(err)
	}

	log.Record(ConnectionEvent{
		Direction: "outbound",
		Event:     "connected",
		Endpoint:  "wss://anvil.sendbsv.com/mesh",
	})

	recent := log.Recent(1)
	if len(recent) != 1 {
		t.Fatalf("expected 1 recent event, got %d", len(recent))
	}
	if recent[0].Event != "connected" {
		t.Fatalf("expected connected event, got %q", recent[0].Event)
	}
	if _, err := os.Stat(logPath); err != nil {
		t.Fatalf("expected log file to exist: %v", err)
	}
}

func TestStopEmitsDisconnectEvents(t *testing.T) {
	dir, err := os.MkdirTemp("", "anvil-stop-connlog-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	logPath := filepath.Join(dir, "connections.jsonl")
	cl, err := NewConnectionLog(logPath, 50)
	if err != nil {
		t.Fatal(err)
	}

	m := NewManager(ManagerConfig{
		ConnectionLog: cl,
	})
	// Simulate a connected peer by inserting directly into the map
	m.mu.Lock()
	m.peers["fakepeer"] = &MeshPeer{
		Endpoint:    "wss://test/mesh",
		Direction:   "outbound",
		ConnectedAt: time.Now().Add(-10 * time.Second),
		origKey:     "fakepeer",
	}
	m.mu.Unlock()

	m.Stop()

	recent := cl.Recent(10)
	found := false
	for _, ev := range recent {
		if ev.Event == "disconnected" && ev.Reason == "shutdown" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected a disconnected/shutdown event after Stop()")
	}
}

func TestManagerNormalizesLocalPubkeys(t *testing.T) {
	m := NewManager(ManagerConfig{
		LocalPubkeys: []string{" 02ABCDEF "},
	})
	if _, ok := m.localPubkeys["02abcdef"]; !ok {
		t.Fatal("expected normalized local pubkey to be present")
	}
}
