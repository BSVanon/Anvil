package gossip

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

type countingSHIPDirectory struct {
	stores int
}

func (*countingSHIPDirectory) ForEachSHIP(func(identity, domain, nodeName, version, topic string) bool) {
}

func (d *countingSHIPDirectory) AddSHIPPeerFromGossip(identity, domain, nodeName, version, topic string) error {
	d.stores++
	return nil
}

func (*countingSHIPDirectory) RemoveSHIPPeerByIdentity(string) {}

func TestSHIPDuplicateRefreshesAreStoredButSuppressed(t *testing.T) {
	directory := &countingSHIPDirectory{}
	manager := NewManager(ManagerConfig{OverlayDir: directory})
	entry := SHIPPeerInfo{
		IdentityPub: "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Domain:      "peer.example",
		NodeName:    "peer",
		Version:     "3.6.0",
		Topic:       "anvil:mainnet",
	}
	payload, err := json.Marshal(SHIPSyncPayload{Peers: []SHIPPeerInfo{entry}})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.onSHIPSync("sender", payload); err != nil {
		t.Fatal(err)
	}
	if err := manager.onSHIPSync("sender", payload); err != nil {
		t.Fatal(err)
	}
	if directory.stores != 2 {
		t.Fatalf("directory stores = %d, want 2", directory.stores)
	}
	if len(manager.shipForwarded) != 1 {
		t.Fatalf("forward suppression entries = %d, want 1", len(manager.shipForwarded))
	}
}

func TestSHIPForwardStateIsBoundedAndSkipsSelf(t *testing.T) {
	manager := NewManager(ManagerConfig{})
	manager.localIdentity = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	self := SHIPPeerInfo{
		IdentityPub: manager.localIdentity,
		Domain:      "self.example",
		Topic:       "anvil:mainnet",
	}
	if manager.markSHIPForwarded(self, time.Now()) {
		t.Fatal("manager forwarded its own SHIP identity")
	}
	now := time.Now()
	for i := 0; i < maxSHIPForwarded+1; i++ {
		entry := SHIPPeerInfo{
			IdentityPub: fmt.Sprintf("02%064x", i+1),
			Domain:      fmt.Sprintf("peer-%d.example", i),
			Topic:       "anvil:mainnet",
		}
		if !manager.markSHIPForwarded(entry, now) {
			t.Fatalf("unique entry %d was suppressed", i)
		}
	}
	if got := len(manager.shipForwarded); got > maxSHIPForwarded {
		t.Fatalf("forward state grew to %d, cap %d", got, maxSHIPForwarded)
	}
}
