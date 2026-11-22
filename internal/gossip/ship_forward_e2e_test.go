package gossip

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/BSVanon/Anvil/internal/overlay"
)

type shipTestNode struct {
	manager   *Manager
	directory *overlay.Directory
	server    *httptest.Server
	identity  string
}

func newSHIPTestNode(t *testing.T, name string) *shipTestNode {
	t.Helper()
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := overlay.NewDirectory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	identity := fmt.Sprintf("%x", key.PubKey().Compressed())
	manager := managerWithKey(t, key, ManagerConfig{
		OverlayDir:   directory,
		LocalPubkeys: []string{identity},
	})
	server := httptest.NewServer(manager.MeshHandler())
	t.Cleanup(func() {
		manager.Stop()
		server.Close()
		_ = directory.Close()
	})
	return &shipTestNode{manager: manager, directory: directory, server: server, identity: identity}
}

func connectSHIPNodes(t *testing.T, from, to *shipTestNode) {
	t.Helper()
	if err := from.manager.ConnectPeer(t.Context(), websocketURL(to.server.URL)); err != nil {
		t.Fatalf("connect SHIP nodes: %v", err)
	}
}

func waitSHIPQuiescent(t *testing.T, nodes []*shipTestNode, timeout, quietFor time.Duration) int64 {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	last := totalSHIPReceived(nodes)
	unchangedSince := time.Now()
	for {
		select {
		case <-deadline.C:
			t.Fatalf("SHIP traffic did not quiesce: total grew from %d to %d", last, totalSHIPReceived(nodes))
		case <-ticker.C:
			current := totalSHIPReceived(nodes)
			if current != last {
				last = current
				unchangedSince = time.Now()
			}
			if time.Since(unchangedSince) >= quietFor {
				return current
			}
		}
	}
}

func totalSHIPReceived(nodes []*shipTestNode) int64 {
	var total int64
	for _, node := range nodes {
		total += node.manager.SHIPSyncsReceived()
	}
	return total
}

func waitSHIPCount(t *testing.T, manager *Manager, above int64, timeout time.Duration) int64 {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if got := manager.SHIPSyncsReceived(); got > above {
			return got
		}
		select {
		case <-deadline.C:
			t.Fatalf("SHIP receive count did not rise above %d; got %d", above, manager.SHIPSyncsReceived())
		case <-ticker.C:
		}
	}
}

func TestSHIPFullMeshLoopQuiesces(t *testing.T) {
	nodes := make([]*shipTestNode, 4)
	for i := range nodes {
		nodes[i] = newSHIPTestNode(t, fmt.Sprintf("node-%d", i))
		if err := nodes[i].directory.AddSHIPPeerFromGossip(
			nodes[i].identity, fmt.Sprintf("node-%d.example", i), fmt.Sprintf("node-%d", i), "3.6.0", "anvil:mainnet",
		); err != nil {
			t.Fatal(err)
		}
	}
	for i := range nodes {
		for j := i + 1; j < len(nodes); j++ {
			connectSHIPNodes(t, nodes[i], nodes[j])
		}
	}
	waitForMesh(t, 3*time.Second, func() bool {
		for _, node := range nodes {
			if node.manager.PeerCount() != 3 {
				return false
			}
		}
		return true
	})
	total := waitSHIPQuiescent(t, nodes, 2*time.Second, 250*time.Millisecond)
	if total > 160 {
		t.Fatalf("SHIP traffic quiesced only after %d receives; want at most 160", total)
	}
}

func TestSHIPRefreshTravelsMultipleHopsOncePerWindow(t *testing.T) {
	a := newSHIPTestNode(t, "a")
	b := newSHIPTestNode(t, "b")
	c := newSHIPTestNode(t, "c")
	b.manager.shipForwardWindow = 120 * time.Millisecond
	connectSHIPNodes(t, a, b)
	connectSHIPNodes(t, b, c)
	waitForMesh(t, 3*time.Second, func() bool {
		return a.manager.PeerCount() == 1 && b.manager.PeerCount() == 2 && c.manager.PeerCount() == 1
	})
	if err := a.directory.AddSHIPPeerFromGossip(a.identity, "a.example", "a", "3.6.0", "anvil:mainnet"); err != nil {
		t.Fatal(err)
	}

	beforeC := c.manager.SHIPSyncsReceived()
	a.manager.ReannounceToAll()
	firstC := waitSHIPCount(t, c.manager, beforeC, time.Second)
	firstB := b.manager.SHIPSyncsReceived()
	a.manager.ReannounceToAll()
	waitSHIPCount(t, b.manager, firstB, time.Second)
	requireConditionFor(t, 80*time.Millisecond, "B forwarded a duplicate refresh within its window", func() bool {
		return c.manager.SHIPSyncsReceived() == firstC
	})
	if got := c.manager.SHIPSyncsReceived(); got != firstC {
		t.Fatalf("C received duplicate refresh within window: got %d, want %d", got, firstC)
	}

	timer := time.NewTimer(140 * time.Millisecond)
	defer timer.Stop()
	<-timer.C
	a.manager.ReannounceToAll()
	waitSHIPCount(t, c.manager, firstC, time.Second)
}

func TestSHIPConflictingClaimsQuiesceInCycle(t *testing.T) {
	nodes := []*shipTestNode{
		newSHIPTestNode(t, "a"),
		newSHIPTestNode(t, "b"),
		newSHIPTestNode(t, "c"),
	}
	for i, node := range nodes[:2] {
		if err := node.directory.AddSHIPPeerFromGossip(
			node.identity, "shared.example", fmt.Sprintf("claim-%d", i), "3.6.0", "anvil:mainnet",
		); err != nil {
			t.Fatal(err)
		}
	}
	connectSHIPNodes(t, nodes[0], nodes[1])
	connectSHIPNodes(t, nodes[1], nodes[2])
	connectSHIPNodes(t, nodes[2], nodes[0])
	waitForMesh(t, 3*time.Second, func() bool {
		return nodes[0].manager.PeerCount() == 2 && nodes[1].manager.PeerCount() == 2 && nodes[2].manager.PeerCount() == 2
	})
	total := waitSHIPQuiescent(t, nodes, 2*time.Second, 250*time.Millisecond)
	if total > 80 {
		t.Fatalf("conflicting SHIP claims produced %d receives; want at most 80", total)
	}
}
