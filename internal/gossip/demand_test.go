package gossip

import (
	"testing"
)

func TestDemandIncrAndRead(t *testing.T) {
	m := &Manager{}

	m.IncrDemand("oracle:rates:bsv")
	m.IncrDemand("oracle:rates:bsv")
	m.IncrDemand("anvil:catalog")

	if got := m.TopicDemand("oracle:rates:bsv"); got != 2 {
		t.Fatalf("expected demand 2, got %d", got)
	}
	if got := m.TopicDemand("anvil:catalog"); got != 1 {
		t.Fatalf("expected demand 1, got %d", got)
	}
	if got := m.TopicDemand("nonexistent"); got != 0 {
		t.Fatalf("expected demand 0, got %d", got)
	}
}

func TestDemandMapCopy(t *testing.T) {
	m := &Manager{}

	m.IncrDemand("a")
	m.IncrDemand("b")

	dm := m.DemandMap()
	if len(dm) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(dm))
	}

	// Mutating the copy should not affect the manager
	dm["a"] = 999
	if m.TopicDemand("a") == 999 {
		t.Fatal("DemandMap should return a copy, not a reference")
	}
}

func TestMergeDemandMaxSemantics(t *testing.T) {
	m := &Manager{}

	m.IncrDemand("a") // a=1
	m.IncrDemand("a") // a=2

	// Merge with higher value
	m.MergeDemand(map[string]int{"a": 10, "b": 5})

	if got := m.TopicDemand("a"); got != 10 {
		t.Fatalf("expected max(2,10)=10, got %d", got)
	}
	if got := m.TopicDemand("b"); got != 5 {
		t.Fatalf("expected 5, got %d", got)
	}

	// Merge with lower value — should not decrease
	m.MergeDemand(map[string]int{"a": 3})
	if got := m.TopicDemand("a"); got != 10 {
		t.Fatalf("expected max(10,3)=10, got %d", got)
	}
}

func TestDecayDemand(t *testing.T) {
	m := &Manager{}

	m.IncrDemand("a")
	for i := 0; i < 9; i++ {
		m.IncrDemand("a") // a=10
	}
	m.IncrDemand("b") // b=1

	m.DecayDemand() // a=5, b=0 (removed)

	if got := m.TopicDemand("a"); got != 5 {
		t.Fatalf("expected 10/2=5, got %d", got)
	}
	if got := m.TopicDemand("b"); got != 0 {
		t.Fatalf("expected b removed after decay to 0, got %d", got)
	}

	dm := m.DemandMap()
	if _, exists := dm["b"]; exists {
		t.Fatal("b should be removed from map after decaying to 0")
	}
}
