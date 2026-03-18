package txrelay

import "testing"

func TestMempoolAddAndGet(t *testing.T) {
	m := NewMempool()
	raw := []byte{0x01, 0x00, 0x00, 0x00}
	txid := "aaaa"

	if err := m.Add(txid, raw); err != nil {
		t.Fatal(err)
	}

	got, ok := m.Get(txid)
	if !ok {
		t.Fatal("expected to find tx")
	}
	if len(got) != len(raw) {
		t.Fatalf("expected %d bytes, got %d", len(raw), len(got))
	}
}

func TestMempoolDuplicateReject(t *testing.T) {
	m := NewMempool()
	m.Add("tx1", []byte{0x01})
	err := m.Add("tx1", []byte{0x01})
	if err == nil {
		t.Fatal("expected error for duplicate")
	}
}

func TestMempoolHas(t *testing.T) {
	m := NewMempool()
	if m.Has("missing") {
		t.Fatal("should not find missing tx")
	}
	m.Add("present", []byte{0x01})
	if !m.Has("present") {
		t.Fatal("should find present tx")
	}
}

func TestMempoolRemove(t *testing.T) {
	m := NewMempool()
	m.Add("tx1", []byte{0x01})
	m.Remove("tx1")
	if m.Has("tx1") {
		t.Fatal("should be gone after remove")
	}
}

func TestMempoolCount(t *testing.T) {
	m := NewMempool()
	if m.Count() != 0 {
		t.Fatalf("expected 0, got %d", m.Count())
	}
	m.Add("a", []byte{1})
	m.Add("b", []byte{2})
	if m.Count() != 2 {
		t.Fatalf("expected 2, got %d", m.Count())
	}
}
