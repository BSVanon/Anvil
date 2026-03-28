package mempool

import (
	"sync"
	"testing"
	"time"
)

func txid(prefix byte, suffix byte) [32]byte {
	var id [32]byte
	id[0] = prefix
	id[31] = suffix
	return id
}

func TestAddAndHas(t *testing.T) {
	idx := NewIndex()

	id := txid(0xAA, 0x01)
	added := idx.Add(id, TxMeta{FirstSeen: time.Now(), Size: 250})
	if !added {
		t.Fatal("expected Add to return true for new entry")
	}
	if !idx.Has(id) {
		t.Fatal("expected Has to return true")
	}
	if idx.Count() != 1 {
		t.Fatalf("expected count 1, got %d", idx.Count())
	}

	// Duplicate add
	added2 := idx.Add(id, TxMeta{FirstSeen: time.Now(), Size: 250})
	if added2 {
		t.Fatal("expected Add to return false for duplicate")
	}
	if idx.Count() != 1 {
		t.Fatalf("expected count still 1, got %d", idx.Count())
	}
}

func TestRemove(t *testing.T) {
	idx := NewIndex()
	id := txid(0xBB, 0x02)
	idx.Add(id, TxMeta{FirstSeen: time.Now()})
	idx.Remove(id)
	if idx.Has(id) {
		t.Fatal("expected Has to return false after Remove")
	}
	if idx.Count() != 0 {
		t.Fatalf("expected count 0, got %d", idx.Count())
	}

	// Remove non-existent — no panic
	idx.Remove(txid(0xFF, 0xFF))
}

func TestCountByShard(t *testing.T) {
	idx := NewIndex()
	idx.Add(txid(0x10, 0x01), TxMeta{FirstSeen: time.Now()})
	idx.Add(txid(0x10, 0x02), TxMeta{FirstSeen: time.Now()})
	idx.Add(txid(0x20, 0x01), TxMeta{FirstSeen: time.Now()})

	if idx.CountByShard(0x10) != 2 {
		t.Fatalf("expected shard 0x10 count 2, got %d", idx.CountByShard(0x10))
	}
	if idx.CountByShard(0x20) != 1 {
		t.Fatalf("expected shard 0x20 count 1, got %d", idx.CountByShard(0x20))
	}
	if idx.CountByShard(0x30) != 0 {
		t.Fatalf("expected shard 0x30 count 0, got %d", idx.CountByShard(0x30))
	}
}

func TestExpireBefore(t *testing.T) {
	idx := NewIndex()
	old := time.Now().Add(-2 * time.Hour)
	fresh := time.Now()

	idx.Add(txid(0x01, 0x01), TxMeta{FirstSeen: old})
	idx.Add(txid(0x01, 0x02), TxMeta{FirstSeen: old})
	idx.Add(txid(0x02, 0x01), TxMeta{FirstSeen: fresh})

	cutoff := time.Now().Add(-1 * time.Hour)
	evicted := idx.ExpireBefore(cutoff)
	if evicted != 2 {
		t.Fatalf("expected 2 evicted, got %d", evicted)
	}
	if idx.Count() != 1 {
		t.Fatalf("expected count 1, got %d", idx.Count())
	}
	if !idx.Has(txid(0x02, 0x01)) {
		t.Fatal("fresh entry should survive")
	}
}

func TestGetStats(t *testing.T) {
	idx := NewIndex()
	idx.Add(txid(0xA0, 0x01), TxMeta{FirstSeen: time.Now()})
	idx.Add(txid(0xA0, 0x02), TxMeta{FirstSeen: time.Now()})
	idx.Add(txid(0xB0, 0x01), TxMeta{FirstSeen: time.Now()})

	st := idx.GetStats()
	if st.Total != 3 {
		t.Fatalf("expected total 3, got %d", st.Total)
	}
	if st.Shards != 2 {
		t.Fatalf("expected 2 active shards, got %d", st.Shards)
	}
	if st.Largest != 2 {
		t.Fatalf("expected largest 2, got %d", st.Largest)
	}
}

func TestConcurrentAccess(t *testing.T) {
	idx := NewIndex()
	var wg sync.WaitGroup

	// 10 goroutines each adding 100 entries to different shards
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(prefix byte) {
			defer wg.Done()
			for i := byte(0); i < 100; i++ {
				idx.Add(txid(prefix, i), TxMeta{FirstSeen: time.Now(), Size: uint32(i)})
			}
		}(byte(g))
	}
	wg.Wait()

	if idx.Count() != 1000 {
		t.Fatalf("expected 1000, got %d", idx.Count())
	}

	// Concurrent reads + removes
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := byte(0); i < 100; i++ {
			idx.Has(txid(0, i))
		}
	}()
	go func() {
		defer wg.Done()
		for i := byte(0); i < 50; i++ {
			idx.Remove(txid(0, i))
		}
	}()
	wg.Wait()

	if idx.Count() != 950 {
		t.Fatalf("expected 950 after removing 50, got %d", idx.Count())
	}
}
