package health

import (
	"errors"
	"testing"
	"time"
)

func TestRecordAndSnapshot(t *testing.T) {
	r := New()
	if s := r.Snapshot(); s.Total != 0 || s.ByTopic != nil {
		t.Fatalf("empty registry should snapshot empty, got %+v", s)
	}
	r.RecordLookupError("tm_kvstore", errors.New("parse beef: boom"))
	r.RecordLookupError("tm_kvstore", errors.New("parse beef: boom2"))
	r.RecordLookupError("tm_uhrp", errors.New("nope"))

	s := r.Snapshot()
	if s.Total != 3 || s.RecentTotal != 3 {
		t.Fatalf("want total=3 recent=3, got total=%d recent=%d", s.Total, s.RecentTotal)
	}
	kv := s.ByTopic["tm_kvstore"]
	if kv.Total != 2 || kv.Recent1h != 2 {
		t.Fatalf("kvstore want 2/2, got %d/%d", kv.Total, kv.Recent1h)
	}
	if kv.LastError != "parse beef: boom2" {
		t.Fatalf("want last error boom2, got %q", kv.LastError)
	}
	if s.ByTopic["tm_uhrp"].Total != 1 {
		t.Fatalf("uhrp want 1, got %d", s.ByTopic["tm_uhrp"].Total)
	}
}

func TestNilSafe(t *testing.T) {
	var r *Registry
	r.RecordLookupError("t", errors.New("x")) // nil receiver: must not panic
	r2 := New()
	r2.RecordLookupError("t", nil) // nil error: no-op
	if r2.Snapshot().Total != 0 {
		t.Fatal("nil error must not record")
	}
}

func TestRollingWindowPrune(t *testing.T) {
	now := time.Now()
	old := now.Add(-2 * time.Hour).UnixNano()
	fresh := now.Add(-1 * time.Minute).UnixNano()
	got := pruneOld([]int64{old, old, fresh}, now)
	if len(got) != 1 || got[0] != fresh {
		t.Fatalf("prune should keep only the fresh timestamp, got %v", got)
	}
}
