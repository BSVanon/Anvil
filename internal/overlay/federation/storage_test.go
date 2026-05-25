package federation

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-overlay-discovery-services/pkg/ship"
	"github.com/bsv-blockchain/go-overlay-discovery-services/pkg/slap"
	"github.com/bsv-blockchain/go-overlay-discovery-services/pkg/types"
	"github.com/syndtr/goleveldb/leveldb"
)

// stepClock returns a deterministic clock that advances 1 second on each
// call, starting from a fixed epoch. Used by sort-contract tests to
// guarantee distinct CreatedAt timestamps in well-defined order even
// though Store calls run in a tight loop.
func stepClock(t *testing.T) func() {
	t.Helper()
	original := clock
	t.Cleanup(func() { clock = original })
	base := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	tick := 0
	clock = func() time.Time {
		tick++
		return base.Add(time.Duration(tick) * time.Second)
	}
	return func() {}
}

func ptrSort(o types.SortOrder) *types.SortOrder { return &o }

// Compile-time assertions that Anvil's LevelDB adapters satisfy the
// canonical StorageInterface contracts. If go-overlay-discovery-services
// adds a new method to either interface, the build will break here
// instead of at registration time.
var (
	_ ship.StorageInterface = (*SHIPStorage)(nil)
	_ slap.StorageInterface = (*SLAPStorage)(nil)
)

func newTestDB(t *testing.T) *leveldb.DB {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ldb")
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatalf("open leveldb: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func ptrString(s string) *string { return &s }
func ptrInt(i int) *int          { return &i }

func TestSHIPStorage_StoreAndFindRecord(t *testing.T) {
	ctx := context.Background()
	s := NewSHIPStorage(newTestDB(t))

	// Seed three records across two domains.
	if err := s.StoreSHIPRecord(ctx, "txA", 0, "key1", "https://anvil-a.test", "tm_uhrp"); err != nil {
		t.Fatalf("store A: %v", err)
	}
	if err := s.StoreSHIPRecord(ctx, "txB", 0, "key2", "https://anvil-b.test", "tm_uhrp"); err != nil {
		t.Fatalf("store B: %v", err)
	}
	if err := s.StoreSHIPRecord(ctx, "txC", 1, "key1", "https://anvil-a.test", "tm_dex_swap"); err != nil {
		t.Fatalf("store C: %v", err)
	}

	// Domain filter.
	hits, err := s.FindRecord(ctx, types.SHIPQuery{Domain: ptrString("https://anvil-a.test")})
	if err != nil {
		t.Fatalf("find by domain: %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits for anvil-a, got %d", len(hits))
	}

	// Topic filter.
	hits, err = s.FindRecord(ctx, types.SHIPQuery{Topics: []string{"tm_uhrp"}})
	if err != nil {
		t.Fatalf("find by topic: %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits for tm_uhrp, got %d", len(hits))
	}

	// Combined filter.
	hits, err = s.FindRecord(ctx, types.SHIPQuery{
		Domain: ptrString("https://anvil-a.test"),
		Topics: []string{"tm_dex_swap"},
	})
	if err != nil {
		t.Fatalf("find by domain+topic: %v", err)
	}
	if len(hits) != 1 || hits[0].Txid != "txC" {
		t.Fatalf("expected single tm_dex_swap hit, got %+v", hits)
	}
}

func TestSHIPStorage_DeleteRemovesEntry(t *testing.T) {
	ctx := context.Background()
	s := NewSHIPStorage(newTestDB(t))
	_ = s.StoreSHIPRecord(ctx, "txA", 0, "key1", "https://anvil-a.test", "tm_uhrp")

	all, _ := s.FindAll(ctx, nil, nil, nil)
	if len(all) != 1 {
		t.Fatalf("pre-delete expected 1 record, got %d", len(all))
	}
	if err := s.DeleteSHIPRecord(ctx, "txA", 0); err != nil {
		t.Fatalf("delete: %v", err)
	}
	all, _ = s.FindAll(ctx, nil, nil, nil)
	if len(all) != 0 {
		t.Fatalf("post-delete expected 0 records, got %d", len(all))
	}

	// Idempotent on missing key.
	if err := s.DeleteSHIPRecord(ctx, "txA", 0); err != nil {
		t.Fatalf("delete missing must be idempotent, got: %v", err)
	}
}

func TestSHIPStorage_FindAllPagination(t *testing.T) {
	ctx := context.Background()
	s := NewSHIPStorage(newTestDB(t))
	for i, txid := range []string{"tx0", "tx1", "tx2", "tx3", "tx4"} {
		if err := s.StoreSHIPRecord(ctx, txid, i, "key", "https://h.test", "tm_uhrp"); err != nil {
			t.Fatalf("store %d: %v", i, err)
		}
	}

	hits, err := s.FindAll(ctx, ptrInt(2), ptrInt(1), nil)
	if err != nil {
		t.Fatalf("find paginated: %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("limit=2 expected 2 hits, got %d", len(hits))
	}
}

func TestSLAPStorage_StoreFindDelete(t *testing.T) {
	ctx := context.Background()
	s := NewSLAPStorage(newTestDB(t))

	if err := s.StoreSLAPRecord(ctx, "txA", 0, "key1", "https://anvil-a.test", "ls_uhrp"); err != nil {
		t.Fatalf("store A: %v", err)
	}
	if err := s.StoreSLAPRecord(ctx, "txB", 0, "key2", "https://anvil-b.test", "ls_uhrp"); err != nil {
		t.Fatalf("store B: %v", err)
	}

	hits, err := s.FindRecord(ctx, types.SLAPQuery{Service: ptrString("ls_uhrp")})
	if err != nil {
		t.Fatalf("find by service: %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("expected 2 ls_uhrp hits, got %d", len(hits))
	}

	hits, err = s.FindRecord(ctx, types.SLAPQuery{Domain: ptrString("https://anvil-b.test")})
	if err != nil {
		t.Fatalf("find by domain: %v", err)
	}
	if len(hits) != 1 || hits[0].Txid != "txB" {
		t.Fatalf("expected single anvil-b hit, got %+v", hits)
	}

	if err := s.DeleteSLAPRecord(ctx, "txB", 0); err != nil {
		t.Fatalf("delete: %v", err)
	}
	hits, _ = s.FindAll(ctx, nil, nil, nil)
	if len(hits) != 1 || hits[0].Txid != "txA" {
		t.Fatalf("post-delete unexpected: %+v", hits)
	}
}

// TestSHIPStorage_DefaultSortIsDescCreatedAt verifies the canonical
// sort contract from go-overlay-discovery-services/pkg/shared/storage.go:24-31:
// findOpts default to descending createdAt (newest first) when no
// sortOrder is supplied. Codex review 6daa58cb1a6f43e4 caught the
// original adapter just reversing LevelDB key order — bypass of the
// canonical contract that would have produced wrong ordering once
// CreatedAt-aware peers queried us.
func TestSHIPStorage_DefaultSortIsDescCreatedAt(t *testing.T) {
	stepClock(t)
	ctx := context.Background()
	s := NewSHIPStorage(newTestDB(t))

	// Store three records with monotonically increasing CreatedAt.
	// LevelDB key order is alphabetical on txid:vout, so storing in
	// txid-ascending order means LevelDB iteration would yield txA,
	// txB, txC — but canonical desc-CreatedAt requires txC, txB, txA.
	_ = s.StoreSHIPRecord(ctx, "txA", 0, "k", "https://h.test", "tm_uhrp")
	_ = s.StoreSHIPRecord(ctx, "txB", 0, "k", "https://h.test", "tm_uhrp")
	_ = s.StoreSHIPRecord(ctx, "txC", 0, "k", "https://h.test", "tm_uhrp")

	got, err := s.FindAll(ctx, nil, nil, nil)
	if err != nil {
		t.Fatalf("FindAll: %v", err)
	}
	wantOrder := []string{"txC", "txB", "txA"}
	if len(got) != len(wantOrder) {
		t.Fatalf("expected %d hits, got %d (%+v)", len(wantOrder), len(got), got)
	}
	for i, want := range wantOrder {
		if got[i].Txid != want {
			t.Fatalf("position %d: want %s, got %s (default sort should be desc CreatedAt)", i, want, got[i].Txid)
		}
	}
}

// TestSHIPStorage_ExplicitAscDescSort confirms the sortOrder override
// works in both directions, including the boundary where FindRecord
// (with filters) honors the same sort as FindAll.
func TestSHIPStorage_ExplicitAscDescSort(t *testing.T) {
	stepClock(t)
	ctx := context.Background()
	s := NewSHIPStorage(newTestDB(t))
	_ = s.StoreSHIPRecord(ctx, "txA", 0, "k", "https://h.test", "tm_uhrp")
	_ = s.StoreSHIPRecord(ctx, "txB", 0, "k", "https://h.test", "tm_uhrp")
	_ = s.StoreSHIPRecord(ctx, "txC", 0, "k", "https://h.test", "tm_uhrp")

	gotAsc, err := s.FindAll(ctx, nil, nil, ptrSort(types.SortOrderAsc))
	if err != nil {
		t.Fatalf("FindAll asc: %v", err)
	}
	if len(gotAsc) != 3 || gotAsc[0].Txid != "txA" || gotAsc[2].Txid != "txC" {
		t.Fatalf("asc sort expected txA,txB,txC, got %+v", gotAsc)
	}

	gotDesc, err := s.FindAll(ctx, nil, nil, ptrSort(types.SortOrderDesc))
	if err != nil {
		t.Fatalf("FindAll desc: %v", err)
	}
	if len(gotDesc) != 3 || gotDesc[0].Txid != "txC" || gotDesc[2].Txid != "txA" {
		t.Fatalf("desc sort expected txC,txB,txA, got %+v", gotDesc)
	}

	// FindRecord must honor the same sort contract as FindAll.
	gotFiltered, err := s.FindRecord(ctx, types.SHIPQuery{
		Topics:    []string{"tm_uhrp"},
		SortOrder: ptrSort(types.SortOrderAsc),
	})
	if err != nil {
		t.Fatalf("FindRecord asc: %v", err)
	}
	if len(gotFiltered) != 3 || gotFiltered[0].Txid != "txA" {
		t.Fatalf("FindRecord asc expected txA first, got %+v", gotFiltered)
	}
}

// TestSLAPStorage_DefaultSortIsDescCreatedAt mirrors the SHIP version
// for the SLAP adapter. Same canonical contract, same regression risk.
func TestSLAPStorage_DefaultSortIsDescCreatedAt(t *testing.T) {
	stepClock(t)
	ctx := context.Background()
	s := NewSLAPStorage(newTestDB(t))
	_ = s.StoreSLAPRecord(ctx, "txA", 0, "k", "https://h.test", "ls_uhrp")
	_ = s.StoreSLAPRecord(ctx, "txB", 0, "k", "https://h.test", "ls_uhrp")
	_ = s.StoreSLAPRecord(ctx, "txC", 0, "k", "https://h.test", "ls_uhrp")

	got, err := s.FindAll(ctx, nil, nil, nil)
	if err != nil {
		t.Fatalf("FindAll: %v", err)
	}
	wantOrder := []string{"txC", "txB", "txA"}
	if len(got) != len(wantOrder) {
		t.Fatalf("expected %d hits, got %d (%+v)", len(wantOrder), len(got), got)
	}
	for i, want := range wantOrder {
		if got[i].Txid != want {
			t.Fatalf("position %d: want %s, got %s", i, want, got[i].Txid)
		}
	}
}

// TestSLAPStorage_ExplicitAscDescSort mirrors the SHIP asc/desc test.
func TestSLAPStorage_ExplicitAscDescSort(t *testing.T) {
	stepClock(t)
	ctx := context.Background()
	s := NewSLAPStorage(newTestDB(t))
	_ = s.StoreSLAPRecord(ctx, "txA", 0, "k", "https://h.test", "ls_uhrp")
	_ = s.StoreSLAPRecord(ctx, "txB", 0, "k", "https://h.test", "ls_uhrp")
	_ = s.StoreSLAPRecord(ctx, "txC", 0, "k", "https://h.test", "ls_uhrp")

	gotAsc, _ := s.FindAll(ctx, nil, nil, ptrSort(types.SortOrderAsc))
	if len(gotAsc) != 3 || gotAsc[0].Txid != "txA" {
		t.Fatalf("SLAP asc expected txA first, got %+v", gotAsc)
	}
	gotDesc, _ := s.FindAll(ctx, nil, nil, ptrSort(types.SortOrderDesc))
	if len(gotDesc) != 3 || gotDesc[0].Txid != "txC" {
		t.Fatalf("SLAP desc expected txC first, got %+v", gotDesc)
	}

	gotFiltered, err := s.FindRecord(ctx, types.SLAPQuery{
		Service:   ptrString("ls_uhrp"),
		SortOrder: ptrSort(types.SortOrderAsc),
	})
	if err != nil {
		t.Fatalf("SLAP FindRecord asc: %v", err)
	}
	if len(gotFiltered) != 3 || gotFiltered[0].Txid != "txA" {
		t.Fatalf("SLAP FindRecord asc expected txA first, got %+v", gotFiltered)
	}
}

// TestSHIPStorage_SortAppliesBeforeSkipLimit pins that sort happens
// BEFORE pagination, matching the canonical MongoDB query order. If
// skip/limit were applied before sort, a desc query with limit=2 would
// return arbitrary entries instead of the two newest.
func TestSHIPStorage_SortAppliesBeforeSkipLimit(t *testing.T) {
	stepClock(t)
	ctx := context.Background()
	s := NewSHIPStorage(newTestDB(t))
	// Store 5 records; expect default desc sort + limit=2 to yield the
	// two newest (E, D), not the two earliest (A, B).
	for _, txid := range []string{"txA", "txB", "txC", "txD", "txE"} {
		_ = s.StoreSHIPRecord(ctx, txid, 0, "k", "https://h.test", "tm_uhrp")
	}
	got, err := s.FindAll(ctx, ptrInt(2), nil, nil)
	if err != nil {
		t.Fatalf("FindAll: %v", err)
	}
	if len(got) != 2 || got[0].Txid != "txE" || got[1].Txid != "txD" {
		t.Fatalf("expected newest two (txE, txD) after default desc + limit=2, got %+v", got)
	}
}

func TestStorage_EnsureIndexesNoOp(t *testing.T) {
	ctx := context.Background()
	if err := NewSHIPStorage(newTestDB(t)).EnsureIndexes(ctx); err != nil {
		t.Fatalf("SHIP EnsureIndexes returned err: %v", err)
	}
	if err := NewSLAPStorage(newTestDB(t)).EnsureIndexes(ctx); err != nil {
		t.Fatalf("SLAP EnsureIndexes returned err: %v", err)
	}
}
