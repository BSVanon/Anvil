package sitesfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestAdd_RefusesTheReservedHost(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sites.conf")

	entry, err := ParseEntry("gw.example.com")
	if err != nil {
		t.Fatal(err)
	}
	err = Add(path, entry, "GW.Example.Com.") // different case, trailing dot
	if err == nil {
		t.Fatal("Add: want refused for the reserved host, got nil error")
	}
	if !errors.Is(err, ErrReservedHost) {
		t.Errorf("Add error = %v, want it to wrap ErrReservedHost", err)
	}
	entries, rerr := Read(path)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if len(entries) != 0 {
		t.Errorf("a refused add still wrote an entry: %+v", entries)
	}
}

func TestAdd_AllowsADomainThatIsNotTheReservedHost(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sites.conf")

	entry, err := ParseEntry("site.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := Add(path, entry, "gw.example.com"); err != nil {
		t.Fatalf("Add: unexpected error: %v", err)
	}
	entries, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0] != entry {
		t.Errorf("got %+v, want [%+v]", entries, entry)
	}
}

func TestAdd_EmptyReservedHostReservesNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sites.conf")
	entry, err := ParseEntry("anything.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := Add(path, entry, ""); err != nil {
		t.Fatalf("Add with no reserved host: unexpected error: %v", err)
	}
}

func TestAdd_RejectsADuplicate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sites.conf")
	entry, err := ParseEntry("dup.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := Add(path, entry, ""); err != nil {
		t.Fatal(err)
	}
	if err := Add(path, entry, ""); err == nil {
		t.Fatal("second Add of the same entry: want an error, got nil")
	}
}

func TestRemove_DropsOnlyTheMatchingLineAndKeepsComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sites.conf")
	if err := os.WriteFile(path, []byte("# keep me\ndomain a.example.com\ndomain b.example.com\n"), 0640); err != nil {
		t.Fatal(err)
	}
	removed, err := Remove(path, Entry{Kind: "domain", Value: "a.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Fatal("Remove: want removed=true")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	if !strings.Contains(got, "# keep me") {
		t.Errorf("comment was dropped: %q", got)
	}
	if strings.Contains(got, "a.example.com") {
		t.Errorf("the matching entry is still present: %q", got)
	}
	if !strings.Contains(got, "b.example.com") {
		t.Errorf("the non-matching entry was dropped: %q", got)
	}
}

func TestRemove_MissingEntryReportsFalseNotError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sites.conf")
	removed, err := Remove(path, Entry{Kind: "domain", Value: "never-there.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if removed {
		t.Fatal("Remove on a missing file/entry: want removed=false")
	}
}

// TestAdd_ConcurrentDistinctEntriesAllSucceed proves the writer is safe
// to call concurrently: 20 concurrent adds of 20 DISTINCT entries must
// all succeed, with no spurious errors, and leave exactly 20 entries.
// An unlocked writer staging to a fixed filename, doing a plain
// read-check-read-append-write, loses most of these updates and raises
// spurious "already in file" errors under this same test.
func TestAdd_ConcurrentDistinctEntriesAllSucceed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sites.conf")

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			entry := Entry{Kind: "domain", Value: fmt.Sprintf("site%02d.example.com", i)}
			errs[i] = Add(path, entry, "")
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent Add #%d returned an unexpected error: %v", i, err)
		}
	}
	entries, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(entries) != n {
		t.Fatalf("got %d entries after %d concurrent adds, want %d: %+v", len(entries), n, n, entries)
	}
}

// TestAddRemove_ConcurrentMixLeavesAConsistentFile is the writer's other
// required concurrency property: concurrent adds mixed with concurrent
// removes must still leave the file consistent — every add that should
// have landed is present, every remove that should have landed is gone,
// nothing corrupted or duplicated.
func TestAddRemove_ConcurrentMixLeavesAConsistentFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sites.conf")

	const n = 10
	for i := 0; i < n; i++ {
		entry := Entry{Kind: "domain", Value: fmt.Sprintf("old%02d.example.com", i)}
		if err := Add(path, entry, ""); err != nil {
			t.Fatalf("seed Add: %v", err)
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			entry := Entry{Kind: "domain", Value: fmt.Sprintf("old%02d.example.com", i)}
			if _, err := Remove(path, entry); err != nil {
				t.Errorf("concurrent Remove #%d: %v", i, err)
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			entry := Entry{Kind: "domain", Value: fmt.Sprintf("new%02d.example.com", i)}
			if err := Add(path, entry, ""); err != nil {
				t.Errorf("concurrent Add #%d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	entries, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(entries) != n {
		t.Fatalf("got %d entries, want %d (every old removed, every new added): %+v", len(entries), n, entries)
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Value, "new") {
			t.Errorf("unexpected leftover entry: %+v", e)
		}
	}
}

func TestAtomicWriteFile_SetsThePermAndTheContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target.conf")
	if err := AtomicWriteFile(path, []byte("hello\n"), 0640); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello\n" {
		t.Errorf("content = %q", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Errorf("mode = %v, want 0640", info.Mode().Perm())
	}

	// A second write overwrites in place and leaves no staging file
	// behind.
	if err := AtomicWriteFile(path, []byte("world\n"), 0640); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "world\n" {
		t.Errorf("content after overwrite = %q", got)
	}
	leftovers, err := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Errorf("staging files left behind: %v", leftovers)
	}
}
