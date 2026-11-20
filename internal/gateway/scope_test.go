package gateway

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// graphContent is a controllable contentFetcher that serves a fixed graph
// of text inscriptions referencing each other, for exercising the scope
// scanner's bounds directly (no HTTP, no real content.Server).
type graphContent struct {
	mu    sync.Mutex
	nodes map[string]string // outpoint -> body (served as text/html)
	calls map[string]int
}

func newGraphContent() *graphContent {
	return &graphContent{nodes: map[string]string{}, calls: map[string]int{}}
}

func (g *graphContent) set(outpoint, body string) {
	g.nodes[outpoint] = body
}

func (g *graphContent) Inscription(_ context.Context, txid string, vout int) ([]byte, string, error) {
	op := txid + "_" + strconv.Itoa(vout)
	g.mu.Lock()
	g.calls[op]++
	g.mu.Unlock()
	body, ok := g.nodes[op]
	if !ok {
		return nil, "", fmt.Errorf("no such node: %s", op)
	}
	return []byte(body), "text/html", nil
}

func ref(outpoint string) string { return "/content/" + outpoint }

func TestScanScope_DepthBound(t *testing.T) {
	// A straight chain: node0 -> node1 -> node2 -> node3 -> node4 -> node5.
	g := newGraphContent()
	nodes := make([]string, 6)
	for i := range nodes {
		nodes[i] = testOutpoint(100+i, 0)
	}
	for i := 0; i < 5; i++ {
		g.set(nodes[i], "<html>"+ref(nodes[i+1])+"</html>")
	}
	g.set(nodes[5], "<html>leaf</html>")

	result := scanScope(context.Background(), g, nodes[0], nodes[0])

	// scopeMaxDepth=4: the root (depth 0) through depth-4 nodes are
	// reachable (5 levels: node0..node4); node5 sits at depth 5 and is
	// only discoverable by scanning node4, which this scan never expands
	// (depth 4 >= scopeMaxDepth stops expansion from it).
	for i := 0; i <= 4; i++ {
		if !result.has(nodes[i]) {
			t.Fatalf("expected node%d (depth %d) to be in scope", i, i)
		}
	}
	if result.has(nodes[5]) {
		t.Fatal("expected node5 (depth 5) to be out of scope — beyond scopeMaxDepth")
	}
}

func TestScanScope_CountBound(t *testing.T) {
	// One root fanning out to more references than scopeMaxOutpoints
	// allows.
	g := newGraphContent()
	root := testOutpoint(200, 0)
	const fanOut = scopeMaxOutpoints + 500

	var body strings.Builder
	body.WriteString("<html>")
	children := make([]string, fanOut)
	for i := 0; i < fanOut; i++ {
		children[i] = testOutpoint(201+i, 0)
		body.WriteString(ref(children[i]))
	}
	body.WriteString("</html>")
	g.set(root, body.String())

	result := scanScope(context.Background(), g, root, root)

	if len(result.set) != scopeMaxOutpoints {
		t.Fatalf("expected the scan to stop at exactly %d outpoints, got %d", scopeMaxOutpoints, len(result.set))
	}
	if !result.has(children[0]) {
		t.Fatal("expected the first-referenced child to be in scope")
	}
	if result.has(children[fanOut-1]) {
		t.Fatal("expected the last-referenced child (past the count bound) to be out of scope")
	}
}

func TestScanScope_BytesBound(t *testing.T) {
	// root -> child1 -> child3, root -> child2 -> child4. root and child1
	// are each padded to 20 MiB (> scopeMaxBytes/2), so fetching both
	// (40 MiB) crosses the 32 MiB bound before child2 is ever fetched —
	// child2 itself stays in scope (it WAS referenced, by root), but
	// child4 (only discoverable by fetching child2) must not be.
	g := newGraphContent()
	root := testOutpoint(300, 0)
	child1 := testOutpoint(301, 0)
	child2 := testOutpoint(302, 0)
	child3 := testOutpoint(303, 0)
	child4 := testOutpoint(304, 0)

	pad := strings.Repeat("x", 20<<20) // 20 MiB
	g.set(root, "<html>"+pad+ref(child1)+ref(child2)+"</html>")
	g.set(child1, "<html>"+pad+ref(child3)+"</html>")
	g.set(child2, "<html>"+ref(child4)+"</html>")
	g.set(child3, "<html>leaf</html>")
	g.set(child4, "<html>leaf</html>")

	result := scanScope(context.Background(), g, root, root)

	if !result.has(child1) || !result.has(child2) {
		t.Fatal("expected both of root's direct references to be in scope")
	}
	if !result.has(child3) {
		t.Fatal("expected child3 to be in scope: discovered while scanning child1, which fits under the bound")
	}
	if result.has(child4) {
		t.Fatal("expected child4 to be out of scope: only discoverable by scanning child2, which the bytes bound stops before fetching")
	}
}

func TestScanScope_RootsAlwaysInScopeEvenUnreferenced(t *testing.T) {
	g := newGraphContent()
	origin := testOutpoint(400, 0)
	latest := testOutpoint(400, 1)
	g.set(origin, "<html>no refs here</html>")
	g.set(latest, "<html>no refs here either</html>")

	result := scanScope(context.Background(), g, origin, latest)
	if !result.has(origin) || !result.has(latest) {
		t.Fatal("expected both the origin and the latest outpoint to be in scope unconditionally")
	}
}

func TestScanScope_NonTextContentIsNotScanned(t *testing.T) {
	g := newGraphContent()
	root := testOutpoint(500, 0)
	hidden := testOutpoint(501, 0)
	g.set(root, ref(hidden)) // raw bytes, but served as a binary type below

	// Override Inscription via a tiny wrapper to report a non-text type.
	binG := &binaryTypeContent{inner: g, binaryOutpoints: map[string]bool{root: true}}
	result := scanScope(context.Background(), binG, root, root)
	if result.has(hidden) {
		t.Fatal("expected a reference inside non-text (binary) content to never be scanned")
	}
}

type binaryTypeContent struct {
	inner           *graphContent
	binaryOutpoints map[string]bool
}

func (b *binaryTypeContent) Inscription(ctx context.Context, txid string, vout int) ([]byte, string, error) {
	data, _, err := b.inner.Inscription(ctx, txid, vout)
	if err != nil {
		return nil, "", err
	}
	op := txid + "_" + strconv.Itoa(vout)
	if b.binaryOutpoints[op] {
		return data, "application/octet-stream", nil
	}
	return data, "text/html", nil
}

func TestScopeCache_SingleflightOneScanPerKey(t *testing.T) {
	g := newGraphContent()
	root := testOutpoint(600, 0)
	child := testOutpoint(601, 0)
	g.set(root, "<html>"+ref(child)+"</html>")
	g.set(child, "<html>leaf</html>")

	sc := newScopeCache(g)
	const n = 20
	var wg sync.WaitGroup
	results := make([]bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// A non-root target forces an actual scan (root/latest alone
			// would take InScope's trivial-match shortcut and never scan).
			results[i] = sc.InScope(context.Background(), root, root, child)
		}(i)
	}
	wg.Wait()

	for i, ok := range results {
		if !ok {
			t.Fatalf("caller %d: expected child to be in scope", i)
		}
	}
	g.mu.Lock()
	calls := g.calls[root]
	g.mu.Unlock()
	if calls != 1 {
		t.Fatalf("expected exactly 1 fetch of the root across %d concurrent InScope calls, got %d", n, calls)
	}
}

// TestScanScope_CompleteWhenFinishedNaturally confirms scanScope's new
// complete field: a scan that runs to its natural end (its queue empties
// before any bound is even approached) is complete — the ordinary case
// every other scope_test.go test already exercises, pinned explicitly here
// now that caching depends on it (R4).
func TestScanScope_CompleteWhenFinishedNaturally(t *testing.T) {
	g := newGraphContent()
	root := testOutpoint(700, 0)
	g.set(root, "<html>leaf</html>")

	result := scanScope(context.Background(), g, root, root)
	if !result.complete {
		t.Fatal("expected a scan that finishes within its bounds to be complete")
	}
}

// TestScanScope_IncompleteWhenContextDone confirms the other half of R4's
// caching gate: a scan whose context is already done before it can finish
// is marked incomplete, even though the roots it never got to expand are
// still (conservatively) in its returned set.
func TestScanScope_IncompleteWhenContextDone(t *testing.T) {
	g := newGraphContent()
	root := testOutpoint(701, 0)
	child := testOutpoint(702, 0)
	g.set(root, "<html>"+ref(child)+"</html>")
	g.set(child, "<html>leaf</html>")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already done before the scan starts

	result := scanScope(ctx, g, root, root)
	if result.complete {
		t.Fatal("expected a scan under an already-done context to be incomplete")
	}
	if !result.has(root) {
		t.Fatal("expected the root to still be in the (incomplete) result unconditionally")
	}
}

// blockingContent wraps a graphContent but blocks the fetch of one
// specific outpoint until released, so a test can deterministically
// cancel a caller's context WHILE the shared scan is in flight on a
// different, later outpoint.
type blockingContent struct {
	inner   *graphContent
	blockOn string
	started chan struct{} // closed once the blocking fetch begins
	release chan struct{} // closed to let the blocking fetch proceed
}

func (b *blockingContent) Inscription(ctx context.Context, txid string, vout int) ([]byte, string, error) {
	op := txid + "_" + strconv.Itoa(vout)
	if op == b.blockOn {
		close(b.started)
		<-b.release
	}
	return b.inner.Inscription(ctx, txid, vout)
}

// TestScopeCache_CallerCancellationDoesNotTruncateOrPoisonCache is R4's
// required test: the first caller cancels mid-scan, a second caller still
// gets the correct answer, and nothing truncated is cached.
//
// Chain: root -> slow -> tail -> deep. The shared scan blocks fetching
// `slow`; while blocked, the first caller's OWN context is cancelled.
// Before the fix, scanScope ran under that first caller's context, so the
// cancellation would make the very next loop iteration (fetching `tail`)
// see ctx.Err() != nil and stop there — `deep` (only discoverable by
// fetching tail) would never be found, and that truncated result would
// be cached forever. After the fix (R4's detached, independently-bounded
// context), the first caller's cancellation has no effect at all on the
// shared scan: it runs to completion, finds `deep`, and that complete
// result is what gets cached for every caller, including the one that
// cancelled.
func TestScopeCache_CallerCancellationDoesNotTruncateOrPoisonCache(t *testing.T) {
	g := newGraphContent()
	root := testOutpoint(800, 0)
	slow := testOutpoint(801, 0)
	tail := testOutpoint(802, 0)
	deep := testOutpoint(803, 0)
	g.set(root, "<html>"+ref(slow)+"</html>")
	g.set(slow, "<html>"+ref(tail)+"</html>")
	g.set(tail, "<html>"+ref(deep)+"</html>")
	g.set(deep, "<html>leaf</html>")

	blocking := &blockingContent{
		inner:   g,
		blockOn: slow,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	sc := newScopeCache(blocking)

	ctx1, cancel1 := context.WithCancel(context.Background())
	done1 := make(chan bool, 1)
	go func() {
		// `deep` is only reachable by scanning past `slow` and `tail`, so
		// this forces the full chain to be walked — it is not one of the
		// trivial root/latest matches InScope shortcuts.
		done1 <- sc.InScope(ctx1, root, root, deep)
	}()

	<-blocking.started // the shared scan is now blocked fetching `slow`
	cancel1()          // the FIRST caller cancels mid-scan
	time.Sleep(50 * time.Millisecond)
	close(blocking.release) // let the blocked fetch, and the scan, proceed

	if ok := <-done1; !ok {
		t.Fatal("expected the first (cancelling) caller to still get the correct, complete answer")
	}

	// A second caller must see the SAME correct, cached answer — not a
	// truncated one poisoned by the first caller's cancellation.
	if ok := sc.InScope(context.Background(), root, root, deep); !ok {
		t.Fatal("expected the second caller to get the correct answer from cache")
	}
}

// TestScopeCache_IncompleteResultIsNeverCached isolates R4's caching rule
// from the context-detachment mechanism above: a fetch error alone (no
// cancellation at all, plain context.Background() throughout) is enough
// to mark a scan incomplete, and an incomplete result must never be
// cached, regardless of why it was incomplete.
func TestScopeCache_IncompleteResultIsNeverCached(t *testing.T) {
	g := newGraphContent()
	root := testOutpoint(810, 0)
	missing := testOutpoint(811, 0) // referenced, but never g.set: its fetch errors
	g.set(root, "<html>"+ref(missing)+"</html>")

	sc := newScopeCache(g)

	sc.InScope(context.Background(), root, root, missing)
	g.mu.Lock()
	callsAfterFirst := g.calls[root]
	g.mu.Unlock()

	// A second call for the same (origin, latestOutpoint) key must re-scan
	// (re-fetching root) rather than reuse a cached-but-incomplete result.
	sc.InScope(context.Background(), root, root, missing)
	g.mu.Lock()
	callsAfterSecond := g.calls[root]
	g.mu.Unlock()

	if callsAfterSecond <= callsAfterFirst {
		t.Fatalf("expected the second call to re-scan rather than reuse a cached incomplete result: root fetches after first call=%d, after second=%d",
			callsAfterFirst, callsAfterSecond)
	}
}
