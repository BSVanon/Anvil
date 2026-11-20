package gateway

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
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
