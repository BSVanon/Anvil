package gateway

// The scope scan cache's amplification bound
// (a persistently failing reference costs at most one rescan per TTL
// window, and the per-outpoint negative-fetch cache that bound shares
// across different sites). Split out of scope_test.go, which already
// holds the scanScope/scopeCache fixtures (graphContent, ref,
// newGraphContent) these tests reuse, to keep both files under the
// project's bespoke-file line budget.

import (
	"context"
	"testing"
	"time"
)

// TestScopeCache_PersistentlyFailingReferenceRescansAtMostOncePerTTLWindow
// verifies that a scan whose only
// problem is one persistently failing reference must not pay for a full
// rescan on every single call — only the first call inside
// scopeIncompleteCacheTTL does the real work; a second call still inside
// that window reuses the cached incomplete result instead of re-scanning.
// This supersedes the old TestScopeCache_IncompleteResultIsNeverCached,
// which pinned the opposite, now-deliberately-changed behaviour: before
// this fix, an incomplete result was never cached at all, so every call
// re-scanned from scratch — up to scopeScanTimeout and scopeMaxOutpoints
// fetches each time a request hit a site with one broken reference, and
// if the failure was a transient upstream 429, every one of those
// rescans' fetches fed back into the very rate limit causing it.
func TestScopeCache_PersistentlyFailingReferenceRescansAtMostOncePerTTLWindow(t *testing.T) {
	g := newGraphContent()
	root := testOutpoint(810, 0)
	missing := testOutpoint(811, 0) // referenced, but never g.set: its fetch errors
	g.set(root, "<html>"+ref(missing)+"</html>")

	sc := newScopeCache(g)

	sc.InScope(context.Background(), root, root, missing)
	g.mu.Lock()
	callsAfterFirst := g.calls[root]
	g.mu.Unlock()

	// A second call for the same (origin, latestOutpoint) key, still
	// inside the TTL, must reuse the cached incomplete result rather than
	// re-scan (re-fetching root).
	sc.InScope(context.Background(), root, root, missing)
	g.mu.Lock()
	callsAfterSecond := g.calls[root]
	g.mu.Unlock()

	if callsAfterSecond != callsAfterFirst {
		t.Fatalf("expected the second call, still inside the TTL, to reuse the cached incomplete result rather than re-scan: root fetches after first call=%d, after second=%d",
			callsAfterFirst, callsAfterSecond)
	}
}

// TestScopeCache_IncompleteResultExpiresAndRecoversWhenHealthy is fix
// verifies that once scopeIncompleteCacheTTL
// has passed, a reference that has since started working again gets the
// full, correct answer — the short TTL bounds the cost of a failure, it
// does not wedge a site into a permanently-incomplete scope the way
// caching the incomplete result forever would.
func TestScopeCache_IncompleteResultExpiresAndRecoversWhenHealthy(t *testing.T) {
	g := newGraphContent()
	root := testOutpoint(820, 0)
	flaky := testOutpoint(821, 0) // not set yet: its first fetch errors
	recovered := testOutpoint(822, 0)
	g.set(root, "<html>"+ref(flaky)+"</html>")

	sc := newScopeCache(g)
	clock := time.Now()
	sc.now = func() time.Time { return clock }

	if ok := sc.InScope(context.Background(), root, root, recovered); ok {
		t.Fatal("expected recovered to be out of scope while flaky still fails to resolve it")
	}

	// flaky starts working, and now references recovered — but this
	// can't be discovered until the cached incomplete result expires.
	g.set(flaky, "<html>"+ref(recovered)+"</html>")
	clock = clock.Add(scopeIncompleteCacheTTL + time.Second)

	if ok := sc.InScope(context.Background(), root, root, recovered); !ok {
		t.Fatal("expected a rescan after the TTL to find recovered, now that flaky resolves correctly")
	}
}

// TestScopeCache_FailedOutpointFetchIsNegativelyCachedAcrossOrigins is
// verifies the per-outpoint negative-fetch
// cache (negativeCachingFetcher) is shared across different (origin,
// latestOutpoint) keys, not scoped to one site's own result cache — two
// different sites that both reference the very same broken outpoint must
// not each pay for their own fetch of it. Site B's scan is a cache miss
// at the outer scopeCache level (a distinct key from site A's), so this
// isolates the negative-fetch cache's own effect from the outer
// incomplete-result cache the two tests above already cover.
func TestScopeCache_FailedOutpointFetchIsNegativelyCachedAcrossOrigins(t *testing.T) {
	g := newGraphContent()
	siteA := testOutpoint(830, 0)
	siteB := testOutpoint(831, 0)
	brokenRef := testOutpoint(832, 0) // referenced by both sites, never set: always errors
	g.set(siteA, "<html>"+ref(brokenRef)+"</html>")
	g.set(siteB, "<html>"+ref(brokenRef)+"</html>")

	sc := newScopeCache(g)

	sc.InScope(context.Background(), siteA, siteA, brokenRef)
	g.mu.Lock()
	callsAfterSiteA := g.calls[brokenRef]
	g.mu.Unlock()
	if callsAfterSiteA != 1 {
		t.Fatalf("expected exactly 1 fetch of the broken reference from site A's scan, got %d", callsAfterSiteA)
	}

	sc.InScope(context.Background(), siteB, siteB, brokenRef)
	g.mu.Lock()
	callsAfterSiteB := g.calls[brokenRef]
	g.mu.Unlock()
	if callsAfterSiteB != callsAfterSiteA {
		t.Fatalf("expected site B's scan to reuse the shared negative cache rather than retry the broken reference: calls after site A=%d, after site B=%d",
			callsAfterSiteA, callsAfterSiteB)
	}
}
