package gateway

import (
	"context"
	"strings"
	"testing"
)

func TestScanScope_ScansLatestTreeBeforeOlderVersions(t *testing.T) {
	g := newGraphContent()
	origin := testOutpoint(900, 0)
	latest := testOutpoint(901, 0)
	stylesheet := testOutpoint(902, 0)
	asset := testOutpoint(903, 0)
	olderOne := testOutpoint(904, 0)
	olderTwo := testOutpoint(905, 0)

	g.set(origin, "<html>origin</html>")
	g.set(latest, "<html>"+ref(stylesheet)+"</html>")
	g.set(stylesheet, ref(asset))
	g.setContentType(stylesheet, "text/css")
	g.set(asset, "asset")
	g.setContentType(asset, "image/png")
	for _, older := range []string{olderOne, olderTwo} {
		g.set(older, strings.Repeat("i", 17<<20))
		g.setContentType(older, "image/png")
	}

	result := scanScope(context.Background(), g, origin, latest, olderOne, olderTwo)

	if !result.has(asset) {
		t.Fatal("expected the latest version's CSS-referenced asset to be in scope")
	}
	if !result.complete {
		t.Fatal("expected reaching the bytes bound to remain complete")
	}
}

func TestScanScope_VersionRootsRemainInScopeWhenLatestExhaustsByteBudget(t *testing.T) {
	g := newGraphContent()
	origin := testOutpoint(906, 0)
	latest := testOutpoint(907, 0)
	stylesheet := testOutpoint(908, 0)
	stylesheetAsset := testOutpoint(909, 0)
	imageOne := testOutpoint(910, 0)
	imageTwo := testOutpoint(911, 0)
	olderOne := testOutpoint(912, 0)
	olderTwo := testOutpoint(913, 0)

	g.set(origin, "<html>origin</html>")
	g.set(latest, "<html>"+ref(stylesheet)+ref(imageOne)+ref(imageTwo)+"</html>")
	g.set(stylesheet, ref(stylesheetAsset))
	g.setContentType(stylesheet, "text/css")
	g.set(stylesheetAsset, "asset")
	g.setContentType(stylesheetAsset, "image/png")
	for _, image := range []string{imageOne, imageTwo} {
		g.set(image, strings.Repeat("i", 17<<20))
		g.setContentType(image, "image/png")
	}

	result := scanScope(context.Background(), g, origin, latest, olderOne, olderTwo)

	if !result.has(stylesheetAsset) {
		t.Fatal("expected the latest version's CSS-referenced asset to be in scope")
	}
	for _, older := range []string{olderOne, olderTwo} {
		if !result.has(older) {
			t.Fatalf("expected older version root %s to remain in scope", older)
		}
	}
	if !result.complete {
		t.Fatal("expected reaching the bytes bound to remain complete")
	}
}

func TestScanScope_ScansOlderVersionsAfterLatestTree(t *testing.T) {
	g := newGraphContent()
	origin := testOutpoint(910, 0)
	latest := testOutpoint(911, 0)
	older := testOutpoint(912, 0)
	olderAsset := testOutpoint(913, 0)

	g.set(origin, "<html>origin</html>")
	g.set(latest, "<html>latest</html>")
	g.set(older, "<html>"+ref(olderAsset)+"</html>")
	g.set(olderAsset, "asset")
	g.setContentType(olderAsset, "image/png")

	result := scanScope(context.Background(), g, origin, latest, older)

	if !result.has(older) || !result.has(olderAsset) {
		t.Fatal("expected an older version and its referenced asset to be in scope")
	}
	if !result.complete {
		t.Fatal("expected a scan within its bounds to be complete")
	}
}
