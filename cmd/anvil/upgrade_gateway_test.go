package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// forbiddenUpgradeCalls are every function that renders or writes a node
// config or a gateway sites file. `anvil upgrade` must call none of
// them: upgrading a binary must never rewrite a gateway's configuration
// or its sites file. Checked structurally, over the whole of
// upgrade.go's AST, rather than by running cmdUpgrade end-to-end —
// which would need a real systemd + a real release to download.
var forbiddenUpgradeCalls = map[string]bool{
	"renderConfig":             true,
	"renderGatewayConfig":      true,
	"renderGatewayPeersBlock":  true,
	"deployNode":               true,
	"deployGatewayNode":        true,
	"deployAnyNode":            true,
	"resolveGatewayDeployArgs": true,
	"writeSitesFileAtomic":     true,
	"applyGatewayPeers":        true,
	"addSiteEntry":             true,
	"removeSiteEntry":          true,
}

// TestUpgradeNeverRewritesGatewayConfigOrSites parses upgrade.go's
// source and walks every call expression in it. Any call to a function
// that writes a node's TOML config or its gateway sites file fails the
// test, naming the call site.
func TestUpgradeNeverRewritesGatewayConfigOrSites(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "upgrade.go", nil, 0)
	if err != nil {
		t.Fatalf("parse upgrade.go: %v", err)
	}

	var hits []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		if forbiddenUpgradeCalls[ident.Name] {
			hits = append(hits, fset.Position(call.Pos()).String()+": "+ident.Name+"(...)")
		}
		return true
	})

	if len(hits) > 0 {
		t.Errorf("upgrade.go calls a config/sites-file-writing function — anvil upgrade must leave a gateway's config and sites file untouched:\n%s", strings.Join(hits, "\n"))
	}
}
