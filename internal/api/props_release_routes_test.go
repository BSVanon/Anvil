package api

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

type releaseRouteClass struct {
	operator, identity, payment, privateEnvelope, rateLimited, bodyBounded bool
}

func registeredReleaseRoutes(t *testing.T) map[string]struct{} {
	t.Helper()
	files := []string{
		"server.go", "brc31_messagebox.go", "certgate.go",
		"../overlay/v3engine/handlers.go", "../overlay/legacyshim/routes.go",
	}
	routes := make(map[string]struct{})
	for _, name := range files {
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc") {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			pattern, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatal(err)
			}
			routes[pattern] = struct{}{}
			return true
		})
	}

	file, err := parser.ParseFile(token.NewFileSet(), "../gateway/site.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(file, func(node ast.Node) bool {
		lit, ok := node.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		value, _ := strconv.Unquote(lit.Value)
		if value == "/" || value == "/content/" {
			routes["HOST "+value] = struct{}{}
		}
		return true
	})
	return routes
}

func releaseRouteClasses() map[string]releaseRouteClass {
	classes := make(map[string]releaseRouteClass)
	add := func(c releaseRouteClass, patterns ...string) {
		for _, pattern := range patterns {
			if _, exists := classes[pattern]; exists {
				panic("duplicate route classification: " + pattern)
			}
			classes[pattern] = c
		}
	}
	public := releaseRouteClass{rateLimited: true, bodyBounded: true}
	openRead := releaseRouteClass{operator: true, payment: true, rateLimited: true, bodyBounded: true}
	privateRead := openRead
	privateRead.privateEnvelope = true
	operator := releaseRouteClass{operator: true, bodyBounded: true}
	operatorOrPayment := releaseRouteClass{operator: true, payment: true, bodyBounded: true}
	none := releaseRouteClass{bodyBounded: true}
	identity := releaseRouteClass{operator: true, identity: true, rateLimited: true, bodyBounded: true}

	add(none, "GET /{$}", "GET /.well-known/x402", "GET /.well-known/x402-info",
		"GET /.well-known/identity", "GET /app/{name}", "GET /explorer", "POST /quote", "OPTIONS /quote", "OPTIONS /data")
	add(public, "GET /mesh/status", "GET /mesh/nodes", "GET /findHeaderHexForHeight",
		"GET /findHeaderHexForBlockHash", "GET /getPresentHeight", "GET /chaintracks/v2/network",
		"GET /chaintracks/v2/tip", "GET /chaintracks/v2/tip.bin", "GET /chaintracks/v2/tip/stream",
		"GET /chaintracks/v2/reorg/stream", "GET /chaintracks/v2/height",
		"GET /chaintracks/v2/header/height/{height}", "GET /chaintracks/v2/header/hash/{hash}",
		"GET /chaintracks/v2/headers", "GET /chaintracks/v2/headers.bin", "GET /tx/{txid}/status",
		"GET /.well-known/anvil")
	add(openRead, "GET /status", "GET /headers/tip", "GET /headers/range", "GET /tx/{txid}/beef",
		"GET /overlay/lookup", "GET /content/{origin}", "GET /mempool/watch", "GET /mempool/watch/history",
		"GET /mempool/watch/subscribe")
	add(privateRead, "GET /stats", "GET /data", "GET /data/subscribe", "GET /topics",
		"GET /topics/{topic...}", "GET /identity/{pubkey}")
	add(operator, "DELETE /data", "POST /bootstrap/block/{blockHash}", "POST /mempool/watch",
		"DELETE /mempool/watch", "POST /overlay/register", "POST /overlay/deregister", "POST /node/publish")
	add(operatorOrPayment, "POST /broadcast", "POST /data")

	add(identity, "/.well-known/auth", "/sendMessage", "/listMessages", "/acknowledgeMessage",
		"/messages/session", "POST /sendMessage", "POST /listMessages", "POST /acknowledgeMessage",
		"POST /messages/session", "GET /messages/subscribe")
	add(identity, "/gateway/sites", "/gateway/sites/", "POST /gateway/sites", "DELETE /gateway/sites/{domain}")

	add(none, "/submit", "/lookup", "/listTopicManagers", "/listLookupServiceProviders", "/arc-ingest",
		"/requestSyncResponse", "/requestForeignGASPNode", "OPTIONS /submit", "OPTIONS /lookup",
		"OPTIONS /arc-ingest", "OPTIONS /requestSyncResponse", "OPTIONS /requestForeignGASPNode",
		"POST /overlay/submit", "POST /overlay/query", "GET /overlay/topics", "GET /overlay/services",
		"OPTIONS /overlay/submit", "OPTIONS /overlay/query")
	add(releaseRouteClass{rateLimited: true, bodyBounded: true}, "HOST /", "HOST /content/")
	return classes
}

func TestEveryRegisteredRouteHasACompleteClassification(t *testing.T) {
	registered := registeredReleaseRoutes(t)
	classes := releaseRouteClasses()
	for route := range registered {
		if _, ok := classes[route]; !ok {
			t.Errorf("registered route is unclassified: %s", route)
		}
	}
	for route, class := range classes {
		if _, ok := registered[route]; !ok {
			t.Errorf("classification names no registered route: %s", route)
		}
		if !class.bodyBounded {
			t.Errorf("route has no bounded-body contract: %s", route)
		}
		if !class.operator && !class.identity && !class.payment && strings.HasPrefix(route, "POST /gateway/sites") {
			t.Errorf("certificate registration lost its identity requirement: %s", route)
		}
	}
	if t.Failed() {
		t.Log(fmt.Sprintf("registered=%d classified=%d", len(registered), len(classes)))
	}
}
