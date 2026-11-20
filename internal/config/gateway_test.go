package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestConfig(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "anvil.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadGatewayDefaults(t *testing.T) {
	dir := t.TempDir()
	p := writeTestConfig(t, dir, "[node]\nname = \"test\"\n")

	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Gateway.Enabled {
		t.Fatal("expected gateway disabled by default")
	}
	if cfg.Gateway.TXTCacheTTL != defaultGatewayTXTCacheTTL {
		t.Fatalf("expected txt_cache_ttl=%d, got %d", defaultGatewayTXTCacheTTL, cfg.Gateway.TXTCacheTTL)
	}
	if cfg.Gateway.TXTStaleGrace != defaultGatewayTXTStaleGrace {
		t.Fatalf("expected txt_stale_grace=%d, got %d", defaultGatewayTXTStaleGrace, cfg.Gateway.TXTStaleGrace)
	}
	if cfg.Gateway.RootMaxAge != defaultGatewayRootMaxAge {
		t.Fatalf("expected root_max_age=%d, got %d", defaultGatewayRootMaxAge, cfg.Gateway.RootMaxAge)
	}
	if cfg.Gateway.ContentScope != "site" {
		t.Fatalf("expected content_scope=site, got %q", cfg.Gateway.ContentScope)
	}
	wantSites := filepath.Join(dir, "gateway-sites.conf")
	if cfg.Gateway.SitesFile != wantSites {
		t.Fatalf("expected sites_file=%q, got %q", wantSites, cfg.Gateway.SitesFile)
	}
	if cfg.Node.Mode != "" {
		t.Fatalf("expected empty mode, got %q", cfg.Node.Mode)
	}
}

func TestLoadGatewayExplicitValues(t *testing.T) {
	dir := t.TempDir()
	p := writeTestConfig(t, dir, `
[node]
name = "gw"
mode = "gateway"

[gateway]
enabled = true
api_host = "admin.example.org"
sites_file = "/custom/sites.conf"
txt_cache_ttl = 120
txt_stale_grace = 3600
root_max_age = 30
content_scope = "any"
`)

	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Gateway.Enabled {
		t.Fatal("expected gateway enabled")
	}
	if cfg.Node.Mode != "gateway" {
		t.Fatalf("expected mode=gateway, got %q", cfg.Node.Mode)
	}
	if cfg.Gateway.APIHost != "admin.example.org" {
		t.Fatalf("unexpected api_host %q", cfg.Gateway.APIHost)
	}
	if cfg.Gateway.SitesFile != "/custom/sites.conf" {
		t.Fatalf("explicit sites_file must not be overridden, got %q", cfg.Gateway.SitesFile)
	}
	if cfg.Gateway.TXTCacheTTL != 120 || cfg.Gateway.TXTStaleGrace != 3600 || cfg.Gateway.RootMaxAge != 30 {
		t.Fatalf("explicit numeric overrides not honoured: %+v", cfg.Gateway)
	}
	if cfg.Gateway.ContentScope != "any" {
		t.Fatalf("expected content_scope=any, got %q", cfg.Gateway.ContentScope)
	}
}

func TestLoadRejectsInvalidMode(t *testing.T) {
	dir := t.TempDir()
	p := writeTestConfig(t, dir, "[node]\nname = \"test\"\nmode = \"bogus\"\n")

	if _, err := Load(p); err == nil {
		t.Fatal("expected an error for an invalid [node] mode")
	}
}

func TestLoadStandardModeUnchanged(t *testing.T) {
	dir := t.TempDir()
	p := writeTestConfig(t, dir, "[node]\nname = \"test\"\nmode = \"standard\"\n")

	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Gateway.Enabled {
		t.Fatal("mode=standard must not itself enable [gateway] — only an installer decides that")
	}
}

// TestLoadGatewayAPIHostDefaultsFromPublicURL is D2's default-fill rule:
// api_host left unset is resolved from [node] public_url's host, so a
// gateway node needs no api_host of its own as long as public_url agrees.
func TestLoadGatewayAPIHostDefaultsFromPublicURL(t *testing.T) {
	dir := t.TempDir()
	p := writeTestConfig(t, dir, `
[node]
name = "gw"
public_url = "https://anvil.example.org"

[gateway]
enabled = true
`)

	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Gateway.APIHost != "anvil.example.org" {
		t.Fatalf("expected api_host to default from public_url's host, got %q", cfg.Gateway.APIHost)
	}
}

// TestLoadGatewayFailsWhenAPIHostAndPublicURLBothEmpty is D2: with
// [gateway] enabled, Load fails when api_host can't be resolved from
// anywhere — D1's Router has no wildcard any more, so an api_host-less
// gateway would be unreachable at its own API.
func TestLoadGatewayFailsWhenAPIHostAndPublicURLBothEmpty(t *testing.T) {
	dir := t.TempDir()
	p := writeTestConfig(t, dir, "[node]\nname = \"gw\"\n\n[gateway]\nenabled = true\n")

	if _, err := Load(p); err == nil {
		t.Fatal("expected an error when [gateway] is enabled with neither api_host nor public_url set")
	}
}

// TestLoadGatewayFailsWhenAPIHostAndPublicURLDisagree is D2: Load refuses
// an explicit api_host whose host doesn't match an explicit public_url's
// host, since overlay federation calls this node at public_url and a
// mismatch would make Router 404 it.
func TestLoadGatewayFailsWhenAPIHostAndPublicURLDisagree(t *testing.T) {
	dir := t.TempDir()
	p := writeTestConfig(t, dir, `
[node]
name = "gw"
public_url = "https://real.example.org"

[gateway]
enabled = true
api_host = "other.example.org"
`)

	if _, err := Load(p); err == nil {
		t.Fatal("expected an error when api_host and public_url's host disagree")
	}
}

// TestLoadGatewayFailsWhenAPIHostListedAsSite is D2's sites-file overlap
// rule: Load refuses a config whose sites file lists api_host itself as
// a "domain" entry — the API always wins, so a site entry for the same
// host is a misconfiguration, not a silent no-op.
func TestLoadGatewayFailsWhenAPIHostListedAsSite(t *testing.T) {
	dir := t.TempDir()
	// Written at the default sites_file path Load will resolve to
	// (next to anvil.toml), so the overlap check actually sees it.
	sitesPath := filepath.Join(dir, "gateway-sites.conf")
	if err := os.WriteFile(sitesPath, []byte("domain admin.example.org\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	p := writeTestConfig(t, dir, `
[node]
name = "gw"

[gateway]
enabled = true
api_host = "admin.example.org"
`)

	if _, err := Load(p); err == nil {
		t.Fatal("expected an error when the sites file lists api_host as a domain entry")
	}
}

// TestLoadRejectsInvalidContentScope is D3: only "", "site" or "any" are
// accepted for [gateway] content_scope; anything else fails Load, rather
// than silently falling back to "site" as it used to.
func TestLoadRejectsInvalidContentScope(t *testing.T) {
	dir := t.TempDir()
	p := writeTestConfig(t, dir, "[node]\nname = \"test\"\n\n[gateway]\ncontent_scope = \"anyy\"\n")

	if _, err := Load(p); err == nil {
		t.Fatal("expected an error for an invalid [gateway] content_scope")
	}
}

// TestLoadAcceptsValidContentScopeValues is D3's positive case, for both
// explicit values (empty/default is already covered by
// TestLoadGatewayDefaults and TestLoadGatewayExplicitValues).
func TestLoadAcceptsValidContentScopeValues(t *testing.T) {
	for _, scope := range []string{"site", "any"} {
		dir := t.TempDir()
		p := writeTestConfig(t, dir, "[node]\nname = \"test\"\n\n[gateway]\ncontent_scope = \""+scope+"\"\n")

		cfg, err := Load(p)
		if err != nil {
			t.Fatalf("content_scope=%q: unexpected error: %v", scope, err)
		}
		if cfg.Gateway.ContentScope != scope {
			t.Fatalf("content_scope=%q: got %q", scope, cfg.Gateway.ContentScope)
		}
	}
}
