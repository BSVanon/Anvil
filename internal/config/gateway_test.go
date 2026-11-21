package config

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/acme/autocert"
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
	if cfg.Gateway.HTTPSListen != defaultGatewayHTTPSListen {
		t.Fatalf("expected https_listen=%q, got %q", defaultGatewayHTTPSListen, cfg.Gateway.HTTPSListen)
	}
	if cfg.Gateway.HTTPListen != defaultGatewayHTTPListen {
		t.Fatalf("expected http_listen=%q, got %q", defaultGatewayHTTPListen, cfg.Gateway.HTTPListen)
	}
	if cfg.Gateway.ACMEDirectory != defaultGatewayACMEDirectory {
		t.Fatalf("expected acme_directory=%q, got %q", defaultGatewayACMEDirectory, cfg.Gateway.ACMEDirectory)
	}
	if cfg.Gateway.ACMEEmail != "" {
		t.Fatalf("expected empty acme_email, got %q", cfg.Gateway.ACMEEmail)
	}
	if cfg.Gateway.AcceptTOS {
		t.Fatal("expected acme_accept_tos=false by default")
	}
}

// TestDefaultGatewayACMEDirectoryMatchesAutocert pins
// defaultGatewayACMEDirectory to autocert's own default, so this
// package's literal (kept local rather than importing autocert just for
// one constant — see GatewayConfig.ACMEDirectory's doc comment) can
// never silently drift from what golang.org/x/crypto/acme/autocert
// itself would use when [gateway] acme_directory is left unset.
func TestDefaultGatewayACMEDirectoryMatchesAutocert(t *testing.T) {
	if defaultGatewayACMEDirectory != autocert.DefaultACMEDirectory {
		t.Fatalf("defaultGatewayACMEDirectory = %q, want autocert.DefaultACMEDirectory = %q",
			defaultGatewayACMEDirectory, autocert.DefaultACMEDirectory)
	}
}

// TestLoadGatewayACMEExplicitValues confirms the ACME-specific fields
// round-trip through Load unchanged when set explicitly.
func TestLoadGatewayACMEExplicitValues(t *testing.T) {
	dir := t.TempDir()
	p := writeTestConfig(t, dir, `
[node]
name = "gw"

[gateway]
https_listen = ":8443"
http_listen = ":8080"
acme_directory = "https://pebble.example.org/dir"
acme_email = "ops@example.org"
acme_accept_tos = true
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Gateway.HTTPSListen != ":8443" {
		t.Fatalf("https_listen = %q, want :8443", cfg.Gateway.HTTPSListen)
	}
	if cfg.Gateway.HTTPListen != ":8080" {
		t.Fatalf("http_listen = %q, want :8080", cfg.Gateway.HTTPListen)
	}
	if cfg.Gateway.ACMEDirectory != "https://pebble.example.org/dir" {
		t.Fatalf("acme_directory = %q, want the configured override", cfg.Gateway.ACMEDirectory)
	}
	if cfg.Gateway.ACMEEmail != "ops@example.org" {
		t.Fatalf("acme_email = %q, want ops@example.org", cfg.Gateway.ACMEEmail)
	}
	if !cfg.Gateway.AcceptTOS {
		t.Fatal("acme_accept_tos = false, want true")
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

// TestLoadGatewayDisabledIgnoresAPIHostConflicts confirms that
// with [gateway] disabled, nothing gateway-related can stop a node from
// starting — a disagreeing api_host/public_url and an api_host also
// listed in the sites file are only real problems once the gateway is
// actually serving anything, the same reasoning the "both empty" check
// already applied. This combines both checks in one config, gateway off,
// to confirm Load succeeds through both.
func TestLoadGatewayDisabledIgnoresAPIHostConflicts(t *testing.T) {
	dir := t.TempDir()
	// The sites file lists the resolved host: since api_host is set
	// explicitly and non-empty, it is never defaulted from public_url, so
	// the "resolved" api_host stays "other.example.org" even though it
	// disagrees with public_url.
	sitesPath := filepath.Join(dir, "gateway-sites.conf")
	if err := os.WriteFile(sitesPath, []byte("domain other.example.org\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	p := writeTestConfig(t, dir, `
[node]
name = "gw"
public_url = "https://real.example.org"

[gateway]
api_host = "other.example.org"
`)

	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("expected Load to succeed with [gateway] disabled despite a disagreeing api_host and a sites-file overlap, got: %v", err)
	}
	if cfg.Gateway.APIHost != "other.example.org" {
		t.Fatalf("expected api_host to stay %q, got %q", "other.example.org", cfg.Gateway.APIHost)
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
