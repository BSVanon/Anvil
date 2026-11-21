package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/sitesfile"
)

// TestGatewaySiteAddEntry_RefusesTheConfigResolvedAPIHost verifies the
// required coverage: cmdGatewaySite hands gatewaySiteAdd (here,
// gatewaySiteAddEntry, its error-returning core) cfg.Gateway.APIHost —
// config.Load's own already-resolved value, not a hand-typed copy of
// the resolution rule — and that value must be refused as a site, the
// same way internal/config's own finalizeGateway refuses it as a
// pre-existing sites-file entry at load time. Covers both ways
// config.Load can arrive at that value: an explicit [gateway] api_host,
// and one defaulted from [node] public_url's host.
func TestGatewaySiteAddEntry_RefusesTheConfigResolvedAPIHost(t *testing.T) {
	cases := map[string]struct {
		body string
	}{
		"explicit api_host": {
			body: `
[node]
name = "a"
mode = "gateway"

[gateway]
enabled = true
api_host = "gw-explicit.example.org"
`,
		},
		"api_host derived from public_url": {
			body: `
[node]
name = "a"
mode = "gateway"
public_url = "https://gw-derived.example.org:9333"

[gateway]
enabled = true
`,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "node-a.toml")
			if err := os.WriteFile(configPath, []byte(c.body), 0644); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				t.Fatalf("config.Load: %v", err)
			}
			if cfg.Gateway.APIHost == "" {
				t.Fatal("test setup: cfg.Gateway.APIHost resolved empty")
			}

			_, err = gatewaySiteAddEntry(cfg.Gateway.SitesFile, cfg.Gateway.APIHost, []string{cfg.Gateway.APIHost})
			if err == nil {
				t.Fatalf("want the resolved api_host %q refused as a site, got nil error", cfg.Gateway.APIHost)
			}
			if !errors.Is(err, sitesfile.ErrReservedHost) {
				t.Errorf("error = %v, want it to wrap sitesfile.ErrReservedHost", err)
			}

			entries, err := sitesfile.Read(cfg.Gateway.SitesFile)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Errorf("a refused add still wrote an entry: %+v", entries)
			}
		})
	}
}

// TestGatewaySiteAddEntry_AllowsADomainOtherThanTheResolvedAPIHost is
// TestGatewaySiteAddEntry_RefusesTheConfigResolvedAPIHost's control:
// without it, that test could pass even if gatewaySiteAddEntry refused
// every domain unconditionally, proving nothing about api_host
// specifically.
func TestGatewaySiteAddEntry_AllowsADomainOtherThanTheResolvedAPIHost(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "node-a.toml")
	body := `
[node]
name = "a"
mode = "gateway"
public_url = "https://gw-derived.example.org:9333"

[gateway]
enabled = true
`
	if err := os.WriteFile(configPath, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	entry, err := gatewaySiteAddEntry(cfg.Gateway.SitesFile, cfg.Gateway.APIHost, []string{"served.example.com"})
	if err != nil {
		t.Fatalf("unexpected refusal for a domain that is not the resolved api_host: %v", err)
	}
	if entry.Kind != "domain" || entry.Value != "served.example.com" {
		t.Errorf("entry = %+v, want domain served.example.com", entry)
	}
}

func TestGatewaySiteListAndRemoveIncludeRegistrations(t *testing.T) {
	dir := t.TempDir()
	operatorPath := filepath.Join(dir, "operator.conf")
	registrationPath := filepath.Join(dir, "gateway-registrations.conf")
	identity := "02" + repeatByte('1', 64)
	if err := os.WriteFile(operatorPath, []byte("domain operator.example\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(registrationPath, []byte("domain registered.example  # registered-by "+identity+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	entries, err := gatewaySiteEntries(operatorPath, registrationPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].registered || !entries[1].registered || entries[1].Value != "registered.example" {
		t.Fatalf("entries = %#v", entries)
	}
	entry, removed, err := gatewaySiteRemoveEntry(operatorPath, registrationPath, []string{"registered.example"})
	if err != nil || !removed || entry.Value != "registered.example" {
		t.Fatalf("remove = %#v, %v, %v", entry, removed, err)
	}
	operator, _ := sitesfile.Read(operatorPath)
	registered, _ := sitesfile.Read(registrationPath)
	if len(operator) != 1 || len(registered) != 0 {
		t.Fatalf("operator = %#v, registered = %#v", operator, registered)
	}
}

func repeatByte(value byte, count int) string {
	b := make([]byte, count)
	for i := range b {
		b[i] = value
	}
	return string(b)
}
