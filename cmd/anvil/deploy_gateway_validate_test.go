package main

import (
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// TestValidateGatewayDeployMode and TestValidateGatewayDeployAPIHost
// unit-test resolveGatewayDeployArgs's two pure checks directly, so
// dropping either one fails a real test instead of needing a manual CLI
// run to notice.

func TestValidateGatewayDeployMode(t *testing.T) {
	if err := validateGatewayDeployMode("standard"); err != nil {
		t.Errorf("standard: unexpected error: %v", err)
	}
	if err := validateGatewayDeployMode("gateway"); err != nil {
		t.Errorf("gateway: unexpected error: %v", err)
	}
	if err := validateGatewayDeployMode("bogus"); err == nil {
		t.Error("bogus mode: want an error, got nil")
	}
	if err := validateGatewayDeployMode(""); err == nil {
		t.Error("empty mode: want an error, got nil")
	}
}

func TestValidateGatewayDeployAPIHost(t *testing.T) {
	if err := validateGatewayDeployAPIHost("standard", ""); err != nil {
		t.Errorf("standard mode, no api-host: unexpected error: %v", err)
	}
	if err := validateGatewayDeployAPIHost("standard", "anything at all \" \n"); err != nil {
		t.Errorf("standard mode ignores api-host entirely: unexpected error: %v", err)
	}
	if err := validateGatewayDeployAPIHost("gateway", ""); err == nil {
		t.Error("gateway mode, empty api-host: want an error, got nil")
	}
	if err := validateGatewayDeployAPIHost("gateway", "gateway.example.org"); err != nil {
		t.Errorf("gateway mode, valid hostname: unexpected error: %v", err)
	}
	if err := validateGatewayDeployAPIHost("gateway", "203.0.113.5"); err == nil {
		t.Error("gateway mode, IP literal api-host: want an error, got nil")
	}

	// A quote-plus-newline value can break out of api_host = "%s" and
	// inject a TOML key config.Load would then accept. The hostname shape
	// check refuses it outright, before it ever reaches the config
	// template.
	injection := `gw.example.com"` + "\n" + `[rogue]` + "\n" + `evil = true`
	if err := validateGatewayDeployAPIHost("gateway", injection); err == nil {
		t.Error("gateway mode, quote-plus-newline injection api-host: want it refused, got nil error")
	}
}

func TestValidateGatewayDeployACME(t *testing.T) {
	if err := validateGatewayDeployACME("gateway", true, true, "ops@example.org"); err != nil {
		t.Errorf("valid gateway ACME settings: unexpected error: %v", err)
	}
	if err := validateGatewayDeployACME("standard", true, false, ""); err == nil {
		t.Error("standard mode with --acme-accept-tos: want an error, got nil")
	} else if !strings.Contains(err.Error(), "--mode gateway") {
		t.Errorf("standard mode terms error = %q, want clear gateway-mode guidance", err)
	}
	if err := validateGatewayDeployACME("standard", false, true, "ops@example.org"); err == nil {
		t.Error("standard mode with --acme-email: want an error, got nil")
	} else if !strings.Contains(err.Error(), "--mode gateway") {
		t.Errorf("standard mode email error = %q, want clear gateway-mode guidance", err)
	}
	for _, email := range []string{
		"ops.example.org",
		"ops @example.org",
		"ops@exam\nple.org",
		"ops@example.org\x00",
	} {
		if err := validateGatewayDeployACME("gateway", false, true, email); err == nil {
			t.Errorf("hostile email %q: want an error, got nil", email)
		}
	}
}

// TestRenderGatewayConfig_EscapesAnAPIHostInjectionAttempt is the
// defense-in-depth half of the same fix: even if a quote-plus-newline
// value somehow reached renderGatewayConfig directly (bypassing
// validateGatewayDeployAPIHost), the rendered TOML must still parse with
// api_host coming back as that exact literal string — not as a second,
// injected table — rather than relying solely on the earlier check.
func TestRenderGatewayConfig_EscapesAnAPIHostInjectionAttempt(t *testing.T) {
	injection := `gw.example.com"` + "\n" + `[rogue]` + "\n" + `evil = true` + "\n" + `api_host = "gw.example.com`
	rendered := renderGatewayConfig("a", "/var/lib/anvil", "/etc/anvil", injection, "golden-gateway", gatewayDeployArgs{})

	var doc struct {
		Gateway struct {
			APIHost string `toml:"api_host"`
		} `toml:"gateway"`
		Rogue struct {
			Evil bool `toml:"evil"`
		} `toml:"rogue"`
	}
	if _, err := toml.Decode(rendered, &doc); err != nil {
		t.Fatalf("rendered config did not even parse as TOML: %v\nrendered:\n%s", err, rendered)
	}
	if doc.Gateway.APIHost != injection {
		t.Errorf("api_host round-tripped to %q, want the exact original %q — the injection broke out of the string literal", doc.Gateway.APIHost, injection)
	}
	if doc.Rogue.Evil {
		t.Error("a [rogue] table with evil = true was actually parsed out of the rendered config — the injection succeeded")
	}
}

// TestTomlEscapeString_QuoteBackslashAndControlChars pins the escaper's
// behaviour on the characters that matter: ordinary text is untouched,
// and every character that could otherwise break out of or corrupt a
// TOML basic string round-trips through a real TOML parser to the exact
// original rune.
func TestTomlEscapeString_QuoteBackslashAndControlChars(t *testing.T) {
	if got := tomlEscapeString("plain-host.example.com"); got != "plain-host.example.com" {
		t.Errorf("ordinary text was altered: %q", got)
	}

	for _, raw := range []string{
		`a"b`,
		`a\b`,
		"a\nb",
		"a\rb",
		"a\tb",
		"a\"b\\c\nd",
	} {
		escaped := tomlEscapeString(raw)
		literal := `"` + escaped + `"`
		var doc struct{ V string }
		if _, err := toml.Decode("V = "+literal, &doc); err != nil {
			t.Errorf("tomlEscapeString(%q) = %q, which did not parse as a TOML string: %v", raw, escaped, err)
			continue
		}
		if doc.V != raw {
			t.Errorf("tomlEscapeString(%q) round-tripped to %q, want the original", raw, doc.V)
		}
	}
}
