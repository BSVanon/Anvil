package config

import (
	"strings"
	"testing"
	"time"
)

const testCertificateType = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
const testCertifier = "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66"

func TestCertificateGateDefaultsAreOff(t *testing.T) {
	cfg, err := Load(writeTestConfig(t, t.TempDir(), "[node]\nname = \"test\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CertGate.Enabled() || cfg.CertGate.SenderRequired || cfg.CertGate.RegistrationAllowed {
		t.Fatalf("unset certificate gate became active: %+v", cfg.CertGate)
	}
	if cfg.CertGate.RevocationCheck != "strict" || cfg.CertGate.RevocationRecheckDuration() != time.Hour {
		t.Fatalf("certificate defaults = %+v", cfg.CertGate)
	}
}

func TestCertificateGateConfig(t *testing.T) {
	body := `[messaging]
require_sender_certificate = true
[gateway]
enabled = true
api_host = "gateway.example"
allow_registration = true
[certgate]
certifiers = ["` + testCertifier + `"]
types = ["` + testCertificateType + `"]
revocation_check = "lazy"
revocation_recheck = "30m"
[certgate.reveal_fields]
"` + testCertificateType + `" = ["role"]
[certgate.allow_unrevocable]
"` + testCertificateType + `" = true
`
	cfg, err := Load(writeTestConfig(t, t.TempDir(), body))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.CertGate.Enabled() || !cfg.CertGate.SenderRequired || !cfg.CertGate.RegistrationAllowed {
		t.Fatalf("certificate uses not loaded: %+v", cfg.CertGate)
	}
	if cfg.CertGate.RevocationCheck != "lazy" || cfg.CertGate.RevocationRecheckDuration() != 30*time.Minute {
		t.Fatalf("revocation policy = %+v", cfg.CertGate)
	}
	if got := cfg.CertGate.RevealFields[testCertificateType]; len(got) != 1 || got[0] != "role" || !cfg.CertGate.AllowUnrevocable[testCertificateType] {
		t.Fatalf("type policy not loaded: %+v", cfg.CertGate)
	}
}

func TestConfiguredCertificatePolicyDoesNotEnableAUse(t *testing.T) {
	body := "[gateway]\nenabled = true\napi_host = \"gateway.example\"\n[certgate]\ncertifiers = [\"" + testCertifier + "\"]\ntypes = [\"" + testCertificateType + "\"]\n"
	cfg, err := Load(writeTestConfig(t, t.TempDir(), body))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.CertGate.Enabled() || cfg.CertGate.SenderRequired || cfg.CertGate.RegistrationAllowed {
		t.Fatalf("configured policy enabled a use: %+v", cfg.CertGate)
	}
}

func TestCertificateGateLoadErrors(t *testing.T) {
	t.Run("sender switch without policy", func(t *testing.T) {
		path := writeTestConfig(t, t.TempDir(), "[messaging]\nrequire_sender_certificate = true\n")
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "requires [certgate]") {
			t.Fatalf("missing policy error = %v", err)
		}
	})
	t.Run("registration switch without policy", func(t *testing.T) {
		path := writeTestConfig(t, t.TempDir(), "[gateway]\nallow_registration = true\n")
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "requires [certgate]") {
			t.Fatalf("missing policy error = %v", err)
		}
	})
	t.Run("registration without gateway", func(t *testing.T) {
		body := "[gateway]\nallow_registration = true\n[certgate]\ncertifiers = [\"" + testCertifier + "\"]\ntypes = [\"" + testCertificateType + "\"]\n"
		if _, err := Load(writeTestConfig(t, t.TempDir(), body)); err == nil || !strings.Contains(err.Error(), "requires [gateway] enabled") {
			t.Fatalf("disabled gateway error = %v", err)
		}
	})
	t.Run("invalid configured policy", func(t *testing.T) {
		path := writeTestConfig(t, t.TempDir(), "[certgate]\ncertifiers = [\"not-a-key\"]\ntypes = [\"not-a-type\"]\n")
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "invalid [certgate]") {
			t.Fatalf("invalid policy error = %v", err)
		}
	})
}
