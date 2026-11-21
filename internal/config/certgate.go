package config

import (
	"fmt"
	"time"

	certgatepolicy "github.com/BSVanon/Anvil/internal/certgate"
	"github.com/BurntSushi/toml"
)

const defaultRevocationRecheck = time.Hour

// CertGateConfig is the shared certificate-admission policy. The use
// switches are populated from their owning TOML sections by finalizeCertGate.
type CertGateConfig struct {
	Certifiers          []string            `toml:"certifiers"`
	Types               []string            `toml:"types"`
	RevealFields        map[string][]string `toml:"reveal_fields"`
	AllowUnrevocable    map[string]bool     `toml:"allow_unrevocable"`
	RevocationCheck     string              `toml:"revocation_check"`
	RevocationRecheck   string              `toml:"revocation_recheck"`
	SenderRequired      bool                `toml:"-"`
	RegistrationAllowed bool                `toml:"-"`
	revocationDuration  time.Duration
}

// RevocationRecheckDuration returns the validated recheck interval.
func (c CertGateConfig) RevocationRecheckDuration() time.Duration {
	if c.revocationDuration > 0 {
		return c.revocationDuration
	}
	return defaultRevocationRecheck
}

// Enabled reports whether a complete certificate policy is configured.
func (c CertGateConfig) Enabled() bool { return len(c.Certifiers) > 0 && len(c.Types) > 0 }

func finalizeCertGate(data []byte, cfg *Config) error {
	if err := validateChangedSectionValues(cfg); err != nil {
		return err
	}
	var uses struct {
		Messaging struct {
			RequireSenderCertificate bool `toml:"require_sender_certificate"`
		} `toml:"messaging"`
		Gateway struct {
			AllowRegistration bool `toml:"allow_registration"`
		} `toml:"gateway"`
	}
	meta, err := toml.Decode(string(data), &uses)
	if err != nil {
		return fmt.Errorf("parse certificate use config: %w", err)
	}
	c := &cfg.CertGate
	c.SenderRequired = uses.Messaging.RequireSenderCertificate
	c.RegistrationAllowed = uses.Gateway.AllowRegistration
	configured := meta.IsDefined("certgate")
	if c.SenderRequired && !configured {
		return fmt.Errorf("[messaging] require_sender_certificate requires [certgate]")
	}
	if c.RegistrationAllowed && !configured {
		return fmt.Errorf("[gateway] allow_registration requires [certgate]")
	}
	if c.RegistrationAllowed && !cfg.Gateway.Enabled {
		return fmt.Errorf("[gateway] allow_registration requires [gateway] enabled")
	}
	if c.RevocationCheck == "" {
		c.RevocationCheck = "strict"
	}
	if c.RevocationCheck != "strict" && c.RevocationCheck != "lazy" {
		return fmt.Errorf(`invalid certgate.revocation_check %q: must be "strict" or "lazy"`, c.RevocationCheck)
	}
	if c.RevocationRecheck == "" {
		c.RevocationRecheck = defaultRevocationRecheck.String()
	}
	d, err := time.ParseDuration(c.RevocationRecheck)
	if err != nil || d <= 0 {
		return fmt.Errorf("invalid certgate.revocation_recheck %q: must be a positive duration", c.RevocationRecheck)
	}
	c.revocationDuration = d
	if !configured {
		return nil
	}
	if err := certgatepolicy.ValidateConfig(certgatepolicy.Config{
		Certifiers: c.Certifiers, Types: c.Types, RevealFields: c.RevealFields,
		AllowUnrevocable: c.AllowUnrevocable, RevocationCheck: c.RevocationCheck,
		Recheck: c.revocationDuration,
	}); err != nil {
		return fmt.Errorf("invalid [certgate]: %w", err)
	}
	return nil
}
