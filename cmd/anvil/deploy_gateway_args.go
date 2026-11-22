package main

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/BSVanon/Anvil/internal/sitesfile"
)

type gatewayDeployArgs struct {
	Peers         []gatewayPeer
	ACMEAcceptTOS bool
	ACMEEmail     string
}

// validateGatewayDeployMode is resolveGatewayDeployArgs's pure check on
// --mode alone, split out so it returns an error instead of calling
// fatal — dropping this check is then a real, test-asserted regression
// rather than something only a manual CLI run would catch.
func validateGatewayDeployMode(mode string) error {
	if mode != "standard" && mode != "gateway" {
		return fmt.Errorf("--mode must be standard or gateway")
	}
	return nil
}

// validateGatewayDeployAPIHost is resolveGatewayDeployArgs's pure check
// on --api-host: required in gateway mode (there is no [node] public_url
// for internal/config.Load to default it from — gateway mode never sets
// one), and shaped like a hostname — the same rule
// internal/sitesfile.ValidateDomain applies to a site domain, so IP
// literals and anything but ASCII LDH labels are refused here too. In
// standard mode apiHost is unused, so nothing is checked.
func validateGatewayDeployAPIHost(mode, apiHost string) error {
	if mode != "gateway" {
		return nil
	}
	if apiHost == "" {
		return fmt.Errorf("--mode gateway requires --api-host (there is no [node] public_url for internal/config.Load to default it from — gateway mode never sets one)")
	}
	if _, ok := sitesfile.ValidateDomain(apiHost); !ok {
		return fmt.Errorf("--api-host %q is not a valid hostname: no IP literals, ASCII LDH labels only", apiHost)
	}
	return nil
}

// validateGatewayDeployACME ensures ACME settings only affect new gateway
// configs and that an account contact cannot corrupt the generated TOML.
func validateGatewayDeployACME(mode string, acceptTOSSet, emailSet bool, email string) error {
	if mode != "gateway" && (acceptTOSSet || emailSet) {
		if acceptTOSSet && emailSet {
			return fmt.Errorf("--acme-accept-tos and --acme-email are only valid with --mode gateway")
		}
		if acceptTOSSet {
			return fmt.Errorf("--acme-accept-tos is only valid with --mode gateway")
		}
		return fmt.Errorf("--acme-email is only valid with --mode gateway")
	}
	if !emailSet {
		return nil
	}
	if !strings.Contains(email, "@") || strings.IndexFunc(email, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) >= 0 {
		return fmt.Errorf("--acme-email must contain @ and no whitespace or control characters")
	}
	return nil
}

// resolveGatewayDeployArgs validates `anvil deploy`'s gateway-mode flags
// and parses --gateway-peers, failing fast with a clear message rather
// than writing a config internal/config.Load would only reject once the
// daemon tries to start.
func resolveGatewayDeployArgs(mode, apiHost, gatewayPeersRaw string, acmeAcceptTOS bool, acmeEmail string, acmeAcceptTOSSet, acmeEmailSet bool) gatewayDeployArgs {
	if err := validateGatewayDeployMode(mode); err != nil {
		fatal(err.Error())
	}
	if err := validateGatewayDeployACME(mode, acmeAcceptTOSSet, acmeEmailSet, acmeEmail); err != nil {
		fatal(err.Error())
	}
	peers, err := parseGatewayPeers(gatewayPeersRaw)
	if err != nil {
		fatal("--gateway-peers: " + err.Error())
	}
	if err := validateGatewayDeployAPIHost(mode, apiHost); err != nil {
		fatal(err.Error())
	}
	return gatewayDeployArgs{Peers: peers, ACMEAcceptTOS: acmeAcceptTOS, ACMEEmail: acmeEmail}
}
