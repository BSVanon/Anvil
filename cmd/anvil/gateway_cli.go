package main

import (
	"flag"
	"fmt"
	"os"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/BSVanon/Anvil/internal/config"
)

// cmdGateway handles `anvil gateway ...` — the operator-facing surface for
// gateway mode: which sites this node serves, which other gateways it
// federates with directly, and this node's own identity/URLs for pairing
// with another gateway. No restart is ever needed for site changes (the
// running node hot-reloads the sites file); peer changes do restart the
// service, since they are rare (see gateway_cli_peers.go).
func cmdGateway(args []string) {
	if len(args) == 0 {
		printGatewayUsage()
		os.Exit(1)
	}
	switch args[0] {
	case "site":
		cmdGatewaySite(args[1:])
	case "peer":
		cmdGatewayPeer(args[1:])
	case "info":
		cmdGatewayInfo(args[1:])
	default:
		printGatewayUsage()
		os.Exit(1)
	}
}

func printGatewayUsage() {
	fmt.Fprintln(os.Stderr, `usage: anvil gateway <command> [args]

commands:
  site add <domain|origin>                     allow a site to be served
  site remove <domain|origin>                  stop serving a site
  site list                                    list allowed sites and their TXT status
  peer add <pubkey> <mesh-url> <overlay-url>   add or update a federated gateway peer
  peer remove <pubkey>                         remove a federated gateway peer
  peer list                                    list federated gateway peers
  info                                         this node's identity and URLs

every command accepts -config <path> (default: the same as "anvil info")`)
}

// checkGatewayEnabled is loadGatewayConfigOrFatal's pure check that
// [gateway] is actually enabled, split out so it returns an error
// instead of calling fatal — dropping this check is then a real,
// test-asserted regression rather than something only a manual CLI run
// would catch.
func checkGatewayEnabled(cfg *config.Config, configPath string) error {
	if !cfg.Gateway.Enabled {
		return fmt.Errorf("[gateway] enabled is not true in %s — this node is not configured as a gateway", configPath)
	}
	return nil
}

// loadGatewayConfigOrFatal loads configPath and confirms [gateway] is
// actually enabled — site/peer management on a node that isn't serving
// gateway traffic at all is almost certainly a mistake, so this fails
// fast with a clear message rather than silently editing files nothing
// reads.
func loadGatewayConfigOrFatal(configPath string) *config.Config {
	loadEnvFile(configPath)
	cfg, err := config.Load(configPath)
	if err != nil {
		fatal("config: " + err.Error())
	}
	if err := checkGatewayEnabled(cfg, configPath); err != nil {
		fatal(err.Error())
	}
	return cfg
}

// cmdGatewayInfo prints this node's identity key and the api_host/mesh
// URLs another gateway operator needs, plus the exact `peer add` command
// to run on their own gateway to federate with this one.
//
// The mesh URL is printed as ws:// (Anvil's mesh listener has no TLS of
// its own yet) and the overlay URL as https://api_host — matching
// ANVIL_GATEWAY_PEERS's own "overlay-https-url" labelling, on the
// assumption that whatever makes api_host reachable also terminates TLS
// for it; Anvil does not need to know how.
func cmdGatewayInfo(args []string) {
	fs := flag.NewFlagSet("gateway info", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to config file")
	_ = fs.Parse(args)

	cfg := loadGatewayConfigOrFatal(*configPath)
	if cfg.Identity.WIF == "" {
		fatal("no identity — ANVIL_IDENTITY_WIF not configured")
	}
	privKey, err := ec.PrivateKeyFromWif(cfg.Identity.WIF)
	if err != nil {
		fatal("invalid WIF: " + err.Error())
	}
	if cfg.Gateway.APIHost == "" {
		fatal("[gateway] api_host is empty")
	}
	identityHex := fmt.Sprintf("%x", privKey.PubKey().Compressed())
	meshURL := fmt.Sprintf("ws://%s%s", cfg.Gateway.APIHost, normalizePort(cfg.Node.Listen))
	overlayURL := "https://" + cfg.Gateway.APIHost

	fmt.Printf("Identity:     %s\n", identityHex)
	fmt.Printf("API host:     %s\n", cfg.Gateway.APIHost)
	fmt.Printf("Mesh URL:     %s\n", meshURL)
	fmt.Printf("Overlay URL:  %s\n", overlayURL)
	fmt.Println()
	fmt.Println("On the other gateway, run:")
	fmt.Printf("  sudo anvil gateway peer add %s %s %s\n", identityHex, meshURL, overlayURL)
}
