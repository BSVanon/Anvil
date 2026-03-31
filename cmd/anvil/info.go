package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BSVanon/Anvil/internal/config"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	bsvscript "github.com/bsv-blockchain/go-sdk/script"
)

// cmdInfo prints the node's identity public key and P2PKH funding address.
// Usage: anvil info [-config /etc/anvil/node-a.toml] [-json]
//
// Automatically loads the matching .env file (node-a.toml → node-a.env)
// so it works the same way as the systemd service.
func cmdInfo(args []string) {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to config file")
	jsonOut := fs.Bool("json", false, "output as JSON")
	_ = fs.Parse(args)

	// Auto-load the matching env file (e.g. node-a.toml → node-a.env)
	loadEnvFile(*configPath)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	if cfg.Identity.WIF == "" {
		fmt.Fprintln(os.Stderr, "no identity — ANVIL_IDENTITY_WIF not configured")
		os.Exit(1)
	}

	privKey, err := ec.PrivateKeyFromWif(cfg.Identity.WIF)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid WIF: %v\n", err)
		os.Exit(1)
	}

	pubKey := privKey.PubKey()
	identityHex := fmt.Sprintf("%x", pubKey.Compressed())

	addr, err := bsvscript.NewAddressFromPublicKey(pubKey, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "address derivation failed: %v\n", err)
		os.Exit(1)
	}

	if *jsonOut {
		out := map[string]string{
			"identity_key": identityHex,
			"address":      addr.AddressString,
			"auth_token":   cfg.API.AuthToken,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	} else {
		fmt.Printf("Identity:  %s\n", identityHex)
		fmt.Printf("Address:   %s\n", addr.AddressString)
		fmt.Printf("Token:     %s\n", cfg.API.AuthToken)
	}
}

// defaultConfigPath returns the most likely config file path.
// Checks /etc/anvil/node-a.toml first, then falls back to anvil.toml in cwd.
func defaultConfigPath() string {
	if _, err := os.Stat("/etc/anvil/node-a.toml"); err == nil {
		return "/etc/anvil/node-a.toml"
	}
	return "anvil.toml"
}

// loadEnvFile reads a simple KEY=VALUE env file and sets any values
// not already present in the environment. Derives the env file path
// from the config path: /etc/anvil/node-a.toml → /etc/anvil/node-a.env
func loadEnvFile(configPath string) {
	configDir := filepath.Dir(configPath)
	configBase := strings.TrimSuffix(filepath.Base(configPath), filepath.Ext(configPath))
	envPath := filepath.Join(configDir, configBase+".env")

	f, err := os.Open(envPath)
	if err != nil {
		return // env file is optional
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		// Don't override existing env vars
		if os.Getenv(key) == "" {
			_ = os.Setenv(key, val)
		}
	}
}
