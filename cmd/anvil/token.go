package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/BSVanon/Anvil/internal/config"
)

// cmdToken prints the derived API auth token for the configured identity.
// Usage: anvil token [-config /etc/anvil/node-a.toml]
func cmdToken(args []string) {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to config file")
	_ = fs.Parse(args)

	loadEnvFile(*configPath)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	if cfg.API.AuthToken == "" {
		fmt.Fprintln(os.Stderr, "no auth token — identity.wif not configured")
		os.Exit(1)
	}

	fmt.Println(cfg.API.AuthToken)
}
