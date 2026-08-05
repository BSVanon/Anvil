package main

import (
	"fmt"
)

// cmdHelp prints a quick reference of common Anvil commands.
// Usage: anvil help
func cmdHelp(args []string) {
	const (
		cyan   = "\033[0;36m"
		yellow = "\033[1;33m"
		bold   = "\033[1m"
		dim    = "\033[2m"
		green  = "\033[0;32m"
		nc     = "\033[0m"
	)

	fmt.Println()
	fmt.Printf("  %s▄▀█ █▄░█ █░█ █ █░░%s\n", bold, nc)
	fmt.Printf("  %s█▀█ █░▀█ ▀▄▀ █ █▄▄%s  Quick Reference\n", bold, nc)
	fmt.Println()
	fmt.Printf("  %s─────────────────────────────────────────────────────%s\n", dim, nc)
	fmt.Println()
	fmt.Printf("  %sNODE INFO%s\n", bold, nc)
	fmt.Println()
	fmt.Printf("    %ssudo anvil info%s\n", cyan, nc)
	fmt.Printf("    %sShows your identity key, funding address, and auth token.%s\n", dim, nc)
	fmt.Println()
	fmt.Printf("  %s─────────────────────────────────────────────────────%s\n", dim, nc)
	fmt.Println()
	fmt.Printf("  %sFUNDING%s\n", bold, nc)
	fmt.Println()
	fmt.Printf("    %s1.%s Get your funding address:\n", green, nc)
	fmt.Printf("       %ssudo anvil info%s\n", cyan, nc)
	fmt.Println()
	fmt.Printf("    %s2.%s Send BSV to that address (1,000,000 sats recommended)\n", green, nc)
	fmt.Println()
	fmt.Printf("    %s3.%s After 1 confirmation, import the funds:\n", green, nc)
	fmt.Printf("       %sTOKEN=$(sudo anvil token)%s\n", cyan, nc)
	fmt.Printf("       %scurl -X POST http://localhost:9333/wallet/scan \\%s\n", cyan, nc)
	fmt.Printf("       %s  -H \"Authorization: Bearer $TOKEN\"%s\n", cyan, nc)
	fmt.Println()
	fmt.Printf("    %sRun the scan command any time you send more funds.%s\n", dim, nc)
	fmt.Println()
	fmt.Printf("  %s─────────────────────────────────────────────────────%s\n", dim, nc)
	fmt.Println()
	fmt.Printf("  %sOPERATIONS%s\n", bold, nc)
	fmt.Println()
	fmt.Printf("    %ssudo anvil upgrade%s                            Download latest + restart\n", cyan, nc)
	fmt.Printf("    %ssudo anvil upgrade --check%s                    Check for updates\n", cyan, nc)
	fmt.Printf("    %scurl -s http://localhost:9333/status%s          Node status\n", cyan, nc)
	fmt.Printf("    %scurl -s http://localhost:9333/mesh/status%s     Live mesh activity\n", cyan, nc)
	fmt.Printf("    %ssudo journalctl -u anvil-a -f%s                 Live logs\n", cyan, nc)
	fmt.Printf("    %ssudo systemctl restart anvil-a%s                Restart\n", cyan, nc)
	fmt.Printf("    %ssudo systemctl stop anvil-a%s                   Stop\n", cyan, nc)
	fmt.Printf("    %ssudo anvil doctor%s                             Diagnostics\n", cyan, nc)
	fmt.Println()
	fmt.Printf("  %s─────────────────────────────────────────────────────%s\n", dim, nc)
	fmt.Println()
	fmt.Printf("  %sFILES%s\n", bold, nc)
	fmt.Println()
	fmt.Printf("    /etc/anvil/node-a.toml      %sNode configuration%s\n", dim, nc)
	fmt.Printf("    /etc/anvil/node-a.env       %sPrivate key (WIF) — KEEP SAFE%s\n", dim, nc)
	fmt.Printf("    /var/lib/anvil/             %sData directory%s\n", dim, nc)
	fmt.Println()
	fmt.Printf("  %s─────────────────────────────────────────────────────%s\n", dim, nc)
	fmt.Println()
	fmt.Printf("  %sNETWORKING%s\n", bold, nc)
	fmt.Println()
	fmt.Printf("    Port 8333   %sMesh peering (WebSocket)%s\n", dim, nc)
	fmt.Printf("    Port 9333   %sREST API (HTTP)%s\n", dim, nc)
	fmt.Println()
	fmt.Printf("    %sOpen both in your firewall for full mesh participation.%s\n", dim, nc)
	fmt.Println()
}
