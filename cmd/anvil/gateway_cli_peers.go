package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/sitesfile"
)

// cmdGatewayPeer handles `anvil gateway peer add|remove|list`.
func cmdGatewayPeer(args []string) {
	if len(args) == 0 {
		printGatewayUsage()
		os.Exit(1)
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("gateway peer "+sub, flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to config file")
	_ = fs.Parse(rest)
	posArgs := fs.Args()

	cfg := loadGatewayConfigOrFatal(*configPath)

	switch sub {
	case "list":
		gatewayPeerList(*configPath)
	case "add":
		assertRoot()
		gatewayPeerAdd(cfg, *configPath, posArgs)
	case "remove":
		assertRoot()
		gatewayPeerRemove(cfg, *configPath, posArgs)
	default:
		printGatewayUsage()
		os.Exit(1)
	}
}

func gatewayPeerList(configPath string) {
	peers, err := readGatewayPeersBlock(configPath)
	if err != nil {
		fatal(err.Error())
	}
	if len(peers) == 0 {
		fmt.Println("no peers configured")
		return
	}
	for _, p := range peers {
		fmt.Printf("%s  %s  %s\n", p.PubKey, p.MeshURL, p.OverlayURL)
	}
}

func gatewayPeerAdd(cfg *config.Config, configPath string, posArgs []string) {
	if len(posArgs) != 3 {
		fatal("usage: anvil gateway peer add <pubkey> <mesh-url> <overlay-url>")
	}
	pubKey, err := validateGatewayPeerPubKey(posArgs[0])
	if err != nil {
		fatal(err.Error())
	}
	meshURL, err := validateGatewayPeerURL(posArgs[1], "ws", "wss")
	if err != nil {
		fatal(err.Error())
	}
	overlayURL, err := validateGatewayOverlayURL(posArgs[2])
	if err != nil {
		fatal(err.Error())
	}
	updated := gatewayPeer{PubKey: pubKey, MeshURL: meshURL, OverlayURL: overlayURL}

	var replaced bool
	err = applyGatewayPeers(configPath, func(peers []gatewayPeer) []gatewayPeer {
		for i, p := range peers {
			if p.PubKey == pubKey {
				peers[i] = updated
				replaced = true
				return peers
			}
		}
		replaced = false
		return append(peers, updated)
	})
	if err != nil {
		fatal(err.Error())
	}
	if replaced {
		fmt.Printf("updated peer %s\n", pubKey)
	} else {
		fmt.Printf("added peer %s\n", pubKey)
	}
	restartGatewayService(cfg)
}

func gatewayPeerRemove(cfg *config.Config, configPath string, posArgs []string) {
	if len(posArgs) != 1 {
		fatal("usage: anvil gateway peer remove <pubkey>")
	}
	pubKey, err := validateGatewayPeerPubKey(posArgs[0])
	if err != nil {
		fatal(err.Error())
	}

	var removed bool
	err = applyGatewayPeers(configPath, func(peers []gatewayPeer) []gatewayPeer {
		var kept []gatewayPeer
		for _, p := range peers {
			if p.PubKey == pubKey {
				removed = true
				continue
			}
			kept = append(kept, p)
		}
		return kept
	})
	if err != nil {
		fatal(err.Error())
	}
	if !removed {
		fmt.Printf("peer %s was not configured\n", pubKey)
		return
	}
	fmt.Printf("removed peer %s\n", pubKey)
	restartGatewayService(cfg)
}

// gatewayPeerLineRe matches one commented peer line inside the marked
// block: "# <pubkey>@<mesh-url>@<overlay-url>" (renderGatewayPeersBlock's
// exact format).
var gatewayPeerLineRe = regexp.MustCompile(`^#\s*([0-9a-fA-F]{66})@(\S+)@(\S+)$`)

// readGatewayPeersBlock extracts the current peer list from configPath's
// "# BEGIN gateway peers" / "# END gateway peers" marked block
// (deployGatewayNode / renderGatewayPeersBlock write it; this is its
// reader).
func readGatewayPeersBlock(configPath string) ([]gatewayPeer, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var peers []gatewayPeer
	inBlock := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case line == gatewayPeersBeginMarker:
			inBlock = true
		case line == gatewayPeersEndMarker:
			inBlock = false
		case inBlock:
			if m := gatewayPeerLineRe.FindStringSubmatch(line); m != nil {
				peers = append(peers, gatewayPeer{PubKey: strings.ToLower(m[1]), MeshURL: m[2], OverlayURL: m[3]})
			}
		}
	}
	return peers, scanner.Err()
}

// applyGatewayPeers reads configPath's current peer list, applies
// transform to compute the desired new list, and surgically rewrites
// the peer-derived fields — the marked block plus the four array lines
// deploy wrote from the same peer list ([mesh] seeds/allowed_peers,
// [overlay] named_peers, [bsv] header_fallback_peers) — to match,
// leaving every other line untouched: editing only the marked block and
// those four fields is this function's whole contract — every other
// operator customization in the file (node name, data dir, sites_file,
// api settings, ...) survives byte-for-byte because this never
// re-renders the file from a template, only patches the lines it owns.
//
// The read, transform and write all run inside one sitesfile.WithLock
// critical section, so two concurrent calls — two concurrent `peer add`s,
// say — can't each read the same starting list and then overwrite one
// another: the second call's transform always sees the first call's
// already-written result, never a stale one. If transform's result
// equals what it was given unchanged (a remove of a pubkey that wasn't
// there, say), the write is skipped entirely.
//
// This assumes the file already has the block and the four fields, which
// every config deployGatewayNode writes does (even with zero peers, as
// empty arrays and an empty block) — a gateway config not produced by
// `anvil deploy` is out of scope for v1.
func applyGatewayPeers(configPath string, transform func([]gatewayPeer) []gatewayPeer) error {
	return sitesfile.WithLock(configPath, func() error {
		current, err := readGatewayPeersBlock(configPath)
		if err != nil {
			return err
		}
		peers := transform(current)
		if peersEqual(current, peers) {
			return nil
		}

		info, err := os.Stat(configPath)
		if err != nil {
			return fmt.Errorf("stat config: %w", err)
		}
		data, err := os.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("read config: %w", err)
		}
		lines := strings.Split(string(data), "\n")

		out := make([]string, 0, len(lines))
		section := ""
		inBlock := false
		blockWritten := false
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			switch {
			case trimmed == gatewayPeersBeginMarker:
				inBlock = true
				out = append(out, strings.TrimRight(renderGatewayPeersBlock(peers), "\n"))
				blockWritten = true
				continue
			case trimmed == gatewayPeersEndMarker:
				inBlock = false
				continue
			case inBlock:
				continue
			}
			if sec, ok := tomlSectionHeader(trimmed); ok {
				section = sec
			}
			if replaced, ok := replaceGatewayPeerField(section, trimmed, peers); ok {
				out = append(out, replaced)
				continue
			}
			out = append(out, line)
		}
		if !blockWritten {
			out = append(out, "", strings.TrimRight(renderGatewayPeersBlock(peers), "\n"))
		}
		// A restart follows this write immediately (gatewayPeerAdd/Remove), so
		// a partial write here would break it: the same unique-temp-file,
		// fsync, rename, directory-fsync pattern the sites file uses, and the
		// existing file's own mode kept rather than a hardcoded one. newUID
		// and newGID are -1, -1 (unused): this file always already exists by
		// this point, so AtomicWriteFile's existing-file ownership copy is the
		// branch that applies, not these.
		return sitesfile.AtomicWriteFile(configPath, []byte(strings.Join(out, "\n")), info.Mode().Perm(), -1, -1)
	})
}

// peersEqual reports whether a and b list the same peers in the same
// order — applyGatewayPeers' signal to skip a write entirely when
// transform made no actual change.
func peersEqual(a, b []gatewayPeer) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// tomlSectionHeader reports whether trimmed is a "[section]" table header
// (not a "[[...]]" array-of-tables header) and, if so, its name.
func tomlSectionHeader(trimmed string) (string, bool) {
	if len(trimmed) > 2 && strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") && !strings.HasPrefix(trimmed, "[[") {
		return strings.TrimSuffix(strings.TrimPrefix(trimmed, "["), "]"), true
	}
	return "", false
}

// replaceGatewayPeerField rewrites one of the four peer-derived array
// lines in place when trimmed is exactly that "key = ..." line within the
// expected section (renderGatewayConfig writes each as a single line, so
// a plain key match is sufficient — no general TOML parser is needed).
// Any inline comment on the original line is not preserved.
func replaceGatewayPeerField(section, trimmed string, peers []gatewayPeer) (string, bool) {
	key, _, ok := strings.Cut(trimmed, "=")
	if !ok {
		return "", false
	}
	key = strings.TrimSpace(key)
	var value []string
	switch {
	case section == "mesh" && key == "seeds":
		value = peerMeshURLs(peers)
	case section == "mesh" && key == "allowed_peers":
		value = peerPubKeys(peers)
	case section == "overlay" && key == "named_peers":
		value = peerOverlayURLs(peers)
	case section == "bsv" && key == "header_fallback_peers":
		value = peerOverlayURLs(peers)
	default:
		return "", false
	}
	return fmt.Sprintf("%s = %s", key, tomlStringArray(value)), true
}

// restartGatewayService restarts cfg's systemd service, since peer
// changes (unlike site changes) are rare enough that a short
// interruption to apply one is acceptable. Reuses doctor.go's existing
// restart+verify helper rather than a second implementation.
func restartGatewayService(cfg *config.Config) {
	svc := guessServiceName(cfg)
	fmt.Printf("restarting %s...\n", svc)
	if err := applyServiceRestartAndVerify(svc); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
}
