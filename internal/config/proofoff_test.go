package config

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeProofConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "anvil.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestX402ProofSchemeDefaultsOff(t *testing.T) {
	cfg, err := Load(writeProofConfig(t, "[api]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.API.X402ProofScheme {
		t.Fatal("x402 proof scheme defaulted on")
	}
}

func TestX402ProofSchemeTrueParsesAndWarnsOnce(t *testing.T) {
	var logs bytes.Buffer
	oldWriter := log.Writer()
	oldFlags := log.Flags()
	oldPrefix := log.Prefix()
	log.SetOutput(&logs)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(oldWriter)
		log.SetFlags(oldFlags)
		log.SetPrefix(oldPrefix)
	})

	cfg, err := Load(writeProofConfig(t, "[api]\nx402_proof_scheme = true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.API.X402ProofScheme {
		t.Fatal("x402_proof_scheme=true did not parse")
	}
	const warning = "x402: x402_proof_scheme is deprecated and for development only"
	if strings.Count(logs.String(), warning) != 1 {
		t.Fatalf("deprecation warning count = %d: %q", strings.Count(logs.String(), warning), logs.String())
	}
}
