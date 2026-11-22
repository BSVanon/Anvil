package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorUnavailableAPISkipsDependentChecks(t *testing.T) {
	if os.Getenv("ANVIL_DOCTOR_UNAVAILABLE_API_HELPER") == "1" {
		cmdDoctor([]string{"--no-fix", "--config", os.Getenv("ANVIL_DOCTOR_UNAVAILABLE_API_CONFIG")})
		return
	}

	dataDir := t.TempDir()
	for _, name := range []string{"headers", "envelopes", "overlay", "wallet", "invoices", "proofs"} {
		if err := os.Mkdir(filepath.Join(dataDir, name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(t.TempDir(), "anvil.toml")
	config := "[node]\n" +
		"data_dir = \"" + dataDir + "\"\n" +
		"api_listen = \"127.0.0.1:1\"\n" +
		"[identity]\n" +
		"wif = \"KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S\"\n" +
		"[bsv]\n" +
		"nodes = []\n" +
		"[arc]\n" +
		"enabled = false\n"
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestDoctorUnavailableAPISkipsDependentChecks$")
	cmd.Env = append(os.Environ(),
		"ANVIL_DOCTOR_UNAVAILABLE_API_HELPER=1",
		"ANVIL_DOCTOR_UNAVAILABLE_API_CONFIG="+configPath,
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("doctor exited successfully with no API listener")
	}
	text := string(out)
	if got := strings.Count(text, "API not responding at http://127.0.0.1:1:"); got != 1 {
		t.Fatalf("API failure lines = %d, want 1:\n%s", got, text)
	}
	for _, want := range []string{
		"systemctl status anvil-a",
		"CORS headers: API not answering (skipped)",
		"x402 discovery: API not answering (skipped)",
		"overlay health: API not answering (skipped)",
		"envelope store: API not answering (skipped)",
		"local mesh status: API not answering (skipped)",
		"wallet: API not answering (skipped)",
		"BRC-121: API not answering (skipped)",
		"payment paths: API not answering (skipped)",
		"header sync health: API not answering (skipped)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q:\n%s", want, text)
		}
	}
	for _, unwanted := range []string{
		"x402 discovery not responding",
		"wallet not responding",
		"BRC-121: failed to read",
		"priced routes have no available payment path",
	} {
		if strings.Contains(text, unwanted) {
			t.Errorf("unexpected dependent-check failure %q:\n%s", unwanted, text)
		}
	}
}
