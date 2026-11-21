package config

import (
	"os"
	"strings"
	"testing"
)

func TestPaymentDocumentationDescribesProofOffContract(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	assertContains := func(name, body string, fragments ...string) {
		t.Helper()
		for _, fragment := range fragments {
			if !strings.Contains(body, fragment) {
				t.Errorf("%s does not contain %q", name, fragment)
			}
		}
	}

	docs := read("../../docs/PAYMENTS.md")
	assertContains("payment documentation", docs,
		"off by default",
		"[api] x402_proof_scheme = true",
		"ERR_PAYMENT_REQUIRED",
		"ERR_PROOF_PAYMENT_UNAVAILABLE",
		"no challenge coin is minted",
	)

	example := read("../../anvil.example.toml")
	assertContains("example configuration", example,
		"x402_proof_scheme = false",
		"Set x402_proof_scheme = true",
		"ERR_PAYMENT_REQUIRED",
		"ERR_PROOF_PAYMENT_UNAVAILABLE",
		"no challenge coin is minted",
	)
}
