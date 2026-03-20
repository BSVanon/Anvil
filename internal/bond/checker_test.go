package bond

import (
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func TestCheckerNotRequired(t *testing.T) {
	c := NewChecker(0, "")
	if c.Required() {
		t.Fatal("checker with minSats=0 should not be required")
	}
	pk, _ := ec.NewPrivateKey()
	bal, err := c.VerifyBond(pk.PubKey())
	if err != nil {
		t.Fatalf("unexpected error when bond not required: %v", err)
	}
	if bal != 0 {
		t.Fatalf("expected 0 balance when not required, got %d", bal)
	}
}

func TestCheckerRequired(t *testing.T) {
	c := NewChecker(10000, "")
	if !c.Required() {
		t.Fatal("checker with minSats=10000 should be required")
	}
	if c.MinSats() != 10000 {
		t.Fatalf("expected MinSats=10000, got %d", c.MinSats())
	}
}

func TestCheckerRejectsUnfundedKey(t *testing.T) {
	// Generate a random key — will have no UTXOs on mainnet
	c := NewChecker(10000, "")
	pk, _ := ec.NewPrivateKey()
	_, err := c.VerifyBond(pk.PubKey())
	if err == nil {
		t.Fatal("expected error for unfunded random key")
	}
}

func TestAddressDerivation(t *testing.T) {
	pk, _ := ec.NewPrivateKey()
	addr, err := pubKeyToAddress(pk.PubKey())
	if err != nil {
		t.Fatalf("address derivation failed: %v", err)
	}
	if len(addr) < 25 || addr[0] != '1' {
		t.Fatalf("invalid P2PKH address: %s", addr)
	}
}
