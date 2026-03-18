package brc

import (
	"encoding/hex"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
)

// Frozen fixtures from relay-federation derivation.test.js
const (
	fixtureWIF         = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S"
	fixtureIdentityPub = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
	// Canonical fixtures using go-sdk protocol IDs:
	// SHIP invoice = "2-service host interconnect-1"
	// SLAP invoice = "2-service lookup availability-1"
	fixtureSHIPChild = "03e05a6728208a45344c078aa042b670702fbdceba193307474ffe4f637b5b40c2"
	fixtureSLAPChild = "033df6e48e8ab2b6f37f6a5c8f085799a647de70682d98dcfbb9daadcd74dac0bf"
)

func loadFixtureKey(t *testing.T) *ec.PrivateKey {
	t.Helper()
	key, err := ec.PrivateKeyFromWif(fixtureWIF)
	if err != nil {
		t.Fatalf("load fixture WIF: %v", err)
	}
	pubHex := hex.EncodeToString(key.PubKey().Compressed())
	if pubHex != fixtureIdentityPub {
		t.Fatalf("fixture key mismatch: got %s", pubHex)
	}
	return key
}

// --- BRC-42 Derivation (via go-sdk ec.PrivateKey.DeriveChild) ---

func TestDeriveChildDeterminism(t *testing.T) {
	key := loadFixtureKey(t)
	anyonePub := AnyonePub()
	child1, err := DeriveChild(key, anyonePub, InvoiceSHIP)
	if err != nil {
		t.Fatal(err)
	}
	child2, err := DeriveChild(key, anyonePub, InvoiceSHIP)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(child1.PubKey().Compressed()) != hex.EncodeToString(child2.PubKey().Compressed()) {
		t.Fatal("derivation is not deterministic")
	}
}

func TestDeriveChildSHIPFixture(t *testing.T) {
	key := loadFixtureKey(t)
	child, err := DeriveChild(key, AnyonePub(), InvoiceSHIP)
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(child.PubKey().Compressed())
	if got != fixtureSHIPChild {
		t.Fatalf("SHIP child mismatch:\n  got  %s\n  want %s", got, fixtureSHIPChild)
	}
}

func TestDeriveChildSLAPFixture(t *testing.T) {
	key := loadFixtureKey(t)
	child, err := DeriveChild(key, AnyonePub(), InvoiceSLAP)
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(child.PubKey().Compressed())
	if got != fixtureSLAPChild {
		t.Fatalf("SLAP child mismatch:\n  got  %s\n  want %s", got, fixtureSLAPChild)
	}
}

func TestDeriveChildDifferentInvoices(t *testing.T) {
	key := loadFixtureKey(t)
	shipChild, _ := DeriveChild(key, AnyonePub(), InvoiceSHIP)
	slapChild, _ := DeriveChild(key, AnyonePub(), InvoiceSLAP)
	if hex.EncodeToString(shipChild.PubKey().Compressed()) == hex.EncodeToString(slapChild.PubKey().Compressed()) {
		t.Fatal("different invoices should produce different child keys")
	}
}

func TestDeriveChildPubMatchesPrivate(t *testing.T) {
	key := loadFixtureKey(t)
	privChild, _ := DeriveChild(key, AnyonePub(), InvoiceSHIP)
	pubChild, err := DeriveChildPub(key.PubKey(), InvoiceSHIP)
	if err != nil {
		t.Fatal(err)
	}
	privHex := hex.EncodeToString(privChild.PubKey().Compressed())
	pubHex := hex.EncodeToString(pubChild.Compressed())
	if privHex != pubHex {
		t.Fatalf("public derivation doesn't match private:\n  priv: %s\n  pub:  %s", privHex, pubHex)
	}
}

// --- BRC-43 Invoice Constants ---

func TestInvoiceConstants(t *testing.T) {
	// These should use the canonical protocol IDs from go-sdk
	if InvoiceSHIP == "" {
		t.Fatal("SHIP invoice empty")
	}
	if InvoiceSLAP == "" {
		t.Fatal("SLAP invoice empty")
	}
	if InvoiceHandshake != "2-relay-handshake-1" {
		t.Fatalf("Handshake invoice: got %q", InvoiceHandshake)
	}
}

// --- SHIP ---

func TestBuildAndValidateSHIP(t *testing.T) {
	key := loadFixtureKey(t)
	scriptBytes, _, err := BuildSHIPScript(key, "example.com", "forge:mainnet")
	if err != nil {
		t.Fatal(err)
	}

	token, err := ValidateSHIPToken(scriptBytes)
	if err != nil {
		t.Fatal(err)
	}
	if token.Domain != "example.com" {
		t.Fatalf("domain: got %q", token.Domain)
	}
	if token.Topic != "forge:mainnet" {
		t.Fatalf("topic: got %q", token.Topic)
	}
}

func TestSHIPRejectsWrongDerivation(t *testing.T) {
	key := loadFixtureKey(t)
	// Build a SHIP script but use SLAP-derived locking key (wrong)
	slapKey, _ := DeriveChild(key, AnyonePub(), InvoiceSLAP)
	identityPubHex := hex.EncodeToString(key.PubKey().Compressed())

	// Manually construct a bad SHIP script with wrong locking key
	fields := [][]byte{
		[]byte("SHIP"),
		[]byte(identityPubHex),
		[]byte("example.com"),
		[]byte("forge:mainnet"),
	}
	s, _ := script.EncodePushDatas(fields)
	pubBytes := slapKey.PubKey().Compressed()
	pushPrefix, _ := script.PushDataPrefix(pubBytes)
	buf := append(s, 0x75, 0x6d, 0x75)
	buf = append(buf, pushPrefix...)
	buf = append(buf, pubBytes...)
	buf = append(buf, 0xac)

	_, err := ValidateSHIPToken(buf)
	if err == nil {
		t.Fatal("expected validation to fail for wrong derivation")
	}
}

// --- SLAP ---

func TestBuildAndValidateSLAP(t *testing.T) {
	key := loadFixtureKey(t)
	scriptBytes, _, err := BuildSLAPScript(key, "example.com", "SHIP")
	if err != nil {
		t.Fatal(err)
	}

	token, err := ValidateSLAPToken(scriptBytes)
	if err != nil {
		t.Fatal(err)
	}
	if token.Domain != "example.com" {
		t.Fatalf("domain: got %q", token.Domain)
	}
	if token.Provider != "SHIP" {
		t.Fatalf("provider: got %q", token.Provider)
	}
}
