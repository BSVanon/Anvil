package brc

import (
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Frozen fixtures from relay-federation derivation.test.js
const (
	fixtureWIF         = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S"
	fixtureIdentityPub = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
	fixtureSHIPChild   = "02d1ab523f5572d711b583e15093a03d9cf873099ccaed040854f3cc3032677240"
	fixtureSLAPChild   = "023a0f647e26ba4e23ec9ee0e1b9e22b4d5fcb51b65ce492fbd0f47ba96b942cef"
)

func loadFixtureKey(t *testing.T) *secp256k1.PrivateKey {
	t.Helper()
	// KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S is private key = 3
	privBytes, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000003")
	key := secp256k1.PrivKeyFromBytes(privBytes)
	// Verify the pubkey matches
	pubHex := hex.EncodeToString(key.PubKey().SerializeCompressed())
	if pubHex != fixtureIdentityPub {
		t.Fatalf("fixture key mismatch: got %s", pubHex)
	}
	return key
}

// --- BRC-42 Derivation ---

func TestDeriveChildDeterminism(t *testing.T) {
	key := loadFixtureKey(t)
	_, pub1 := DeriveChild(key, InvoiceSHIP)
	_, pub2 := DeriveChild(key, InvoiceSHIP)
	if hex.EncodeToString(pub1.SerializeCompressed()) != hex.EncodeToString(pub2.SerializeCompressed()) {
		t.Fatal("derivation is not deterministic")
	}
}

func TestDeriveChildSHIPFixture(t *testing.T) {
	key := loadFixtureKey(t)
	_, pub := DeriveChild(key, InvoiceSHIP)
	got := hex.EncodeToString(pub.SerializeCompressed())
	if got != fixtureSHIPChild {
		t.Fatalf("SHIP child mismatch:\n  got  %s\n  want %s", got, fixtureSHIPChild)
	}
}

func TestDeriveChildSLAPFixture(t *testing.T) {
	key := loadFixtureKey(t)
	_, pub := DeriveChild(key, InvoiceSLAP)
	got := hex.EncodeToString(pub.SerializeCompressed())
	if got != fixtureSLAPChild {
		t.Fatalf("SLAP child mismatch:\n  got  %s\n  want %s", got, fixtureSLAPChild)
	}
}

func TestDeriveChildDifferentInvoices(t *testing.T) {
	key := loadFixtureKey(t)
	_, shipPub := DeriveChild(key, InvoiceSHIP)
	_, slapPub := DeriveChild(key, InvoiceSLAP)
	if hex.EncodeToString(shipPub.SerializeCompressed()) == hex.EncodeToString(slapPub.SerializeCompressed()) {
		t.Fatal("different invoices should produce different child keys")
	}
}

func TestDeriveChildPubMatchesPrivate(t *testing.T) {
	key := loadFixtureKey(t)
	_, privPub := DeriveChild(key, InvoiceSHIP)
	pubOnly := DeriveChildPub(key.PubKey(), InvoiceSHIP)

	privHex := hex.EncodeToString(privPub.SerializeCompressed())
	pubHex := hex.EncodeToString(pubOnly.SerializeCompressed())
	if privHex != pubHex {
		t.Fatalf("public derivation doesn't match private:\n  priv: %s\n  pub:  %s", privHex, pubHex)
	}
}

func TestDeriveChildPubSLAPMatchesPrivate(t *testing.T) {
	key := loadFixtureKey(t)
	_, privPub := DeriveChild(key, InvoiceSLAP)
	pubOnly := DeriveChildPub(key.PubKey(), InvoiceSLAP)

	privHex := hex.EncodeToString(privPub.SerializeCompressed())
	pubHex := hex.EncodeToString(pubOnly.SerializeCompressed())
	if privHex != pubHex {
		t.Fatalf("public SLAP derivation doesn't match private:\n  priv: %s\n  pub:  %s", privHex, pubHex)
	}
}

// --- BRC-43 Invoice Constants ---

func TestInvoiceConstants(t *testing.T) {
	if InvoiceSHIP != "2-SHIP-1" {
		t.Fatalf("SHIP invoice: got %q", InvoiceSHIP)
	}
	if InvoiceSLAP != "2-SLAP-1" {
		t.Fatalf("SLAP invoice: got %q", InvoiceSLAP)
	}
	if InvoiceHandshake != "2-relay-handshake-1" {
		t.Fatalf("Handshake invoice: got %q", InvoiceHandshake)
	}
}

// --- BRC-48 Token Scripts ---

func TestBuildAndParseTokenScript(t *testing.T) {
	key := loadFixtureKey(t)
	_, lockingPub := DeriveChild(key, InvoiceSHIP)

	fields := []string{"SHIP", fixtureIdentityPub, "example.com", "forge:mainnet"}
	script := BuildTokenScript(fields, lockingPub)

	tf, err := ParseTokenScript(script)
	if err != nil {
		t.Fatal(err)
	}
	if tf.Protocol != "SHIP" {
		t.Fatalf("protocol: got %q", tf.Protocol)
	}
	if tf.IdentityPub != fixtureIdentityPub {
		t.Fatalf("identity pub: got %q", tf.IdentityPub)
	}
	if tf.Domain != "example.com" {
		t.Fatalf("domain: got %q", tf.Domain)
	}
	if tf.TopicProvider != "forge:mainnet" {
		t.Fatalf("topic: got %q", tf.TopicProvider)
	}
	if len(tf.LockingPub) != 33 {
		t.Fatalf("locking pub length: got %d", len(tf.LockingPub))
	}
}

func TestParseTokenScriptRejectsBadOpcodes(t *testing.T) {
	key := loadFixtureKey(t)
	_, lockingPub := DeriveChild(key, InvoiceSHIP)
	fields := []string{"SHIP", fixtureIdentityPub, "example.com", "forge:mainnet"}
	script := BuildTokenScript(fields, lockingPub)

	// Replace OP_CHECKSIG (last byte) with OP_NOP (0x61) — guaranteed to fail validation
	corrupted := make([]byte, len(script))
	copy(corrupted, script)
	corrupted[len(corrupted)-1] = 0x61
	_, err := ParseTokenScript(corrupted)
	if err == nil {
		t.Fatal("expected error for corrupted opcodes")
	}
}

// --- SHIP ---

func TestBuildAndValidateSHIP(t *testing.T) {
	key := loadFixtureKey(t)
	script, _, err := BuildSHIPScript(key, "example.com", "forge:mainnet")
	if err != nil {
		t.Fatal(err)
	}

	token, err := ValidateSHIPToken(script)
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
	identityPubHex := hex.EncodeToString(key.PubKey().SerializeCompressed())
	_, wrongPub := DeriveChild(key, InvoiceSLAP) // wrong invoice
	fields := []string{"SHIP", identityPubHex, "example.com", "forge:mainnet"}
	script := BuildTokenScript(fields, wrongPub)

	_, err := ValidateSHIPToken(script)
	if err == nil {
		t.Fatal("expected validation to fail for wrong derivation")
	}
}

// --- SLAP ---

func TestBuildAndValidateSLAP(t *testing.T) {
	key := loadFixtureKey(t)
	script, _, err := BuildSLAPScript(key, "example.com", "SHIP")
	if err != nil {
		t.Fatal(err)
	}

	token, err := ValidateSLAPToken(script)
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

func TestSLAPRejectsWrongDerivation(t *testing.T) {
	key := loadFixtureKey(t)
	identityPubHex := hex.EncodeToString(key.PubKey().SerializeCompressed())
	_, wrongPub := DeriveChild(key, InvoiceSHIP) // wrong invoice
	fields := []string{"SLAP", identityPubHex, "example.com", "SHIP"}
	script := BuildTokenScript(fields, wrongPub)

	_, err := ValidateSLAPToken(script)
	if err == nil {
		t.Fatal("expected validation to fail for wrong derivation")
	}
}
