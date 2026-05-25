package topics

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// canonical 32-byte placeholders for Type + SerialNumber. The wallet
// type system enforces an explicit 32-byte ceiling (interfaces.go:80,
// :94) so test fixtures must base64-encode exactly 32 bytes (or less)
// to round-trip cleanly through Certificate.ToBinary / Sign / Verify.
func placeholder32(seed byte) string {
	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = seed
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// identityTestKeys returns a fresh subject + certifier keypair. Both
// are needed for a real Certificate.Sign + Verify round-trip: subject
// is the cert's Subject field; certifier signs the cert with the
// canonical "certificate signature" protocol.
func identityTestKeys(t *testing.T) (subject, certifier *ec.PrivateKey) {
	t.Helper()
	var err error
	subject, err = ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new subject: %v", err)
	}
	certifier, err = ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new certifier: %v", err)
	}
	return subject, certifier
}

// makeIdentityCert builds + signs a canonical Certificate. Uses
// CompletedProtoWallet as the CertifierWallet (satisfies
// PublicKeyGetter + CipherOperations + SignatureOperations).
func makeIdentityCert(t *testing.T, subject, certifier *ec.PrivateKey) *certificates.Certificate {
	t.Helper()
	certifierWallet, err := wallet.NewCompletedProtoWallet(certifier)
	if err != nil {
		t.Fatalf("certifier wallet: %v", err)
	}
	revHash, _ := chainhash.NewHashFromHex("0000000000000000000000000000000000000000000000000000000000000000")
	cert := &certificates.Certificate{
		Type:               wallet.StringBase64(placeholder32(0x01)),
		SerialNumber:       wallet.StringBase64(placeholder32(0x02)),
		Subject:            *subject.PubKey(),
		Certifier:          *certifier.PubKey(),
		RevocationOutpoint: &transaction.Outpoint{Txid: *revHash, Index: 0},
		// Fields can be empty for the signature-only verification path —
		// the Verify() check exercises ToBinary + signature roundtrip,
		// not field decryption.
		Fields: map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{},
	}
	if err := cert.Sign(context.Background(), certifierWallet); err != nil {
		t.Fatalf("cert.Sign: %v", err)
	}
	return cert
}

// buildIdentityScript wraps a JSON-encoded Certificate as the first
// PushDrop field. The Anvil IdentityTopicManager admit path expects
// the cert at field[0]; nothing else needs to be present for
// signature-chain verification to pass.
func buildIdentityScript(t *testing.T, cert *certificates.Certificate) []byte {
	t.Helper()
	certJSON, err := json.Marshal(cert)
	if err != nil {
		t.Fatalf("marshal cert: %v", err)
	}
	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("locking key: %v", err)
	}
	w, err := wallet.NewCompletedProtoWallet(priv)
	if err != nil {
		t.Fatalf("new wallet: %v", err)
	}
	pd := &pushdrop.PushDrop{Wallet: w}
	s, err := pd.Lock(
		context.Background(),
		[][]byte{certJSON, {0x00}}, // field[0]=cert JSON, field[1]=placeholder (TS impl pops a signature field at the end)
		wallet.Protocol{
			SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
			Protocol:      "identity",
		},
		"1",
		wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
		false,
		false,
		pushdrop.LockBefore,
	)
	if err != nil {
		t.Fatalf("PushDrop Lock: %v", err)
	}
	return s.Bytes()
}

// TestParseIdentityOutput_SignedCertAdmitted pins the happy path: a
// real signed Certificate embedded in a PushDrop output passes
// signature-chain verification (canonical cert.Verify) and yields an
// IdentityEntry with the correct identityKey + certifierKey hex.
func TestParseIdentityOutput_SignedCertAdmitted(t *testing.T) {
	subject, certifier := identityTestKeys(t)
	cert := makeIdentityCert(t, subject, certifier)
	scriptBytes := buildIdentityScript(t, cert)

	entry, err := ParseIdentityOutput(context.Background(), scriptBytes)
	if err != nil {
		t.Fatalf("ParseIdentityOutput: %v", err)
	}
	if entry == nil {
		t.Fatal("expected non-nil identity entry")
	}
	wantIdentity := hex.EncodeToString(subject.PubKey().Compressed())
	if entry.IdentityKey != wantIdentity {
		t.Fatalf("IdentityKey mismatch: want %s, got %s", wantIdentity, entry.IdentityKey)
	}
	wantCertifier := hex.EncodeToString(certifier.PubKey().Compressed())
	if entry.CertifierKey != wantCertifier {
		t.Fatalf("CertifierKey mismatch: want %s, got %s", wantCertifier, entry.CertifierKey)
	}
	if entry.CertType != string(cert.Type) {
		t.Fatalf("CertType mismatch: want %s, got %s", cert.Type, entry.CertType)
	}
}

// TestParseIdentityOutput_TamperedCertRejected verifies that a signed
// cert with a tampered field (changed SerialNumber post-sign) fails
// the canonical Verify check and is rejected. This is the load-bearing
// security check — without it, malicious certs would pollute the
// ls_identity index.
func TestParseIdentityOutput_TamperedCertRejected(t *testing.T) {
	subject, certifier := identityTestKeys(t)
	cert := makeIdentityCert(t, subject, certifier)
	// Tamper: change the serial number AFTER signing. cert.Verify
	// re-serializes + checks against the existing signature; mismatch
	// means rejected.
	cert.SerialNumber = wallet.StringBase64(placeholder32(0xff))
	scriptBytes := buildIdentityScript(t, cert)

	entry, err := ParseIdentityOutput(context.Background(), scriptBytes)
	if entry != nil {
		t.Fatalf("expected nil entry for tampered cert, got %+v", entry)
	}
	if err == nil {
		t.Fatal("expected error for tampered cert")
	}
}

// TestParseIdentityOutput_NonJSONField0Ignored confirms that a
// PushDrop output whose first field isn't JSON-decodable as a
// Certificate is silently ignored (returns nil, nil) — not an error,
// because the engine fans every admit to every topic, and non-identity
// outputs should be skipped without noise.
func TestParseIdentityOutput_NonJSONField0Ignored(t *testing.T) {
	priv, _ := ec.NewPrivateKey()
	w, _ := wallet.NewCompletedProtoWallet(priv)
	pd := &pushdrop.PushDrop{Wallet: w}
	s, _ := pd.Lock(
		context.Background(),
		[][]byte{[]byte("not-a-cert"), {0x00}},
		wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty, Protocol: "identity"},
		"1",
		wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
		false, false, pushdrop.LockBefore,
	)
	entry, err := ParseIdentityOutput(context.Background(), s.Bytes())
	if err != nil {
		t.Fatalf("non-JSON field[0] returned error: %v", err)
	}
	if entry != nil {
		t.Fatalf("expected nil entry for non-cert PushDrop, got %+v", entry)
	}
}

// TestParseIdentityOutput_EmptyScript pins the nil-safety guard.
func TestParseIdentityOutput_EmptyScript(t *testing.T) {
	entry, err := ParseIdentityOutput(context.Background(), nil)
	if err != nil || entry != nil {
		t.Fatalf("expected (nil, nil) for empty script, got (%+v, %v)", entry, err)
	}
}

// TestParseIdentityOutput_NonPushDropIgnored confirms that a script
// which doesn't decode as PushDrop returns (nil, nil).
func TestParseIdentityOutput_NonPushDropIgnored(t *testing.T) {
	entry, err := ParseIdentityOutput(context.Background(), []byte{0x51}) // OP_1 — not PushDrop
	if err != nil {
		t.Fatalf("non-PushDrop returned error: %v", err)
	}
	if entry != nil {
		t.Fatalf("non-PushDrop returned entry: %+v", entry)
	}
}
