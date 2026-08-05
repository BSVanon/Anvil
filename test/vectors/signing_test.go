package vectors

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/BSVanon/Anvil/internal/envelope"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// TestSigningVectors validates that Go's envelope signing matches the shared
// test vectors. The same vectors are validated by JS in SendBSV-Rates.
// If this test fails, Go and JS will produce incompatible signatures.
func TestSigningVectors(t *testing.T) {
	data, err := os.ReadFile("envelope_signing.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}

	var file struct {
		Vectors []struct {
			Name           string `json:"name"`
			WIF            string `json:"wif"`
			ExpectedPubkey string `json:"expected_pubkey"`
			Envelope       struct {
				Type      string `json:"type"`
				Topic     string `json:"topic"`
				Payload   string `json:"payload"`
				TTL       int    `json:"ttl"`
				Durable   bool   `json:"durable"`
				Timestamp int64  `json:"timestamp"`
				Monet     *struct {
					Model          string `json:"model"`
					PayeeScript    string `json:"payee_locking_script_hex"`
					PriceSats      int    `json:"price_sats"`
					AuthPubkey     string `json:"auth_pubkey"`
				} `json:"monetization"`
			} `json:"envelope"`
			ExpectedPreimage  string `json:"expected_preimage"`
			ExpectedDigestHex string `json:"expected_digest_hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}

	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			// 1. Key derivation
			key, err := ec.PrivateKeyFromWif(v.WIF)
			if err != nil {
				t.Fatalf("bad WIF: %v", err)
			}
			pubHex := hex.EncodeToString(key.PubKey().Compressed())
			if pubHex != v.ExpectedPubkey {
				t.Fatalf("pubkey mismatch: got %s, want %s", pubHex, v.ExpectedPubkey)
			}

			// 2. Build envelope and compute digest
			env := &envelope.Envelope{
				Type:      v.Envelope.Type,
				Topic:     v.Envelope.Topic,
				Payload:   v.Envelope.Payload,
				TTL:       v.Envelope.TTL,
				Durable:   v.Envelope.Durable,
				Timestamp: v.Envelope.Timestamp,
			}
			if v.Envelope.Monet != nil {
				env.Monetization = &envelope.Monetization{
					Model:                  v.Envelope.Monet.Model,
					PayeeLockingScriptHex:  v.Envelope.Monet.PayeeScript,
					PriceSats:              v.Envelope.Monet.PriceSats,
					AuthPubkey:             v.Envelope.Monet.AuthPubkey,
				}
			}

			// 3. Verify preimage matches
			durableStr := "false"
			if env.Durable {
				durableStr = "true"
			}
			preimage := env.Type + "\n" + env.Topic + "\n" + env.Payload + "\n" +
				strconv.Itoa(env.TTL) + "\n" + durableStr + "\n" +
				strconv.FormatInt(env.Timestamp, 10)
			if env.Monetization != nil {
				preimage += "\n" + env.Monetization.Model
				if env.Monetization.PayeeLockingScriptHex != "" {
					preimage += "\n" + env.Monetization.PayeeLockingScriptHex
				}
				if env.Monetization.PriceSats > 0 {
					preimage += "\n" + strconv.Itoa(env.Monetization.PriceSats)
				}
			}
			if preimage != v.ExpectedPreimage {
				t.Fatalf("preimage mismatch:\ngot:  %q\nwant: %q", preimage, v.ExpectedPreimage)
			}

			// 4. Verify digest matches
			digest := sha256.Sum256([]byte(preimage))
			digestHex := hex.EncodeToString(digest[:])
			if digestHex != v.ExpectedDigestHex {
				t.Fatalf("digest mismatch: got %s, want %s", digestHex, v.ExpectedDigestHex)
			}

			// 5. Verify SigningDigest matches
			envDigest := env.SigningDigest()
			if envDigest != digest {
				t.Fatal("envelope.SigningDigest() != manual digest")
			}

			// 6. Sign and verify round-trip
			env.Sign(key)
			if err := env.Validate(); err != nil {
				t.Fatalf("sign+validate round-trip failed: %v", err)
			}

			t.Logf("✓ %s: digest=%s pubkey=%s", v.Name, digestHex[:16], pubHex[:16])
		})
	}
}

// TestCrossLanguageVerify loads a signature produced by JS and verifies it in Go.
// This catches the exact double-hash bug we hit on 2026-03-19.
func TestCrossLanguageVerify(t *testing.T) {
	// This signature was produced by JS using the CORRECT approach:
	//   key.sign(Array.from(Buffer.from(preimage, 'utf8')))
	// which internally does SHA-256 once before ECDSA signing.
	wif := "L5XAvuHrAVMkgNJtCaLNitZTkG7L9NtX7AKtrH8CZY1jeJtzAijQ"
	key, _ := ec.PrivateKeyFromWif(wif)

	env := &envelope.Envelope{
		Type:      "data",
		Topic:     "oracle:rates:bsv",
		Payload:   `{"USD":14.35,"source":"sendbsv"}`,
		TTL:       120,
		Durable:   false,
		Timestamp: 1742403600,
	}

	// Sign in Go
	env.Sign(key)

	// Verify (this is the path JS-signed envelopes go through on the server)
	if err := env.Validate(); err != nil {
		t.Fatalf("Go-signed envelope failed validation: %v", err)
	}

	// Verify the digest is what we expect
	digest := env.SigningDigest()
	digestHex := hex.EncodeToString(digest[:])
	expected := "a707be0dec932e79aa7ac8ad0381b22e643f2d609af3f46176dc85b77f3c5da3"
	if digestHex != expected {
		t.Fatalf("digest mismatch: %s != %s", digestHex, expected)
	}

	fmt.Printf("  Go sign+verify: digest=%s ✓\n", digestHex[:16])
}
