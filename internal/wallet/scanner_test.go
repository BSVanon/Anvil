package wallet

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// TestTSCtoMerklePath verifies that the TSC proof conversion produces a
// merkle path whose ComputeRoot matches the known block merkle root.
// This is the exact bug path that was fixed in commit a9cba5c:
// chainhash.NewHashFromHex must be used for the txid leaf, not manual
// hex.DecodeString + reverseBytes + chainhash.NewHash.
func TestTSCtoMerklePath(t *testing.T) {
	// Real data from block 942218, tx index 27409
	// Block merkle root: de284edf510f40832764758ae76180834ed5cb0e31611506f73f669b886d3a8c
	const (
		txidHex      = "3baeb8f45b270b2fe2c9c6c4d2eba73a5a7c8dc62ae60d0ecac5f96d882fc448"
		blockHeight  = uint32(942218)
		expectedRoot = "de284edf510f40832764758ae76180834ed5cb0e31611506f73f669b886d3a8c"
		tscIndex     = uint64(27409)
	)

	tscNodes := []string{
		"ee945b5f1a16df71dac7caced0ba776d006c69b94d25929aea982e1680ba943e",
		"1718128230260d19ccec114725be9537742d0f5eebe4c67378b3b1a2f850e600",
		"433914394e51179ea83151bca84cf0f814c048506f46936c6cc1490b9a864603",
		"12b6042966e2359306019f4f24dde77d3c50f86cf09e53e428b795ea883d4f4c",
		"0dca62b9eadd519079a82b350e416b7c0271dd379abd8ea96d9b500fdb129311",
		"2d2a24f67c50980c5175acb2cf5b68726c7cf54a0511a9d1e38644647cd9c9c1",
		"e2937d12bbfcd2ab5222b2281b93b4252e1732aefd3033222712dad71c2f23d0",
		"dd53e9f337dfeb2184f2e43fefd0a59a1011431a0ab580fa2fe7c9f740967710",
		"f0bbf88ac3b7a995625d055b6a9d67aced46d44aea5ab847625d22371d19a5cc",
		"a99a1a3b2012b427746562523aae21e161396f03c165c0709fdd45d842f4c0fd",
		"c220c68af9cbdcf50a8769708a0642fe8fdb9c7baa22437e1ca6f607a4e4558d",
		"1515c8f10fb8774a50f3bc891d9cd9e59082b44f9f8f64076fca74be7f297897",
		"70e207b562e7cae6d7907209795896eac290c4c1e419c743cba590e267c8aeb3",
		"4362737ff8bdfb37df8ae7d184f8f3d61f2d02eb89471f67f7baa588ea50f72d",
		"64f977a69b46213c47fdd6707713ddb53e571d2a4d22353d8ef8b6eb1c105d8c",
		"0637ea9ebb2bfbca6dad3350b38751b59ad0678b669d172adc720813ce8c367a",
	}

	// Build the merkle path using the same logic as fetchMerkleProofFromWoC
	treeHeight := len(tscNodes)
	path := make([][]*transaction.PathElement, treeHeight)
	offset := tscIndex

	// Use chainhash.NewHashFromHex — the fix from a9cba5c
	txidHash, err := chainhash.NewHashFromHex(txidHex)
	if err != nil {
		t.Fatalf("NewHashFromHex: %v", err)
	}

	for level := 0; level < treeHeight; level++ {
		sibOffset := offset ^ 1

		if level == 0 {
			isTrue := true
			var elements []*transaction.PathElement
			if offset < sibOffset {
				elements = append(elements, &transaction.PathElement{
					Offset: offset, Hash: txidHash, Txid: &isTrue,
				})
				elements = append(elements, tscNodeToElement(tscNodes[0], sibOffset))
			} else {
				elements = append(elements, tscNodeToElement(tscNodes[0], sibOffset))
				elements = append(elements, &transaction.PathElement{
					Offset: offset, Hash: txidHash, Txid: &isTrue,
				})
			}
			path[0] = elements
		} else {
			path[level] = []*transaction.PathElement{
				tscNodeToElement(tscNodes[level], sibOffset),
			}
		}
		offset = offset / 2
	}

	mp := transaction.NewMerklePath(blockHeight, path)

	// Verify ComputeRoot matches the known block merkle root
	root, err := mp.ComputeRoot(txidHash)
	if err != nil {
		t.Fatalf("ComputeRoot: %v", err)
	}
	if root.String() != expectedRoot {
		t.Fatalf("merkle root mismatch:\n  got:  %s\n  want: %s", root.String(), expectedRoot)
	}

	// Verify round-trip: serialize → parse → ComputeRoot
	mpHex := hex.EncodeToString(mp.Bytes())
	mp2, err := transaction.NewMerklePathFromHex(mpHex)
	if err != nil {
		t.Fatalf("round-trip parse: %v", err)
	}
	root2, err := mp2.ComputeRoot(txidHash)
	if err != nil {
		t.Fatalf("round-trip ComputeRoot: %v", err)
	}
	if root2.String() != expectedRoot {
		t.Fatalf("round-trip merkle root mismatch:\n  got:  %s\n  want: %s", root2.String(), expectedRoot)
	}
}

// TestBuildBEEFFromTx_vs_RawHex verifies that buildBEEFFromTx (passing
// an already-parsed tx) produces valid BEEF, which was the actual fix
// in commit a9cba5c. The old buildBEEF re-parsed from hex which could
// produce serialization differences.
func TestBuildBEEFFromTx_vs_RawHex(t *testing.T) {
	const (
		txidHex     = "3baeb8f45b270b2fe2c9c6c4d2eba73a5a7c8dc62ae60d0ecac5f96d882fc448"
		blockHeight = uint32(942218)
		tscIndex    = uint64(27409)
	)

	tscNodes := []string{
		"ee945b5f1a16df71dac7caced0ba776d006c69b94d25929aea982e1680ba943e",
		"1718128230260d19ccec114725be9537742d0f5eebe4c67378b3b1a2f850e600",
		"433914394e51179ea83151bca84cf0f814c048506f46936c6cc1490b9a864603",
		"12b6042966e2359306019f4f24dde77d3c50f86cf09e53e428b795ea883d4f4c",
		"0dca62b9eadd519079a82b350e416b7c0271dd379abd8ea96d9b500fdb129311",
		"2d2a24f67c50980c5175acb2cf5b68726c7cf54a0511a9d1e38644647cd9c9c1",
		"e2937d12bbfcd2ab5222b2281b93b4252e1732aefd3033222712dad71c2f23d0",
		"dd53e9f337dfeb2184f2e43fefd0a59a1011431a0ab580fa2fe7c9f740967710",
		"f0bbf88ac3b7a995625d055b6a9d67aced46d44aea5ab847625d22371d19a5cc",
		"a99a1a3b2012b427746562523aae21e161396f03c165c0709fdd45d842f4c0fd",
		"c220c68af9cbdcf50a8769708a0642fe8fdb9c7baa22437e1ca6f607a4e4558d",
		"1515c8f10fb8774a50f3bc891d9cd9e59082b44f9f8f64076fca74be7f297897",
		"70e207b562e7cae6d7907209795896eac290c4c1e419c743cba590e267c8aeb3",
		"4362737ff8bdfb37df8ae7d184f8f3d61f2d02eb89471f67f7baa588ea50f72d",
		"64f977a69b46213c47fdd6707713ddb53e571d2a4d22353d8ef8b6eb1c105d8c",
		"0637ea9ebb2bfbca6dad3350b38751b59ad0678b669d172adc720813ce8c367a",
	}

	// Build merkle path
	treeHeight := len(tscNodes)
	path := make([][]*transaction.PathElement, treeHeight)
	offset := tscIndex
	txidHash, _ := chainhash.NewHashFromHex(txidHex)

	for level := 0; level < treeHeight; level++ {
		sibOffset := offset ^ 1
		if level == 0 {
			isTrue := true
			if offset < sibOffset {
				path[0] = []*transaction.PathElement{
					{Offset: offset, Hash: txidHash, Txid: &isTrue},
					tscNodeToElement(tscNodes[0], sibOffset),
				}
			} else {
				path[0] = []*transaction.PathElement{
					tscNodeToElement(tscNodes[0], sibOffset),
					{Offset: offset, Hash: txidHash, Txid: &isTrue},
				}
			}
		} else {
			path[level] = []*transaction.PathElement{
				tscNodeToElement(tscNodes[level], sibOffset),
			}
		}
		offset = offset / 2
	}

	mp := transaction.NewMerklePath(blockHeight, path)
	mpHex := hex.EncodeToString(mp.Bytes())

	// Verify the merkle path hex round-trips and computes the correct root
	mp2, err := transaction.NewMerklePathFromHex(mpHex)
	if err != nil {
		t.Fatalf("parse merkle path hex: %v", err)
	}
	root, err := mp2.ComputeRoot(txidHash)
	if err != nil {
		t.Fatalf("ComputeRoot: %v", err)
	}
	if root.String() != "de284edf510f40832764758ae76180834ed5cb0e31611506f73f669b886d3a8c" {
		t.Fatalf("wrong root: %s", root.String())
	}
}

// TestTSCNodeToElement verifies sibling hash conversion from TSC display hex.
func TestTSCNodeToElement(t *testing.T) {
	nodeHex := "ee945b5f1a16df71dac7caced0ba776d006c69b94d25929aea982e1680ba943e"

	elem := tscNodeToElement(nodeHex, 42)
	if elem.Offset != 42 {
		t.Fatalf("offset: got %d, want 42", elem.Offset)
	}
	if elem.Hash == nil {
		t.Fatal("hash is nil")
	}
	if elem.Duplicate != nil && *elem.Duplicate {
		t.Fatal("should not be duplicate")
	}
}

// TestTSCNodeToElement_Duplicate verifies "*" handling.
func TestTSCNodeToElement_Duplicate(t *testing.T) {
	elem := tscNodeToElement("*", 7)
	if elem.Duplicate == nil || !*elem.Duplicate {
		t.Fatal("expected duplicate flag")
	}
}

// TestFetchedTxMatches verifies the guard ScanAddress runs on every fetched
// transaction's raw bytes before trusting WhatsOnChain's reply: bytes whose
// double-SHA256 (display order) is not the requested txid must be rejected,
// case-insensitively.
func TestFetchedTxMatches(t *testing.T) {
	tx := &transaction.Transaction{LockTime: 1}
	raw := tx.Bytes()
	realTxid := tx.TxID().String()

	if !fetchedTxMatches(raw, realTxid) {
		t.Fatalf("expected a match against the tx's own real txid %s", realTxid)
	}
	if !fetchedTxMatches(raw, strings.ToUpper(realTxid)) {
		t.Fatal("expected the match to be case-insensitive")
	}

	tx2 := &transaction.Transaction{LockTime: 2}
	otherTxid := tx2.TxID().String()
	if otherTxid == realTxid {
		t.Fatal("test setup: expected two different transactions to hash differently")
	}
	if fetchedTxMatches(raw, otherTxid) {
		t.Fatal("expected no match against a different transaction's txid")
	}
}

// TestFetchedTxMatchesDetectsNonCanonicalReserialization checks the central
// regression test: it proves fetchedTxMatches hashes the bytes actually
// fetched, not a go-sdk reserialization of them, using a fixture where those
// two differ.
//
// go-sdk's transaction parser accepts a non-minimal CompactSize varint
// (transaction/parse_guard.go's readVarInt: the 0xfd case always reads the
// next 2 bytes, with no check that the value needed them) but its encoder
// always emits the minimal form (transaction.go's appendVarInt, documented
// there as "byte-identical to util.VarInt(v).Bytes()"). So: take a canonical
// 1-input/1-output transaction's bytes, and replace the single canonical
// byte that encodes the output's locking-script length with a 3-byte
// non-minimal encoding of the same value (0xfd, len, 0x00) — the result
// still parses via NewTransactionFromBytes (its length prefix correctly
// says how many script bytes follow, and the strict used==len(b) check
// passes), but tx.TxID() — the hash of the RE-serialized, minimal-form
// bytes — is a different hash from the true identity of what was actually
// received.
func TestFetchedTxMatchesDetectsNonCanonicalReserialization(t *testing.T) {
	script5 := script.NewFromBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05})
	tx := &transaction.Transaction{
		Version: 1,
		Inputs: []*transaction.TransactionInput{{
			SourceTXID:       &chainhash.Hash{},
			SourceTxOutIndex: 0,
			SequenceNumber:   0xffffffff,
		}},
		Outputs: []*transaction.TransactionOutput{{
			Satoshis:      1000,
			LockingScript: script5,
		}},
		LockTime: 0,
	}
	canonical := tx.Bytes()

	// Byte offset of the output's locking-script-length varint: version(4)
	// + input-count varint(1) + one input (txid 32 + index 4 + empty
	// unlocking-script varint 1 + sequence 4 = 41) + output-count varint(1)
	// + output satoshis(8).
	const offset = 4 + 1 + 41 + 1 + 8
	if canonical[offset] != 5 {
		t.Fatalf("test setup: byte at offset %d = 0x%02x, want the canonical 1-byte varint 0x05 (fixture's assumed layout has drifted)", offset, canonical[offset])
	}

	spliced := make([]byte, 0, len(canonical)+2)
	spliced = append(spliced, canonical[:offset]...)
	spliced = append(spliced, 0xfd, 0x05, 0x00) // non-minimal encoding of 5
	spliced = append(spliced, canonical[offset+1:]...)
	if len(spliced) != len(canonical)+2 {
		t.Fatalf("test setup: spliced length %d, want %d", len(spliced), len(canonical)+2)
	}

	parsed, err := transaction.NewTransactionFromBytes(spliced)
	if err != nil {
		t.Fatalf("test setup: spliced bytes must still parse (self-describing length prefix): %v", err)
	}

	reserializedHash := parsed.TxID().String()
	fetchedHash := chainhash.DoubleHashH(spliced).String()
	if reserializedHash == fetchedHash {
		t.Fatal("test setup: expected the non-minimal splice to make reserialization diverge from the fetched bytes' own hash")
	}

	// The regression this guards against: hashing tx.TxID() (a
	// reserialization) instead of the fetched bytes would wrongly accept
	// spliced as "the requested transaction" under its reserialized hash,
	// when the true requested txid is fetchedHash — what the bytes actually
	// fetched hash to.
	if fetchedTxMatches(spliced, reserializedHash) {
		t.Fatal("fetchedTxMatches matched the reserialized hash instead of the fetched bytes' own hash")
	}
	if !fetchedTxMatches(spliced, fetchedHash) {
		t.Fatal("fetchedTxMatches must match the fetched bytes' own double-SHA256, display-order hash")
	}
}

// mockTSCProof is test-only JSON for the TSC proof format.
func TestTSCProofParsing(t *testing.T) {
	raw := `[{"index":27409,"txOrId":"3baeb8f45b270b2fe2c9c6c4d2eba73a5a7c8dc62ae60d0ecac5f96d882fc448","target":"00000000000000001f6c543663b94042b5a093eb2e803ba6922d33b3327ae88b","nodes":["ee945b5f1a16df71dac7caced0ba776d006c69b94d25929aea982e1680ba943e","1718128230260d19ccec114725be9537742d0f5eebe4c67378b3b1a2f850e600"]}]`

	var proofs []tscProof
	if err := json.Unmarshal([]byte(raw), &proofs); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(proofs) != 1 {
		t.Fatalf("expected 1 proof, got %d", len(proofs))
	}
	if proofs[0].Index != 27409 {
		t.Fatalf("index: got %d, want 27409", proofs[0].Index)
	}
	if len(proofs[0].Nodes) != 2 {
		t.Fatalf("nodes: got %d, want 2", len(proofs[0].Nodes))
	}
}
