// OrdLockBuy topic manager — admits free-agent BSV-locked buy-side vaults
// (the Rúnar-compiled OrdLockBuy covenant from Anvil-Swap Phase B-buy).
//
// Mirrors `ordlock.go` (sell-side listings) but for the buy-side covenant.
// The two are intentionally separate topics so each can apply its own
// structural filter without leaking matches into the other's lookup.
//
// Vendored constants (full artifact template + slot offsets) are
// byte-identical to the canonical TypeScript reference at
// `Anvil-Swap/src/ordlock/runar/buy-covenant.ts` + the artifact JSON at
// `Anvil-Swap/artifacts/OrdLockBuy.runar.json`. Do not edit without
// re-verifying parity against fresh Anvil-Swap-built fixtures.
package topics

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/BSVanon/Anvil/internal/overlay"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// OrdLockBuyTopicName is the BRC-87 topic name for OrdLockBuy vaults.
const OrdLockBuyTopicName = "tm_ordlock_buy_vaults"

// ordLockBuyArtifactHex is the full 142-byte Rúnar-compiled OrdLockBuy
// template. Each `00` byte at one of the constructor slot offsets is a
// placeholder that gets replaced with the encoded constant push at
// vault-build time.
const ordLockBuyArtifactHex = "76009c63755279ab547a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad6900007e7b007e7e007c7e7c7eaa7c820128947f7701207f758767519d5279ab557a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad69537a00ad7c007e00007e7e7c7eaa7c820128947f7701207f758768"

// Canonical fixed parameter values — emitted twice each by the artifact.
const (
	ordLockBuyP2pkhVarintPrefixHex = "1976a914"
	ordLockBuyP2pkhSuffixHex       = "88ac"
)

// ordLockBuyParamName identifies which constructor parameter occupies a slot.
type ordLockBuyParamName int

const (
	paramPriceSatsLE ordLockBuyParamName = iota
	paramP2pkhVarintPrefix
	paramP2pkhSuffix
	paramExpectedOutput0Bytes
	paramBuyerPubKey
	paramCancelPkh
)

// ordLockBuySlot describes one constructor splice slot in the artifact.
type ordLockBuySlot struct {
	byteOffset    int                 // offset of the placeholder byte in the artifact template
	param         ordLockBuyParamName // which constructor param fills this slot
	expectedBytes int                 // 0 = variable length
	expectedHex   string              // optional fixed-value match for invariant pushes
}

// ordLockBuySlots encodes the artifact's slot ordering — 8 entries in
// ascending byteOffset order.
var ordLockBuySlots = []ordLockBuySlot{
	{byteOffset: 46, param: paramPriceSatsLE, expectedBytes: 8},
	{byteOffset: 47, param: paramP2pkhVarintPrefix, expectedBytes: 4, expectedHex: ordLockBuyP2pkhVarintPrefixHex},
	{byteOffset: 50, param: paramP2pkhSuffix, expectedBytes: 2, expectedHex: ordLockBuyP2pkhSuffixHex},
	{byteOffset: 53, param: paramExpectedOutput0Bytes, expectedBytes: 0},
	{byteOffset: 117, param: paramBuyerPubKey, expectedBytes: 33},
	{byteOffset: 120, param: paramP2pkhVarintPrefix, expectedBytes: 4, expectedHex: ordLockBuyP2pkhVarintPrefixHex},
	{byteOffset: 122, param: paramCancelPkh, expectedBytes: 20},
	{byteOffset: 123, param: paramP2pkhSuffix, expectedBytes: 2, expectedHex: ordLockBuyP2pkhSuffixHex},
}

// Derived at startup from the artifact template.
var (
	olockBuyArtifactBytes []byte // full template
	olockBuyPrefixBytes   []byte // bytes before slot[0]
	olockBuySuffixBytes   []byte // bytes after slot[last]
	olockBuyInterSlots    [][]byte // inter-slot fixed bytes; len == len(slots)
)

func init() {
	var err error
	if olockBuyArtifactBytes, err = hex.DecodeString(ordLockBuyArtifactHex); err != nil {
		panic(fmt.Sprintf("ordlock_buy: artifact hex malformed: %v", err))
	}
	if len(olockBuyArtifactBytes) != 142 {
		panic(fmt.Sprintf("ordlock_buy: artifact byte length %d, expected 142", len(olockBuyArtifactBytes)))
	}
	if len(ordLockBuySlots) == 0 {
		panic("ordlock_buy: no slots defined")
	}
	// Verify each slot offset hosts a placeholder (0x00) byte.
	for _, s := range ordLockBuySlots {
		if s.byteOffset >= len(olockBuyArtifactBytes) {
			panic(fmt.Sprintf("ordlock_buy: slot byteOffset %d out of range", s.byteOffset))
		}
		if olockBuyArtifactBytes[s.byteOffset] != 0x00 {
			panic(fmt.Sprintf("ordlock_buy: slot byteOffset %d does not contain placeholder 0x00", s.byteOffset))
		}
	}
	// Verify slots are sorted ascending.
	for i := 1; i < len(ordLockBuySlots); i++ {
		if ordLockBuySlots[i].byteOffset <= ordLockBuySlots[i-1].byteOffset {
			panic("ordlock_buy: slots must be sorted ascending by byteOffset")
		}
	}

	olockBuyPrefixBytes = append([]byte(nil), olockBuyArtifactBytes[:ordLockBuySlots[0].byteOffset]...)
	last := ordLockBuySlots[len(ordLockBuySlots)-1]
	olockBuySuffixBytes = append([]byte(nil), olockBuyArtifactBytes[last.byteOffset+1:]...)

	olockBuyInterSlots = make([][]byte, len(ordLockBuySlots))
	// Slot 0 has no inter-slot prefix in this scheme (the artifact prefix is handled separately).
	olockBuyInterSlots[0] = nil
	for i := 1; i < len(ordLockBuySlots); i++ {
		segStart := ordLockBuySlots[i-1].byteOffset + 1
		segEnd := ordLockBuySlots[i].byteOffset
		olockBuyInterSlots[i] = append([]byte(nil), olockBuyArtifactBytes[segStart:segEnd]...)
	}
}

// OrdLockBuyEntry is the per-vault metadata stored on each admitted output.
// The wire shape is consumed by Anvil-Swap's discovery library.
type OrdLockBuyEntry struct {
	Outpoint           string `json:"outpoint"`                  // "<txid>_<vout>"
	VaultSats          int64  `json:"vaultSats"`                 // sats locked in the vault output
	Protocol           string `json:"protocol,omitempty"`        // "bsv-20" or "bsv-21" (best-effort)
	TokenId            string `json:"tokenId,omitempty"`         // BSV-21 only
	Tick               string `json:"tick,omitempty"`            // BSV-20 only (uppercase)
	RequestedAmount    string `json:"requestedAmount,omitempty"` // stringified atomic units (best-effort)
	PriceSats          int64  `json:"priceSats"`                 // BSV the seller receives
	CancelPkhHex       string `json:"cancelPkhHex"`              // 20-byte hex, lowercase — buyer's cancel key
	BuyerPubKeyHex     string `json:"buyerPubKeyHex"`            // 33-byte compressed pubkey hex
	ExpectedOutput0Hex string `json:"expectedOutput0Hex"`        // BIP-143 wire bytes for token output (verbatim)
	ScriptHex          string `json:"scriptHex"`                 // full vault locking script
	AdmittedAt         string `json:"admittedAt"`                // RFC3339 UTC timestamp at admit time
}

// OrdLockBuyTopicManager implements overlay.TopicManager for OrdLockBuy vaults.
type OrdLockBuyTopicManager struct{}

// NewOrdLockBuyTopicManager creates an OrdLockBuy topic manager.
func NewOrdLockBuyTopicManager() *OrdLockBuyTopicManager {
	return &OrdLockBuyTopicManager{}
}

// Admit scans every output for canonical OrdLockBuy vaults, admits each one,
// and emits CoinsRemoved for every previously-admitted UTXO this tx spends.
//
// No 1-sat invariant — buy vaults carry the buyer's locked BSV
// (priceSats + settlement-fee buffer), typically thousands of sats.
func (m *OrdLockBuyTopicManager) Admit(txData []byte, previousUTXOs []overlay.AdmittedOutput) (*overlay.AdmittanceInstructions, error) {
	tx, err := transaction.NewTransactionFromBytes(txData)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction: %w", err)
	}

	txid := tx.TxID().String()
	now := time.Now().UTC().Format(time.RFC3339)

	var outputsToAdmit []int
	outputMetadata := make(map[int]json.RawMessage)

	for vout, out := range tx.Outputs {
		if out.LockingScript == nil {
			continue
		}
		entry := parseOrdLockBuyScript(out.LockingScript.Bytes())
		if entry == nil {
			continue
		}
		entry.Outpoint = fmt.Sprintf("%s_%d", txid, vout)
		entry.VaultSats = int64(out.Satoshis)
		entry.AdmittedAt = now

		meta, err := json.Marshal(entry)
		if err != nil {
			continue
		}
		outputsToAdmit = append(outputsToAdmit, vout)
		outputMetadata[vout] = meta
	}

	var coinsRemoved []int
	for i := range previousUTXOs {
		coinsRemoved = append(coinsRemoved, i)
	}

	if len(outputsToAdmit) == 0 && len(coinsRemoved) == 0 {
		return nil, nil
	}

	return &overlay.AdmittanceInstructions{
		OutputsToAdmit: outputsToAdmit,
		CoinsRemoved:   coinsRemoved,
		OutputMetadata: outputMetadata,
	}, nil
}

// GetDocumentation returns a description of the OrdLockBuy topic.
func (m *OrdLockBuyTopicManager) GetDocumentation() string {
	return "OrdLockBuy Vaults: Tracks free-agent buy-side BSV-locked vaults (Rúnar-compiled OrdLockBuy covenant). Admits any output that matches the canonical artifact byte structure regardless of sat value."
}

// GetMetadata returns machine-readable metadata about the topic.
func (m *OrdLockBuyTopicManager) GetMetadata() map[string]interface{} {
	return map[string]interface{}{
		"protocol": "ordlock-buy",
		"variants": []string{"bsv-20", "bsv-21"},
		"purpose":  "free-agent-buy-side-limit-orders",
	}
}

// Compile-time conformance check.
var _ overlay.TopicManager = (*OrdLockBuyTopicManager)(nil)

// parseOrdLockBuyScript walks the input script in lockstep with the artifact
// template. Returns a partially-populated OrdLockBuyEntry (Outpoint,
// VaultSats, AdmittedAt are filled by Admit) when the script matches the
// canonical OrdLockBuy layout. Returns nil for any other script.
func parseOrdLockBuyScript(script []byte) *OrdLockBuyEntry {
	scriptHex := hex.EncodeToString(script)

	// Cheap rejects first.
	if len(script) < len(olockBuyPrefixBytes)+len(olockBuySuffixBytes) {
		return nil
	}
	if !startsWith(script, olockBuyPrefixBytes) {
		return nil
	}
	if !endsWith(script, olockBuySuffixBytes) {
		return nil
	}

	// Walk slots. inputCursor advances through the input script bytes.
	inputCursor := len(olockBuyPrefixBytes)
	captured := make(map[ordLockBuyParamName]string, 6)

	for i, slot := range ordLockBuySlots {
		// For slots after the first, verify inter-slot fixed bytes.
		if i > 0 {
			interBytes := olockBuyInterSlots[i]
			if inputCursor+len(interBytes) > len(script) {
				return nil
			}
			if !bytesEqual(script[inputCursor:inputCursor+len(interBytes)], interBytes) {
				return nil
			}
			inputCursor += len(interBytes)
		}

		// Read pushdata at inputCursor.
		payload, next, ok := readPush(script, inputCursor)
		if !ok {
			return nil
		}
		// Length check (when expectedBytes > 0).
		if slot.expectedBytes > 0 && len(payload) != slot.expectedBytes {
			return nil
		}
		payloadHex := hex.EncodeToString(payload)
		// Fixed-value check (P2PKH constants).
		if slot.expectedHex != "" && !strings.EqualFold(payloadHex, slot.expectedHex) {
			return nil
		}

		// Capture for later. Repeated params (P2PKH constants) overwrite —
		// they're invariant so the value is the same anyway.
		captured[slot.param] = payloadHex
		inputCursor = next
	}

	// After last slot, the trailing bytes must equal the suffix exactly.
	if inputCursor != len(script)-len(olockBuySuffixBytes) {
		return nil
	}
	// Suffix already verified by endsWith above.

	// Validate captured fields.
	priceSatsLE, ok := captured[paramPriceSatsLE]
	if !ok || len(priceSatsLE) != 16 {
		return nil
	}
	cancelPkh, ok := captured[paramCancelPkh]
	if !ok || len(cancelPkh) != 40 {
		return nil
	}
	buyerPubKey, ok := captured[paramBuyerPubKey]
	if !ok || len(buyerPubKey) != 66 {
		return nil
	}
	expectedOutput0Bytes, ok := captured[paramExpectedOutput0Bytes]
	if !ok || expectedOutput0Bytes == "" {
		return nil
	}

	priceSats, err := decodePriceSatsLE(priceSatsLE)
	if err != nil {
		return nil
	}

	entry := &OrdLockBuyEntry{
		PriceSats:          priceSats,
		CancelPkhHex:       strings.ToLower(cancelPkh),
		BuyerPubKeyHex:     strings.ToLower(buyerPubKey),
		ExpectedOutput0Hex: strings.ToLower(expectedOutput0Bytes),
		ScriptHex:          strings.ToLower(scriptHex),
	}

	// Best-effort token-transfer decode from expectedOutput0Bytes for
	// server-side filterability. Failure here is non-fatal.
	if proto, tokenId, tick, amt := tryParseTransferFromOutput0Hex(expectedOutput0Bytes); proto != "" {
		entry.Protocol = proto
		entry.TokenId = tokenId
		entry.Tick = tick
		entry.RequestedAmount = amt
	}

	return entry
}

// decodePriceSatsLE decodes 8-byte little-endian hex into an int64.
// Caps at int64 max to keep wire shape signed.
func decodePriceSatsLE(hexStr string) (int64, error) {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return 0, err
	}
	if len(b) != 8 {
		return 0, fmt.Errorf("priceSatsLE must be 8 bytes, got %d", len(b))
	}
	var sats uint64
	for i := 0; i < 8; i++ {
		sats |= uint64(b[i]) << (8 * i)
	}
	if sats > 1<<62 {
		return 0, fmt.Errorf("priceSats overflow")
	}
	if sats < 1 {
		return 0, fmt.Errorf("priceSats must be positive")
	}
	return int64(sats), nil
}

// tryParseTransferFromOutput0Hex best-effort-decodes the inscription JSON
// inside the expectedOutput0Bytes blob. Returns ("", "", "", "") on any
// parse failure.
//
// Wire shape (canonical 1Sat-style transfer output 0):
//   8 bytes satoshis LE (0x0100000000000000)
//   varint scriptLen
//   scriptLen bytes script: OP_0 OP_IF "ord" OP_1 <mime> OP_0 <json> OP_ENDIF
//                           + P2PKH transfer to buyerOrdAddress
func tryParseTransferFromOutput0Hex(out0Hex string) (proto, tokenId, tick, amount string) {
	defer func() { _ = recover() }()

	if len(out0Hex) < 16+2 {
		return "", "", "", ""
	}
	cursor := 16 // skip 8-byte sats
	lenByte, err := strconv.ParseUint(out0Hex[cursor:cursor+2], 16, 8)
	if err != nil {
		return "", "", "", ""
	}
	var scriptLen int
	switch {
	case lenByte < 0xfd:
		scriptLen = int(lenByte)
		cursor += 2
	case lenByte == 0xfd:
		if cursor+6 > len(out0Hex) {
			return "", "", "", ""
		}
		lo, err1 := strconv.ParseUint(out0Hex[cursor+2:cursor+4], 16, 8)
		hi, err2 := strconv.ParseUint(out0Hex[cursor+4:cursor+6], 16, 8)
		if err1 != nil || err2 != nil {
			return "", "", "", ""
		}
		scriptLen = int(lo) | (int(hi) << 8)
		cursor += 6
	default:
		// OP_PUSHDATA4 not realistic for inscription
		return "", "", "", ""
	}
	if cursor+scriptLen*2 > len(out0Hex) {
		return "", "", "", ""
	}
	scriptHex := out0Hex[cursor : cursor+scriptLen*2]

	// Find JSON payload — between `7b22` (start of `{"`) and `227d` (end of `"}` or just `}`).
	start := strings.Index(scriptHex, "7b22")
	if start < 0 {
		return "", "", "", ""
	}
	end := strings.Index(scriptHex[start:], "227d")
	if end < 0 {
		return "", "", "", ""
	}
	jsonHex := scriptHex[start : start+end+4]

	jsonBytes, err := hex.DecodeString(jsonHex)
	if err != nil {
		return "", "", "", ""
	}

	var insc struct {
		P    string      `json:"p"`
		Op   string      `json:"op"`
		Amt  json.Number `json:"amt"`
		Id   string      `json:"id,omitempty"`
		Tick string      `json:"tick,omitempty"`
	}
	if err := json.Unmarshal(jsonBytes, &insc); err != nil {
		return "", "", "", ""
	}
	if insc.P != "bsv-20" || insc.Op != "transfer" || insc.Amt == "" {
		return "", "", "", ""
	}
	amtUint, err := strconv.ParseUint(string(insc.Amt), 10, 64)
	if err != nil || amtUint < 1 {
		return "", "", "", ""
	}
	if bsv21TokenRE.MatchString(insc.Id) {
		return "bsv-21", insc.Id, "", string(insc.Amt)
	}
	if insc.Tick != "" {
		upper := strings.ToUpper(insc.Tick)
		if bsv20TickRE.MatchString(upper) {
			return "bsv-20", "", upper, string(insc.Amt)
		}
	}
	return "", "", "", ""
}
