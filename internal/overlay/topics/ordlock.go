// OrdLock topic manager — admits canonical 1Sat OrdLock self-settling
// fixed-price listings (BSV-20 + BSV-21). See docs/internal/ORDLOCK_TOPIC_REQUEST.md.
//
// The covenant constants below are byte-identical to the canonical TypeScript
// reference at Anvil-Swap repo `src/ordlock/covenant.ts`. Do not edit without
// re-verifying parity against live mainnet listings.
package topics

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/BSVanon/Anvil/internal/overlay"
	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// OrdLockTopicName is the BRC-87 topic name for OrdLock listings.
const OrdLockTopicName = "tm_ordlock_listings"

// OLOCK_PREFIX_HEX is the 102-byte covenant preamble. Vendored from
// @bsv/wallet-helper + js-1sat-ord; byte-parity verified against fixtures
// at Anvil-Swap repo `src/ordlock/__fixtures__/bsv21-{tvzn,ordi}.json`.
const OLOCK_PREFIX_HEX = "2097dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff0262102ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382201008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c0000"

// OLOCK_SUFFIX_HEX is the 702-byte covenant body. See OLOCK_PREFIX_HEX note.
const OLOCK_SUFFIX_HEX = "615179547a75537a537a537a0079537a75527a527a7575615579008763567901c161517957795779210ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda43ad905aadbffc800206c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da8074ce081059795679615679aa0079610079517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e81517a75615779567956795679567961537956795479577995939521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00517951796151795179970079009f63007952799367007968517a75517a75517a7561527a75517a517951795296a0630079527994527a75517a6853798277527982775379012080517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01205279947f7754537993527993013051797e527e54797e58797e527e53797e52797e57797e0079517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a756100795779ac517a75517a75517a75517a75517a75517a75517a75517a75517a7561517a75517a756169587951797e58797eaa577961007982775179517958947f7551790128947f77517a75517a75618777777777777777777767557951876351795779a9876957795779ac777777777777777767006868"

// inscription envelope opcodes (raw bytes, not hex):
//   00         OP_0
//   63         OP_IF
//   03 6f7264  push "ord" (3-byte direct push)
//   51         OP_1
//   12 ...     push "application/bsv-20" (18-byte direct push)
//   00         OP_0  (placeholder for inscription metadata)
//   <push>     inscription JSON
//   68         OP_ENDIF
var (
	olockPrefixBytes []byte
	olockSuffixBytes []byte
	envelopeStart    = []byte{
		0x00, 0x63,
		0x03, 0x6f, 0x72, 0x64,
		0x51,
		0x12, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x62, 0x73, 0x76, 0x2d, 0x32, 0x30,
		0x00,
	}
	bsv20TickRE  = regexp.MustCompile(`^[A-Z0-9]{1,4}$`)
	bsv21TokenRE = regexp.MustCompile(`^[0-9a-fA-F]{64}_\d+$`)
)

func init() {
	var err error
	if olockPrefixBytes, err = hex.DecodeString(OLOCK_PREFIX_HEX); err != nil || len(olockPrefixBytes) != 102 {
		panic(fmt.Sprintf("ordlock: OLOCK_PREFIX_HEX is malformed (len=%d, err=%v)", len(olockPrefixBytes), err))
	}
	if olockSuffixBytes, err = hex.DecodeString(OLOCK_SUFFIX_HEX); err != nil || len(olockSuffixBytes) != 702 {
		panic(fmt.Sprintf("ordlock: OLOCK_SUFFIX_HEX is malformed (len=%d, err=%v)", len(olockSuffixBytes), err))
	}
}

// OrdLockEntry is the per-listing metadata stored on each admitted output.
// The wire shape is consumed by Anvil-Swap's discovery library.
type OrdLockEntry struct {
	Outpoint     string `json:"outpoint"`            // "<txid>_<vout>" — unique key
	Protocol     string `json:"protocol"`            // "bsv-20" or "bsv-21"
	TokenId      string `json:"tokenId,omitempty"`   // BSV-21 only
	Tick         string `json:"tick,omitempty"`      // BSV-20 only (uppercase)
	Amount       string `json:"amount"`              // stringified atomic units
	PriceSats    int64  `json:"priceSats"`
	PayAddress   string `json:"payAddress"`          // base58check mainnet P2PKH from covenant
	CancelPkhHex string `json:"cancelPkhHex"`        // 20-byte hex, lowercase
	ScriptHex    string `json:"scriptHex"`           // full locking script
	AdmittedAt   string `json:"admittedAt"`          // RFC3339 UTC timestamp at admit time
}

// OrdLockTopicManager implements overlay.TopicManager for OrdLock listings.
type OrdLockTopicManager struct{}

// NewOrdLockTopicManager creates an OrdLock topic manager.
func NewOrdLockTopicManager() *OrdLockTopicManager {
	return &OrdLockTopicManager{}
}

// Admit scans every output for canonical OrdLock listings, admits each one,
// and emits CoinsRemoved for every previously-admitted UTXO this tx spends
// (covers both buyer-take and seller-cancel paths).
//
// Stale-listing caveat: spend detection only fires when the spending tx is
// itself submitted to /overlay/submit. Direct broadcasts leave entries
// admitted until GASP/BRC-64 history retention lands. Documented in
// docs/internal/ORDLOCK_TOPIC_REQUEST.md (N1) and the alignment plan.
func (m *OrdLockTopicManager) Admit(txData []byte, previousUTXOs []overlay.AdmittedOutput) (*overlay.AdmittanceInstructions, error) {
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
		// 1Sat invariant: a canonical OrdLock listing is always a 1-sat
		// ordinal output. Reject covenant-shaped outputs at any other value
		// — they aren't real listings and the DEX path can't take them.
		if out.Satoshis != 1 {
			continue
		}
		entry := parseOrdLockScript(out.LockingScript.Bytes())
		if entry == nil {
			continue
		}
		entry.Outpoint = fmt.Sprintf("%s_%d", txid, vout)
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

// GetDocumentation returns a description of the OrdLock topic.
func (m *OrdLockTopicManager) GetDocumentation() string {
	return "OrdLock Listings: Tracks canonical 1Sat OrdLock self-settling fixed-price BSV-20/BSV-21 listings. Admits any output that matches the vendored OrdLock covenant byte-structure."
}

// GetMetadata returns machine-readable metadata about the OrdLock topic.
func (m *OrdLockTopicManager) GetMetadata() map[string]interface{} {
	return map[string]interface{}{
		"protocol": "ordlock",
		"variants": []string{"bsv-20", "bsv-21"},
		"purpose":  "fixed-price-marketplace-listings",
	}
}

// Compile-time conformance check.
var _ overlay.TopicManager = (*OrdLockTopicManager)(nil)

// parseOrdLockScript returns a partially-populated OrdLockEntry (Outpoint and
// AdmittedAt are filled by Admit) when the script matches the canonical
// inscription-first OrdLock layout. Returns nil for any other script — fail-closed.
func parseOrdLockScript(script []byte) *OrdLockEntry {
	// Cheapest reject first: must end with the covenant suffix.
	if len(script) < len(envelopeStart)+len(olockPrefixBytes)+len(olockSuffixBytes)+22 /* min cancelPkh+payOutput pushes */ {
		return nil
	}
	if !endsWith(script, olockSuffixBytes) {
		return nil
	}
	if !startsWith(script, envelopeStart) {
		return nil
	}

	cursor := len(envelopeStart)

	// Inscription JSON push.
	jsonPayload, next, ok := readPush(script, cursor)
	if !ok {
		return nil
	}
	cursor = next

	// OP_ENDIF.
	if cursor >= len(script) || script[cursor] != 0x68 {
		return nil
	}
	cursor++

	// OLOCK_PREFIX (102 raw bytes).
	if cursor+len(olockPrefixBytes) > len(script) {
		return nil
	}
	if !bytesEqual(script[cursor:cursor+len(olockPrefixBytes)], olockPrefixBytes) {
		return nil
	}
	cursor += len(olockPrefixBytes)

	// cancelPkh push — must be exactly 20 bytes (opcode 0x14 + 20 bytes).
	cancelPkh, next, ok := readPush(script, cursor)
	if !ok || len(cancelPkh) != 20 {
		return nil
	}
	cursor = next

	// payOutput push — variable; canonical is 8 sats LE + varint scriptLen + 25-byte P2PKH.
	payOutput, next, ok := readPush(script, cursor)
	if !ok {
		return nil
	}
	cursor = next

	// Remainder must be exactly OLOCK_SUFFIX.
	if cursor+len(olockSuffixBytes) != len(script) {
		return nil
	}
	if !bytesEqual(script[cursor:], olockSuffixBytes) {
		return nil
	}

	// Decode inscription JSON.
	var insc struct {
		P    string `json:"p"`
		Op   string `json:"op"`
		Amt  string `json:"amt"`
		Id   string `json:"id,omitempty"`
		Tick string `json:"tick,omitempty"`
	}
	if err := json.Unmarshal(jsonPayload, &insc); err != nil {
		return nil
	}
	if insc.P != "bsv-20" || insc.Op != "transfer" || insc.Amt == "" {
		return nil
	}
	amt, err := strconv.ParseUint(insc.Amt, 10, 64)
	if err != nil || amt < 1 {
		return nil
	}

	// Decode payOutput.
	priceSats, payAddress, ok := parsePayOutput(payOutput)
	if !ok {
		return nil
	}

	entry := &OrdLockEntry{
		Amount:       insc.Amt,
		PriceSats:    priceSats,
		PayAddress:   payAddress,
		CancelPkhHex: hex.EncodeToString(cancelPkh),
		ScriptHex:    hex.EncodeToString(script),
	}

	// Prefer BSV-21 if `id` matches `<64-hex>_<vout>` — matches GorillaPool
	// classification + canonical emitter. Otherwise try BSV-20 by tick.
	if bsv21TokenRE.MatchString(insc.Id) {
		entry.Protocol = "bsv-21"
		entry.TokenId = insc.Id
		return entry
	}
	if insc.Tick != "" {
		upper := strings.ToUpper(insc.Tick)
		if bsv20TickRE.MatchString(upper) {
			entry.Protocol = "bsv-20"
			entry.Tick = upper
			return entry
		}
	}
	return nil
}

// parsePayOutput decodes the inner output blob: 8-byte sats LE + varint
// scriptLen + canonical P2PKH script. Returns priceSats + base58check mainnet
// address. Non-P2PKH payout scripts and zero prices are rejected.
func parsePayOutput(blob []byte) (int64, string, bool) {
	if len(blob) < 8+1 {
		return 0, "", false
	}

	// 8-byte sats LE → uint64.
	var sats uint64
	for i := 0; i < 8; i++ {
		sats |= uint64(blob[i]) << (8 * i)
	}
	// Cap at int64 max to keep wire shape signed.
	if sats > 1<<62 {
		return 0, "", false
	}
	priceSats := int64(sats)
	if priceSats < 1 {
		return 0, "", false
	}

	// Varint scriptLen.
	cursor := 8
	first := blob[cursor]
	var scriptLen int
	switch {
	case first < 0xfd:
		scriptLen = int(first)
		cursor++
	case first == 0xfd:
		if cursor+3 > len(blob) {
			return 0, "", false
		}
		scriptLen = int(blob[cursor+1]) | int(blob[cursor+2])<<8
		cursor += 3
	default:
		// >64k script in a payOutput is non-canonical for OrdLock.
		return 0, "", false
	}

	if cursor+scriptLen != len(blob) {
		return 0, "", false
	}
	scr := blob[cursor:]

	// Canonical mainnet P2PKH only: 76 a9 14 <20-byte pkh> 88 ac.
	if len(scr) != 25 || scr[0] != 0x76 || scr[1] != 0xa9 || scr[2] != 0x14 || scr[23] != 0x88 || scr[24] != 0xac {
		return 0, "", false
	}
	pkh := scr[3:23]
	addr, err := bsvscript.NewAddressFromPublicKeyHash(pkh, true)
	if err != nil || addr == nil || addr.AddressString == "" {
		return 0, "", false
	}
	return priceSats, addr.AddressString, true
}

// readPush reads a single push-data instruction at cursor.
// Supports OP_0..OP_16, direct push (1-75), OP_PUSHDATA1/2/4.
// Returns (payload, nextCursor, ok).
func readPush(script []byte, cursor int) ([]byte, int, bool) {
	if cursor >= len(script) {
		return nil, 0, false
	}
	op := script[cursor]
	cursor++

	switch {
	case op == 0x00:
		return []byte{}, cursor, true
	case op >= 0x51 && op <= 0x60:
		// OP_1..OP_16 → single-byte payload 0x01..0x10.
		return []byte{op - 0x50}, cursor, true
	case op >= 0x01 && op <= 0x4b:
		size := int(op)
		if cursor+size > len(script) {
			return nil, 0, false
		}
		return script[cursor : cursor+size], cursor + size, true
	case op == 0x4c:
		if cursor+1 > len(script) {
			return nil, 0, false
		}
		size := int(script[cursor])
		cursor++
		if cursor+size > len(script) {
			return nil, 0, false
		}
		return script[cursor : cursor+size], cursor + size, true
	case op == 0x4d:
		if cursor+2 > len(script) {
			return nil, 0, false
		}
		size := int(script[cursor]) | int(script[cursor+1])<<8
		cursor += 2
		if cursor+size > len(script) {
			return nil, 0, false
		}
		return script[cursor : cursor+size], cursor + size, true
	case op == 0x4e:
		if cursor+4 > len(script) {
			return nil, 0, false
		}
		size := int(script[cursor]) | int(script[cursor+1])<<8 | int(script[cursor+2])<<16 | int(script[cursor+3])<<24
		cursor += 4
		if size < 0 || cursor+size > len(script) {
			return nil, 0, false
		}
		return script[cursor : cursor+size], cursor + size, true
	default:
		return nil, 0, false
	}
}

func startsWith(haystack, needle []byte) bool {
	return len(haystack) >= len(needle) && bytesEqual(haystack[:len(needle)], needle)
}

func endsWith(haystack, needle []byte) bool {
	return len(haystack) >= len(needle) && bytesEqual(haystack[len(haystack)-len(needle):], needle)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
