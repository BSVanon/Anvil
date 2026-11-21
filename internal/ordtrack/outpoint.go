package ordtrack

import (
	"strconv"
	"strings"
)

// NormalizeOutpoint returns outpoint as "txid_vout" with a lowercase txid.
// It accepts BRC-159's two string forms, "txid_vout" and "txid.vout".
func NormalizeOutpoint(outpoint string) (string, bool) {
	txid, vout, ok := splitOutpoint(outpoint)
	if !ok {
		return "", false
	}
	return outpointString(txid, vout), true
}

// splitOutpoint parses "txid_vout" or "txid.vout".
func splitOutpoint(outpoint string) (txid string, vout uint32, ok bool) {
	i := strings.LastIndexAny(outpoint, "_.")
	if i != 64 || !isHex(outpoint[:i]) {
		return "", 0, false
	}
	n, err := strconv.ParseUint(outpoint[i+1:], 10, 32)
	if err != nil {
		return "", 0, false
	}
	return strings.ToLower(outpoint[:i]), uint32(n), true
}

func outpointString(txid string, vout uint32) string {
	return txid + "_" + strconv.FormatUint(uint64(vout), 10)
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// isTxid reports whether s is 64 hex characters.
func isTxid(s string) bool { return len(s) == 64 && isHex(s) }
