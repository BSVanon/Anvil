package messaging

// WHATWG host-parsing helpers split out of home.go: qualifyAndNormalise
// (home.go) calls parseWHATWGIPv4 to recognise a dotted- or bare-number host
// as an IPv4 literal the same way a browser's URL parser would, so it is
// normalised the same way canon normalises it.

import (
	"fmt"
	"strconv"
	"strings"
)

// parseWHATWGIPv4 re-parses host as an IPv4 address exactly the way the
// WHATWG URL Standard's host parser does for a domain that "ends in a
// number" (url.spec.whatwg.org/#concept-ipv4-parser), returning its
// canonical dotted-quad form. ok is false if host has more than four
// dot-separated parts, any part fails parseWHATWGIPv4Number, a non-last
// part exceeds 255, or the last part is too wide for the bits its
// position leaves it (256^(5-numParts) — a single bare part like
// "2130706433" leaves all 4 bytes/32 bits, four explicit parts leave
// just the last 8 bits, and so on).
//
// The real standard first runs a separate "ends in a number" checker
// (url.spec.whatwg.org/#ends-in-a-number-checker) on just the LAST part,
// and only attempts this full parse if that returns true; a plain
// domain label fails that checker before ever reaching here. This port
// collapses the two into one pass: attempting the full parse directly
// and reporting ok=false on any failure reaches an identical place
// (treat host as an ordinary domain) for every input that matters here,
// without a hostname ever being misread as numeric when it isn't — the
// per-part parseWHATWGIPv4Number call is exactly as strict as the
// checker's own "contains only ASCII digits, or itself parses as an
// IPv4 number" test, just run eagerly on every part instead of only the
// last.
func parseWHATWGIPv4(host string) (string, bool) {
	parts := strings.Split(host, ".")
	if len(parts) > 1 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1] // a trailing "." (absolute FQDN notation)
	}
	if len(parts) == 0 || len(parts) > 4 {
		return "", false
	}
	numbers := make([]uint64, len(parts))
	for i, p := range parts {
		n, ok := parseWHATWGIPv4Number(p)
		if !ok {
			return "", false
		}
		numbers[i] = n
	}
	for i := 0; i < len(numbers)-1; i++ {
		if numbers[i] > 255 {
			return "", false
		}
	}
	last := numbers[len(numbers)-1]
	maxLast := uint64(1) << uint(8*(5-len(numbers)))
	if last >= maxLast {
		return "", false
	}
	ipv4 := last
	for i := 0; i < len(numbers)-1; i++ {
		ipv4 += numbers[i] << uint(8*(3-i))
	}
	return fmt.Sprintf("%d.%d.%d.%d", byte(ipv4>>24), byte(ipv4>>16), byte(ipv4>>8), byte(ipv4)), true
}

// parseWHATWGIPv4Number parses one dot-separated part per the WHATWG URL
// Standard's IPv4 number parser (#ipv4-number-parser): a leading "0x" or
// "0X" selects hex, a leading "0" (with more digits following) selects
// octal, otherwise decimal. ok is false if what remains after stripping
// a radix prefix contains a digit invalid for that radix (ASCII hex
// digits for 0-15, exactly as the standard specifies).
func parseWHATWGIPv4Number(part string) (uint64, bool) {
	if part == "" {
		return 0, false
	}
	radix := 10
	switch {
	case len(part) >= 2 && (part[:2] == "0x" || part[:2] == "0X"):
		part, radix = part[2:], 16
	case len(part) >= 2 && part[0] == '0':
		part, radix = part[1:], 8
	}
	if part == "" {
		return 0, true // a bare "0", or "0x"/"0X" with nothing after — the standard returns (0, true), not failure
	}
	n, err := strconv.ParseUint(part, radix, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}
