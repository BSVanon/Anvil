package main

import (
	"fmt"
	"strings"
)

// tomlStringArray renders a Go string slice as a single-line TOML array
// literal, e.g. ["a", "b"] or [] for an empty/nil slice. Every item is
// escaped (tomlEscapeString) before quoting: a peer's mesh/overlay URL is
// validated for scheme and host only (validateGatewayPeerURL), so a
// quote character surviving inside its path or query — net/url.Parse
// accepts one there — would otherwise break out of this array's string
// literal.
func tomlStringArray(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = `"` + tomlEscapeString(s) + `"`
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// tomlEscapeString escapes s for safe interpolation inside a TOML basic
// (double-quoted) string literal: backslash and double quote, which
// would otherwise end the literal early and let whatever follows be
// parsed as new TOML, and the C0 control characters a conforming parser
// (BurntSushi/toml, which internal/config.Load uses) would otherwise
// reject outright or, for a raw newline, treat as ending the line. Every
// string the gateway config template renders into a `"..."` slot goes
// through this, rather than relying on each upstream validator to have
// already ruled out every character that matters here.
func tomlEscapeString(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}
