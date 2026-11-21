package content

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// envScript joins script fragments given as hex strings or raw bytes.
func envScript(t *testing.T, parts ...interface{}) []byte {
	t.Helper()
	var out []byte
	for _, p := range parts {
		switch v := p.(type) {
		case string:
			b, err := hex.DecodeString(v)
			if err != nil {
				t.Fatalf("bad hex %q: %v", v, err)
			}
			out = append(out, b...)
		case []byte:
			out = append(out, v...)
		default:
			t.Fatalf("unsupported part %T", p)
		}
	}
	return out
}

// push encodes data as one minimal-length push.
func push(data []byte) []byte {
	switch n := len(data); {
	case n == 0:
		return []byte{0x00}
	case n <= 75:
		return append([]byte{byte(n)}, data...)
	case n <= 0xff:
		return append([]byte{0x4c, byte(n)}, data...)
	default:
		return append([]byte{0x4d, byte(n), byte(n >> 8)}, data...)
	}
}

const (
	hdr  = "0063036f7264" // OP_FALSE OP_IF "ord"
	p2pk = "76a914000102030405060708090a0b0c0d0e0f1011121388ac"
)

func TestParseOrdEnvelope(t *testing.T) {
	ct := push([]byte("text/html"))
	body := push([]byte("<p>hi</p>"))
	parent := push(append(bytes.Repeat([]byte{0xab}, 32), 0x00, 0x00, 0x00, 0x00)) // a 36-byte outpoint, vout 0

	cases := []struct {
		name     string
		script   []byte
		ok       bool
		wantCT   string
		wantBody string
	}{
		{"plain", envScript(t, hdr, "51", ct, "00", body, "68"), true, "text/html", "<p>hi</p>"},
		{"after a lock", envScript(t, p2pk, hdr, "51", ct, "00", body, "68"), true, "text/html", "<p>hi</p>"},
		{"before a lock", envScript(t, hdr, "51", ct, "00", body, "68", p2pk), true, "text/html", "<p>hi</p>"},
		{"tag aliases 0x01 and 0x00", envScript(t, hdr, "0101", ct, "0100", body, "68"), true, "text/html", "<p>hi</p>"},
		{"last content type wins", envScript(t, hdr, "51", push([]byte("text/plain")), "51", ct, "00", body, "68"), true, "text/html", "<p>hi</p>"},
		{"unknown parent field holding zero bytes", envScript(t, hdr, "51", ct, "53", parent, "00", body, "68"), true, "text/html", "<p>hi</p>"},
		{"unknown wide-tag field", envScript(t, hdr, push([]byte("ab")), push([]byte("xyz")), "51", ct, "00", body, "68"), true, "text/html", "<p>hi</p>"},
		{"empty body", envScript(t, hdr, "51", ct, "00", "00", "68"), true, "text/html", ""},
		{"no content type", envScript(t, hdr, "00", body, "68"), true, "", "<p>hi</p>"},
		{"pushdata2 body", envScript(t, hdr, "51", ct, "00", push(bytes.Repeat([]byte("x"), 300)), "68"), true, "text/html", string(bytes.Repeat([]byte("x"), 300))},
		{"no body", envScript(t, hdr, "51", ct, "68"), false, "", ""},
		{"no OP_ENDIF after body", envScript(t, hdr, "51", ct, "00", body), false, "", ""},
		{"a field after the body", envScript(t, hdr, "00", body, "51", ct, "68"), false, "", ""},
		{"non-push tag", envScript(t, hdr, "76", ct, "00", body, "68"), false, "", ""},
		{"small-number body value", envScript(t, hdr, "00", "51", "68"), false, "", ""},
		{"marker inside a push", envScript(t, push(envScript(t, hdr, "00", body, "68"))), false, "", ""},
		{"truncated push", envScript(t, hdr, "51", "0a", "6162"), false, "", ""},
		{"no envelope", envScript(t, p2pk), false, "", ""},
		{"malformed then well-formed", envScript(t, hdr, "00", body, "51", "68", hdr, "51", ct, "00", body, "68"), true, "text/html", "<p>hi</p>"},
		{"OP_IF without OP_FALSE", envScript(t, "63036f7264", "00", body, "68"), false, "", ""},
		{"ord pushed with pushdata1", envScript(t, "00634c036f7264", "00", body, "68"), false, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, ok := ParseOrdEnvelope(tc.script)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if !ok {
				return
			}
			if env.ContentType != tc.wantCT || string(env.Body) != tc.wantBody {
				t.Fatalf("got (%q, %q), want (%q, %q)", env.ContentType, env.Body, tc.wantCT, tc.wantBody)
			}
			if env.Body == nil {
				t.Fatal("body must never be nil")
			}
		})
	}
}

// TestParseInscriptionParentField pins what changed for /content: an
// envelope carrying a parent outpoint (field 3) whose bytes include 0x00 used
// to be read byte by byte, the 0x00 taken as the body tag, and the output
// reported as holding no inscription.
func TestParseInscriptionParentField(t *testing.T) {
	parent := push(append(bytes.Repeat([]byte{0x11}, 32), 0x00, 0x00, 0x00, 0x00))
	lock := envScript(t, hdr, "51", push([]byte("image/webp")), "53", parent, "00", push([]byte("RIFF")), "68", p2pk)

	// version 1, one input (null prevout, empty script), one 1-sat output.
	tx := envScript(t, "01000000", "01", bytes.Repeat([]byte{0}, 32), "ffffffff", "00", "ffffffff", "01", "0100000000000000")
	tx = append(tx, varIntBytes(len(lock))...)
	tx = append(tx, lock...)
	tx = append(tx, 0, 0, 0, 0)

	insc, err := parseInscription(hex.EncodeToString(tx), "0")
	if err != nil {
		t.Fatalf("parseInscription: %v", err)
	}
	if insc.ContentType != "image/webp" || string(insc.Data) != "RIFF" {
		t.Fatalf("got (%q, %q)", insc.ContentType, insc.Data)
	}
}

func varIntBytes(n int) []byte {
	switch {
	case n < 0xfd:
		return []byte{byte(n)}
	case n <= 0xffff:
		return []byte{0xfd, byte(n), byte(n >> 8)}
	default:
		return []byte{0xfe, byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)}
	}
}
