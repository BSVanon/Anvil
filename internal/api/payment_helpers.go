package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
)

// --- Helpers ---

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func base64Url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func canonicalHeaderHash(r *http.Request) string {
	bindHeaders := []string{"host", "content-type", "accept"}
	var pairs []string
	for _, name := range bindHeaders {
		val := r.Header.Get(name)
		if val == "" && name == "host" {
			val = r.Host
		}
		if val != "" {
			pairs = append(pairs, name+":"+strings.TrimSpace(val))
		}
	}
	sort.Strings(pairs)
	canonical := strings.Join(pairs, "\n") + "\n"
	return sha256Hex([]byte(canonical))
}
