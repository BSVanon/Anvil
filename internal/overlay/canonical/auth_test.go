package canonical

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

const testClientIdentityKey = "028d37b941208cd6b8a4c28288eda5f2f16c2b3ab0fcb6d13c18b47fe37b971fc1"

func phase1Request(t *testing.T, headers map[string]string, body map[string]any) *http.Request {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	r := httptest.NewRequest("POST", "/.well-known/auth", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestPhase1_HappyPath(t *testing.T) {
	h := New(Config{Auth: AuthConfig{}})

	req := phase1Request(t,
		map[string]string{
			HeaderAuthVersion:     AuthVersionV01,
			HeaderAuthIdentityKey: testClientIdentityKey,
			HeaderAuthNonce:       "dGVzdE5vbmNlMTIzNA==",
		},
		map[string]any{
			"messageType":  MessageTypeInitialRequest,
			"version":      AuthVersionV01,
			"identityKey":  testClientIdentityKey,
			"initialNonce": "dGVzdE5vbmNlMTIzNA==",
		},
	)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	// Vector .2: required response headers must all be present.
	required := []string{
		HeaderAuthVersion,
		HeaderAuthMessageType,
		HeaderAuthIdentityKey,
		HeaderAuthNonce,
		HeaderAuthYourNonce,
		HeaderAuthSignature,
	}
	for _, hdr := range required {
		if rec.Header().Get(hdr) == "" {
			t.Errorf("response missing required header %q", hdr)
		}
	}

	// Vector .1: body_shape fields must all be present.
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse: %v\n%s", err, rec.Body.String())
	}
	for _, key := range []string{"messageType", "version", "identityKey", "nonce", "yourNonce", "signature"} {
		if _, ok := got[key]; !ok {
			t.Errorf("body missing field %q (got: %v)", key, got)
		}
	}
	if got["messageType"] != MessageTypeInitialResponse {
		t.Errorf("messageType = %v, want %s", got["messageType"], MessageTypeInitialResponse)
	}
	if _, isArray := got["signature"].([]any); !isArray {
		t.Errorf("signature is not an array (got %T: %v)", got["signature"], got["signature"])
	}
}

func TestPhase1_MissingIdentityKey_401(t *testing.T) {
	h := New(Config{Auth: AuthConfig{}})
	req := phase1Request(t,
		map[string]string{
			HeaderAuthVersion: AuthVersionV01,
			HeaderAuthNonce:   "dGVzdE5vbmNlMTIzNA==",
		},
		map[string]any{
			"messageType": MessageTypeInitialRequest,
			"version":     AuthVersionV01,
			"identityKey": testClientIdentityKey,
		},
	)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got["status"] != "error" || got["code"] != "UNAUTHORIZED" {
		t.Errorf("body = %v, want status=error code=UNAUTHORIZED", got)
	}
}

func TestPhase1_MissingNonce_401(t *testing.T) {
	h := New(Config{Auth: AuthConfig{}})
	req := phase1Request(t,
		map[string]string{
			HeaderAuthVersion:     AuthVersionV01,
			HeaderAuthIdentityKey: testClientIdentityKey,
		},
		map[string]any{
			"messageType": MessageTypeInitialRequest,
		},
	)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestMiddleware_AllowUnauthenticatedPassthrough(t *testing.T) {
	// Vector .9: middleware configured with allowUnauthenticated=true, no
	// auth headers on request, downstream handler sees identityKey="unknown".
	var seenKey string
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenKey = IdentityKeyFromContext(r)
		w.WriteHeader(http.StatusOK)
	})
	mw := AuthMiddleware(AuthConfig{AllowUnauthenticated: true})(echo)

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, httptest.NewRequest("GET", "/api/public-resource", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if seenKey != IdentityKeyUnknown {
		t.Errorf("identity key from context = %q, want %q", seenKey, IdentityKeyUnknown)
	}
}

func TestMiddleware_NoAuthHeaders_401WhenNotAllowed(t *testing.T) {
	// Without AllowUnauthenticated, no auth headers must be rejected with
	// 401.
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := AuthMiddleware(AuthConfig{})(echo)

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, httptest.NewRequest("GET", "/api/resource", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestMiddleware_MissingSignature_401(t *testing.T) {
	// Vector .7: identity-key + nonce present but signature missing → 401.
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := AuthMiddleware(AuthConfig{})(echo)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/resource", nil)
	req.Header.Set(HeaderAuthIdentityKey, testClientIdentityKey)
	req.Header.Set(HeaderAuthNonce, "dGVzdE5vbmNl")
	// no signature
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestIdentityKeyFromContext_Empty(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if got := IdentityKeyFromContext(r); got != "" {
		t.Errorf("got %q, want empty for request without auth context", got)
	}
	// With value:
	ctx := context.WithValue(r.Context(), authContextKey{}, "abc")
	r = r.WithContext(ctx)
	if got := IdentityKeyFromContext(r); got != "abc" {
		t.Errorf("got %q, want abc", got)
	}
}

func TestPubKeyHexPattern(t *testing.T) {
	// Vector .15: 66 hex chars, must start with 02 or 03.
	valid := []string{
		"028d37b941208cd6b8a4c28288eda5f2f16c2b3ab0fcb6d13c18b47fe37b971fc1",
		"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
	}
	for _, v := range valid {
		if !PubKeyHexPattern.MatchString(v) {
			t.Errorf("expected %q to match", v)
		}
	}
	invalid := []string{
		"",
		"04abc",                              // wrong prefix
		"02abc",                              // too short
		"04" + "0000000000000000000000000000000000000000000000000000000000000000",   // wrong prefix, right length
		"02" + "z000000000000000000000000000000000000000000000000000000000000000",   // non-hex char
		"01" + "0000000000000000000000000000000000000000000000000000000000000000",   // invalid prefix
	}
	for _, v := range invalid {
		if PubKeyHexPattern.MatchString(v) {
			t.Errorf("expected %q to NOT match", v)
		}
	}
}

func TestNewNonce_44CharsBase64(t *testing.T) {
	// Vector .13: requestId / nonce is 32 bytes base64-encoded → 44 chars
	// including padding.
	n, err := newNonce()
	if err != nil {
		t.Fatalf("newNonce: %v", err)
	}
	if len(n) != 44 {
		t.Errorf("nonce length = %d, want 44", len(n))
	}
}
