package canonical

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
)

// BRC-31 header names. Lowercased canonical form; Go's http.Header
// normalizes lookup so case doesn't affect Get/Set, but emitting
// lowercase keeps wire output aligned with the ts-stack reference.
const (
	HeaderAuthVersion     = "x-bsv-auth-version"
	HeaderAuthIdentityKey = "x-bsv-auth-identity-key"
	HeaderAuthNonce       = "x-bsv-auth-nonce"
	HeaderAuthYourNonce   = "x-bsv-auth-your-nonce"
	HeaderAuthSignature   = "x-bsv-auth-signature"
	HeaderAuthRequestID   = "x-bsv-auth-request-id"
	HeaderAuthMessageType = "x-bsv-auth-message-type"

	AuthVersionV01 = "0.1"

	MessageTypeInitialRequest  = "initialRequest"
	MessageTypeInitialResponse = "initialResponse"
	MessageTypeGeneral         = "general"

	// IdentityKeyUnknown is the placeholder identity key set on the request
	// context when AllowUnauthenticated is true and the request carries no
	// auth headers. Matches conformance vector auth.brc31-handshake.9.
	IdentityKeyUnknown = "unknown"
)

// PubKeyHexPattern is the BRC-31 identity-key format: 66 hex chars
// starting with 02 or 03 (compressed secp256k1 pubkey). Source: vector
// auth.brc31-handshake.15.
var PubKeyHexPattern = regexp.MustCompile(`^0[23][0-9a-fA-F]{64}$`)

// AuthConfig wires BRC-31 behavior. The package itself holds no key
// material; signing/verification callbacks are injected (or omitted for
// Pass 1, which is shape-only).
type AuthConfig struct {
	// Version advertised in /.well-known/auth responses. Empty defaults to "0.1".
	Version string

	// AllowUnauthenticated lets non-auth requests pass through with the
	// request context carrying IdentityKeyUnknown. Used by routes that
	// don't require BRC-31 (vector .9).
	AllowUnauthenticated bool

	// ServerIdentityKey is the 66-char hex pubkey emitted in Phase 1
	// responses. Empty falls back to a deterministic placeholder so Pass-1
	// shape checks still pass.
	ServerIdentityKey string

	// SignResponse is invoked by Phase 1 to produce the response signature.
	// Pass 1 leaves this nil; Pass 2 wires real ECDSA. When nil, the
	// response carries a 64-byte zero placeholder — the shape vectors
	// only require the field be an array of the right size class, not a
	// valid signature.
	SignResponse func(payload []byte) ([]byte, error)
}

func (c AuthConfig) version() string {
	if c.Version == "" {
		return AuthVersionV01
	}
	return c.Version
}

func (c AuthConfig) serverIdentityKey() string {
	if c.ServerIdentityKey != "" {
		return c.ServerIdentityKey
	}
	// Placeholder: a fixed but distinctly fake key so a Pass-1 caller can
	// recognize it as unconfigured. Replace via ServerIdentityKey when real.
	return "020000000000000000000000000000000000000000000000000000000000000001"
}

// authContextKey is the unexported type used for storing BRC-31 identity
// on the request context. Use IdentityKeyFromContext to read it.
type authContextKey struct{}

// IdentityKeyFromContext returns the BRC-31 identity key the middleware
// attached to r. Returns "" if no key is present (middleware not applied,
// or applied without AllowUnauthenticated on an unauthenticated request).
func IdentityKeyFromContext(r *http.Request) string {
	if r == nil {
		return ""
	}
	v := r.Context().Value(authContextKey{})
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

// AuthMiddleware returns a BRC-31 protection middleware.
//
// Pass 1 behavior:
//   - If AllowUnauthenticated && all BRC-31 headers absent: set
//     IdentityKeyUnknown on the context and pass through.
//   - If any auth headers present but signature missing: 401.
//   - If required headers present (no signature verify yet): set context
//     identity key from the request header and pass through.
//
// Pass 2 will add real ECDSA verification + replay protection.
func AuthMiddleware(cfg AuthConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identityKey := r.Header.Get(HeaderAuthIdentityKey)
			nonce := r.Header.Get(HeaderAuthNonce)
			signature := r.Header.Get(HeaderAuthSignature)

			noAuthHeaders := identityKey == "" && nonce == "" && signature == ""
			if noAuthHeaders {
				if cfg.AllowUnauthenticated {
					ctx := context.WithValue(r.Context(), authContextKey{}, IdentityKeyUnknown)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				writeAuthError(w, http.StatusUnauthorized, "UNAUTHORIZED")
				return
			}

			// Some auth headers present. Phase 2 requires identity key + nonce
			// + signature. Missing any of them is 401.
			if identityKey == "" || nonce == "" {
				writeAuthError(w, http.StatusUnauthorized, "UNAUTHORIZED")
				return
			}
			if signature == "" {
				writeAuthError(w, http.StatusUnauthorized, "UNAUTHORIZED")
				return
			}

			// Pass 2 will verify here. For now, attach the identity key from
			// the request and let the handler run.
			ctx := context.WithValue(r.Context(), authContextKey{}, identityKey)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// phase1Body is the JSON body the client sends on POST /.well-known/auth.
type phase1Body struct {
	MessageType    string `json:"messageType"`
	Version        string `json:"version"`
	IdentityKey    string `json:"identityKey"`
	InitialNonce   string `json:"initialNonce,omitempty"`
	Nonce          string `json:"nonce,omitempty"`
	YourNonce      string `json:"yourNonce,omitempty"`
	RequestedCerts any    `json:"requestedCertificates,omitempty"`
}

// phase1Response is the JSON body returned from POST /.well-known/auth.
//
// Signature is []int (not []byte / []uint8) so json.Marshal emits a JSON
// array of numbers — Go marshals []byte as a base64 string, which fails
// the vector .1 body_shape contract requiring signature to be an "array".
type phase1Response struct {
	MessageType string `json:"messageType"`
	Version     string `json:"version"`
	IdentityKey string `json:"identityKey"`
	Nonce       string `json:"nonce"`
	YourNonce   string `json:"yourNonce"`
	Signature   []int  `json:"signature"`
}

// registerAuth attaches POST /.well-known/auth to mux.
func registerAuth(mux *http.ServeMux, cfg AuthConfig) {
	mux.HandleFunc("POST /.well-known/auth", func(w http.ResponseWriter, r *http.Request) {
		handlePhase1(w, r, cfg)
	})
}

func handlePhase1(w http.ResponseWriter, r *http.Request, cfg AuthConfig) {
	// Header presence is mandatory for Phase 1 (vectors .3, .4).
	identityKey := r.Header.Get(HeaderAuthIdentityKey)
	nonce := r.Header.Get(HeaderAuthNonce)
	if identityKey == "" || nonce == "" {
		writeAuthError(w, http.StatusUnauthorized, "UNAUTHORIZED")
		return
	}

	// Body must be JSON of MessageType=initialRequest.
	var body phase1Body
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAuthError(w, http.StatusUnauthorized, "UNAUTHORIZED")
		return
	}
	if body.MessageType != MessageTypeInitialRequest {
		writeAuthError(w, http.StatusUnauthorized, "UNAUTHORIZED")
		return
	}

	// Build response.
	serverNonce, err := newNonce()
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "ERR_RESPONSE_SIGNING_FAILED")
		return
	}

	// Pass 1 placeholder signature: 64 zero bytes (typical ECDSA sig size).
	// Pass 2 replaces with real ECDSA via cfg.SignResponse.
	sigBytes := make([]byte, 64)

	if cfg.SignResponse != nil {
		// Pass 2 will canonicalize the signed payload exactly; for now we sign
		// a minimal representation so the wiring is testable. Real payload
		// canonicalization lands with Pass 2.
		payload := []byte(cfg.version() + "|" + serverNonce + "|" + nonce + "|" + identityKey)
		sig, signErr := cfg.SignResponse(payload)
		if signErr != nil {
			writeAuthError(w, http.StatusInternalServerError, "ERR_RESPONSE_SIGNING_FAILED")
			return
		}
		sigBytes = sig
	}

	resp := phase1Response{
		MessageType: MessageTypeInitialResponse,
		Version:     cfg.version(),
		IdentityKey: cfg.serverIdentityKey(),
		Nonce:       serverNonce,
		YourNonce:   nonce,
		Signature:   bytesToIntSlice(sigBytes),
	}

	// Response headers required by vector .2. The signature header carries
	// the base64-encoded sig bytes so the header value is non-empty even
	// in Pass 1 (vector checks header NAME presence).
	w.Header().Set(HeaderAuthVersion, cfg.version())
	w.Header().Set(HeaderAuthMessageType, MessageTypeInitialResponse)
	w.Header().Set(HeaderAuthIdentityKey, cfg.serverIdentityKey())
	w.Header().Set(HeaderAuthNonce, serverNonce)
	w.Header().Set(HeaderAuthYourNonce, nonce)
	w.Header().Set(HeaderAuthSignature, base64.StdEncoding.EncodeToString(sigBytes))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// bytesToIntSlice converts []byte to []int for JSON-array marshaling.
// (Go marshals []byte as a base64 string; vector .1 requires an array.)
func bytesToIntSlice(b []byte) []int {
	out := make([]int, len(b))
	for i, v := range b {
		out[i] = int(v)
	}
	return out
}

// authError is the body of a BRC-31 error response. Shape fixed by vectors
// .3, .4, .7, .8, .14, .16.
type authError struct {
	Status string `json:"status"` // always "error"
	Code   string `json:"code"`
}

func writeAuthError(w http.ResponseWriter, code int, errCode string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(authError{Status: "error", Code: errCode})
}

// newNonce returns a fresh 32-byte random nonce, base64-encoded (44 chars
// with padding). Matches vector .13 length contract.
func newNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
