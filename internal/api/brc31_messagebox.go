package api

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware"
)

// This file wires Anvil's BRC-33 messagebox routes behind canonical BRC-31
// mutual authentication (go-bsv-middleware), so each request is authenticated by
// the *sender's own identity key* instead of a single shared operator secret.
// This is what lets a public browser DEX use the messagebox without baking the
// node's operator token into a static bundle.
//
// Auth model (dual): BRC-31 mutual auth is preferred and scopes the caller
// strictly to their own identity; a valid operator token is still accepted as a
// backward-compatible fallback for node tooling (broad, node-scoped access).
//
// Live channel (2a): EventSource cannot perform the mutual-auth handshake or set
// headers, so a client first does an authenticated POST /messages/session (real
// BRC-31) to mint a short-lived token bound to its identity, then opens
// GET /messages/subscribe?token=... The session token is NEVER the operator
// secret — it only authorizes reading messages addressed to that one identity.

// sessionSweepInterval bounds how often mint() opportunistically evicts expired
// tokens (cheap; the store is small).
const messageSessionTTL = 5 * time.Minute

// sessionTokenStore maps short-lived opaque SSE session tokens to the
// BRC-31-authenticated identity that minted them.
type sessionTokenStore struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]sessionEntry
}

type sessionEntry struct {
	identityHex string
	expiry      time.Time
}

func newSessionTokenStore(ttl time.Duration) *sessionTokenStore {
	return &sessionTokenStore{ttl: ttl, m: make(map[string]sessionEntry)}
}

// mint creates a new random token bound to identityHex, valid for ttl from now.
func (s *sessionTokenStore) mint(identityHex string, now time.Time) (string, time.Time, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", time.Time{}, err
	}
	tok := hex.EncodeToString(buf)
	exp := now.Add(s.ttl)
	s.mu.Lock()
	s.m[tok] = sessionEntry{identityHex: identityHex, expiry: exp}
	for k, v := range s.m { // opportunistic eviction of expired tokens
		if now.After(v.expiry) {
			delete(s.m, k)
		}
	}
	s.mu.Unlock()
	return tok, exp, nil
}

// resolve returns the identity bound to a token if present and unexpired.
func (s *sessionTokenStore) resolve(tok string, now time.Time) (string, bool) {
	if tok == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[tok]
	if !ok || now.After(e.expiry) {
		if ok {
			delete(s.m, tok)
		}
		return "", false
	}
	return e.identityHex, true
}

// registerMessageboxBRC31 mounts the messagebox routes behind canonical BRC-31
// mutual auth. One auth middleware instance wraps a private sub-mux so the
// handshake (/.well-known/auth), the write routes, and the SSE session-mint all
// share one SessionManager. AllowUnauthenticated lets the operator-token
// fallback reach the handlers, where resolveMessageCaller enforces auth.
// Called from routes() only when s.nodeWallet != nil.
func (s *Server) registerMessageboxBRC31() {
	s.msgSessions = newSessionTokenStore(messageSessionTTL)
	s.messageboxBRC31 = true

	authMW := middleware.NewAuth(s.nodeWallet, middleware.WithAuthAllowUnauthenticated())

	sub := http.NewServeMux()
	sub.HandleFunc("POST /sendMessage", s.handleSendMessage)
	sub.HandleFunc("POST /listMessages", s.handleListMessages)
	sub.HandleFunc("POST /acknowledgeMessage", s.handleAcknowledgeMessage)
	sub.HandleFunc("POST /messages/session", s.handleMessageSession)

	wrapped := brc31CORS(authMW.HTTPHandler(sub))

	// Path-only patterns: preflight OPTIONS and the handshake/write POSTs all
	// reach the wrapper. The auth middleware handles /.well-known/auth
	// internally (handshake) and never calls the sub-mux for it.
	s.mux.Handle("/.well-known/auth", wrapped)
	s.mux.Handle("/sendMessage", wrapped)
	s.mux.Handle("/listMessages", wrapped)
	s.mux.Handle("/acknowledgeMessage", wrapped)
	s.mux.Handle("/messages/session", wrapped)

	// SSE stays a direct route (EventSource can't do the handshake); it is
	// gated by the per-identity session token minted at /messages/session.
	s.mux.HandleFunc("GET /messages/subscribe", s.handleMessageSubscribe)
}

// registerMessageboxLegacy mounts the messagebox routes behind the operator
// auth token only — used when no node wallet is available (mesh/wallet
// disabled), which means canonical BRC-31 server auth cannot be performed.
func (s *Server) registerMessageboxLegacy() {
	s.mux.HandleFunc("POST /sendMessage", s.requireAuth(s.handleSendMessage))
	s.mux.HandleFunc("POST /listMessages", s.requireAuth(s.handleListMessages))
	s.mux.HandleFunc("POST /acknowledgeMessage", s.requireAuth(s.handleAcknowledgeMessage))
	s.mux.HandleFunc("GET /messages/subscribe", s.requireAuthSSE(s.handleMessageSubscribe))
}

// brc31CORS wraps the BRC-31 messagebox handler with permissive CORS. Browser
// AuthFetch both sends x-bsv-auth-* request headers and must read x-bsv-auth-*
// response headers to complete mutual auth, so we allow and expose all headers
// (safe: these routes never use cookie credentials). OPTIONS short-circuits
// before the auth middleware, which does not handle preflight.
func brc31CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "*")
		h.Set("Access-Control-Expose-Headers", "*")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// messageCaller is the authenticated principal for a messagebox request.
type messageCaller struct {
	identityHex string // caller identity (compressed pubkey hex)
	scoped      bool   // true: BRC-31 per-identity (strict); false: operator (broad/node)
}

// resolveMessageCaller authenticates a /sendMessage|/listMessages|
// /acknowledgeMessage request. BRC-31 mutual auth is preferred and strictly
// scopes the caller to its own identity; a valid operator token is accepted as a
// backward-compatible fallback. Writes 401 and returns ok=false otherwise.
func (s *Server) resolveMessageCaller(w http.ResponseWriter, r *http.Request) (messageCaller, bool) {
	if s.messageboxBRC31 {
		if id, err := middleware.ShouldGetAuthenticatedIdentity(r.Context()); err == nil && id != nil {
			return messageCaller{identityHex: hex.EncodeToString(id.Compressed()), scoped: true}, true
		}
	}
	if s.operatorTokenValid(r) {
		return messageCaller{identityHex: s.identityPub, scoped: false}, true
	}
	writeError(w, http.StatusUnauthorized, "unauthorized: BRC-31 mutual auth or operator token required")
	return messageCaller{}, false
}

// scopedRecipient resolves the inbox an authenticated caller may read/ack.
// BRC-31 callers are strictly scoped to their own identity; the operator token
// may target a body-supplied recipient (defaulting to the node identity).
func (s *Server) scopedRecipient(caller messageCaller, bodyRecipient string) string {
	if caller.scoped {
		return caller.identityHex
	}
	if bodyRecipient != "" {
		return bodyRecipient
	}
	return s.identityPub
}

// handleMessageSession mints a short-lived SSE session token bound to the
// caller's BRC-31-authenticated identity (2a). Requires real mutual auth — the
// operator-token fallback is intentionally not accepted here, because the token
// it returns must be tied to a specific subscriber identity.
func (s *Server) handleMessageSession(w http.ResponseWriter, r *http.Request) {
	id, err := middleware.ShouldGetAuthenticatedIdentity(r.Context())
	if err != nil || id == nil {
		writeError(w, http.StatusUnauthorized, "BRC-31 mutual auth required to mint a session token")
		return
	}
	if s.msgSessions == nil {
		writeError(w, http.StatusServiceUnavailable, "messagebox sessions not enabled")
		return
	}
	tok, exp, err := s.msgSessions.mint(hex.EncodeToString(id.Compressed()), time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to mint session token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":        "success",
		"token":         tok,
		"expiresInSecs": int(time.Until(exp).Seconds()),
	})
}

// resolveSSECaller authenticates the messagebox SSE subscription. A per-identity
// session token (minted at /messages/session) scopes the stream strictly to that
// identity; a valid operator token (via ?token= since EventSource can't set
// headers, or via header) is accepted as a broad, node-scoped fallback for
// tooling. Returns the recipient identity to stream and ok.
func (s *Server) resolveSSECaller(w http.ResponseWriter, r *http.Request) (identityHex string, scoped bool, ok bool) {
	tok := r.URL.Query().Get("token")
	if s.msgSessions != nil {
		if id, found := s.msgSessions.resolve(tok, time.Now()); found {
			return id, true, true
		}
	}
	if s.authToken != "" && tok == s.authToken {
		return s.identityPub, false, true
	}
	if s.operatorTokenValid(r) {
		return s.identityPub, false, true
	}
	writeError(w, http.StatusUnauthorized, "unauthorized: session token (POST /messages/session) or operator token required")
	return "", false, false
}

// operatorTokenValid reports whether the request carries the node operator's
// shared auth token (X-Anvil-Auth or Authorization: Bearer). Mirrors requireAuth.
func (s *Server) operatorTokenValid(r *http.Request) bool {
	if s.authToken == "" {
		return false
	}
	tok := r.Header.Get("X-Anvil-Auth")
	if tok == "" {
		if a := r.Header.Get("Authorization"); len(a) > 7 && a[:7] == "Bearer " {
			tok = a[7:]
		}
	}
	return tok != "" && tok == s.authToken
}
