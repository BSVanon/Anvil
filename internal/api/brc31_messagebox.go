package api

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware"
	"github.com/bsv-blockchain/go-sdk/auth"
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

	authMW := middleware.NewAuth(s.nodeWallet, s.certificateAuthOptions()...)

	sub := http.NewServeMux()
	sub.HandleFunc("POST /sendMessage", s.handleSendMessage)
	sub.HandleFunc("POST /listMessages", s.handleListMessages)
	sub.HandleFunc("POST /acknowledgeMessage", s.handleAcknowledgeMessage)
	sub.HandleFunc("POST /messages/session", s.handleMessageSession)
	if s.messagingPolicy.PrivateHomes != nil {
		sub.HandleFunc("POST /messages/home", s.handlePrivateHome)
		sub.HandleFunc("GET /messages/home", s.handlePrivateHome)
	}

	authHandler := brc31ReplayNonceStatus(authMW.HTTPHandler(sub))
	wrapped := brc31CORS(messageboxRateLimit(s.messageboxLimiter, authHandler))

	// Path-only patterns: preflight OPTIONS and the handshake/write POSTs all
	// reach the wrapper. The auth middleware handles /.well-known/auth
	// internally (handshake) and never calls the sub-mux for it.
	s.mux.Handle("/.well-known/auth", wrapped)
	s.mux.Handle("/sendMessage", wrapped)
	s.mux.Handle("/listMessages", wrapped)
	s.mux.Handle("/acknowledgeMessage", wrapped)
	s.mux.Handle("/messages/session", wrapped)
	if s.messagingPolicy.PrivateHomes != nil {
		s.mux.Handle("/messages/home", wrapped)
	}
	s.registerCertificateRoutes(sub, wrapped)

	// SSE stays a direct route (EventSource can't do the handshake); it is
	// gated by the per-identity session token minted at /messages/session.
	s.mux.Handle("GET /messages/subscribe", brc31CORS(messageboxRateLimit(s.messageboxLimiter, http.HandlerFunc(s.handleMessageSubscribe))))
}

// registerMessageboxLegacy mounts the messagebox routes behind the operator
// auth token only — used when no node wallet is available (mesh/wallet
// disabled), which means canonical BRC-31 server auth cannot be performed.
func (s *Server) registerMessageboxLegacy() {
	s.mux.Handle("POST /sendMessage", messageboxRateLimit(s.messageboxLimiter, s.requireAuth(s.handleSendMessage)))
	s.mux.Handle("POST /listMessages", messageboxRateLimit(s.messageboxLimiter, s.requireAuth(s.handleListMessages)))
	s.mux.Handle("POST /acknowledgeMessage", messageboxRateLimit(s.messageboxLimiter, s.requireAuth(s.handleAcknowledgeMessage)))
	s.mux.Handle("GET /messages/subscribe", messageboxRateLimit(s.messageboxLimiter, s.requireAuthSSE(s.handleMessageSubscribe)))
}

// replayedNonceMarker is go-sdk's own text for a replayed BRC-103 message
// nonce (auth.ErrReplayedNonce, go-sdk v1.7.7 auth/errors.go:44), read from
// the sentinel itself rather than retyped, so brc31ReplayNonceStatus keeps
// matching it even if the wording ever changes upstream.
var replayedNonceMarker = []byte(auth.ErrReplayedNonce.Error())

// brc31ReplayNonceStatus wraps the BRC-31 auth handler so a replayed nonce
// answers 401 instead of go-bsv-middleware's default 500.
//
// go-bsv-middleware v0.13.3 maps errors to HTTP statuses once, in
// authentication.(*Middleware).toHTTPError (pkg/internal/authentication/
// middleware.go:236-292). That switch has a case for go-sdk's
// auth.ErrInvalidNonce (400) but none for auth.ErrReplayedNonce, so a
// replayed nonce falls through to the default branch and answers 500. There
// is no exported way to add a case or install a different error handler:
// authentication.Config (what pkg/middleware.AuthMiddlewareConfig aliases)
// has no error-handler field, and authentication.NewMiddleware always sets
// the middleware's handler to DefaultErrorHandler directly — so this wraps
// the HTTP response instead of the Go error.
//
// 401 is what the canonical TypeScript auth middleware answers for the same
// case (@bsv/auth-express-middleware v2.0.5, src/index.ts:665-677): when an
// authenticated general message's callback rejects with an error whose text
// matches /nonce|signature|session|auth version/i, it responds 401 with
// code ERR_AUTH_FAILED rather than 500.
//
// Buffering the whole response is safe here because every route this wraps
// (registerMessageboxBRC31's POST routes) answers with one small, unstreamed
// body; the SSE route is wired separately and never passes through this
// wrapper.
func brc31ReplayNonceStatus(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &replayStatusBuffer{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		rec.flush()
	})
}

type replayStatusBuffer struct {
	http.ResponseWriter
	status int
	wrote  bool
	body   bytes.Buffer
}

func (r *replayStatusBuffer) WriteHeader(status int) {
	r.status = status
	r.wrote = true
}

func (r *replayStatusBuffer) Write(b []byte) (int, error) {
	if !r.wrote {
		r.status = http.StatusOK
		r.wrote = true
	}
	return r.body.Write(b)
}

func (r *replayStatusBuffer) flush() {
	if r.status == http.StatusInternalServerError && bytes.Contains(r.body.Bytes(), replayedNonceMarker) {
		writeCodedError(r.ResponseWriter, http.StatusUnauthorized, "ERR_REPLAYED_NONCE", "This request's nonce has already been used.")
		return
	}
	status := r.status
	if status == 0 {
		status = http.StatusOK
	}
	r.ResponseWriter.WriteHeader(status)
	_, _ = r.ResponseWriter.Write(r.body.Bytes())
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

// scopedRecipient resolves the inbox an authenticated caller may
// read/ack. BRC-31 callers are strictly scoped to their own identity,
// unconditionally — regardless of the operator-box switch below. The operator token may
// target a body-supplied recipient (defaulting to the node identity)
// when [messaging] operator_reads_all_boxes allows it (operatorBoxAllowed,
// below); otherwise this writes a 403 and returns ok=false.
func (s *Server) scopedRecipient(w http.ResponseWriter, caller messageCaller, bodyRecipient string) (string, bool) {
	if caller.scoped {
		return caller.identityHex, true
	}
	if !s.operatorBoxAllowed(bodyRecipient) {
		writeCodedError(w, http.StatusForbidden, "ERR_OPERATOR_BOX_RESTRICTED", operatorBoxRestrictedMsg)
		return "", false
	}
	if bodyRecipient != "" {
		return bodyRecipient, true
	}
	return s.identityPub, true
}

// operatorBoxRestrictedMsg is the 403 body for every path the operator-box
// switch gates (scopedRecipient, above, and handleMessageSubscribe's
// operator fallback, sse_messages.go).
const operatorBoxRestrictedMsg = "the operator token may only access this node's own identity box; naming another recipient is disabled ([messaging] operator_reads_all_boxes = false)"

// operatorBoxAllowed reports whether an operator-token caller may target
// bodyRecipient: naming nothing,
// or this node's own identity box, is always allowed — that is today's
// default behaviour regardless of the switch. Naming any OTHER recipient
// requires operatorReadsAll() (default true, today's behaviour).
func (s *Server) operatorBoxAllowed(bodyRecipient string) bool {
	if bodyRecipient == "" || strings.EqualFold(bodyRecipient, s.identityPub) {
		return true
	}
	return s.operatorReadsAll()
}

// operatorReadsAll reports [messaging] operator_reads_all_boxes. nil
// (never wired, or the config key absent) means the default: true,
// today's behaviour.
func (s *Server) operatorReadsAll() bool {
	if s.messagingPolicy.OperatorReadsAllBoxes == nil {
		return true
	}
	return *s.messagingPolicy.OperatorReadsAllBoxes
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
// identity; a valid operator token in a header is accepted as a broad,
// node-scoped fallback for tooling. Returns the recipient identity to stream
// and ok. The operator credential is never accepted from the URL.
func (s *Server) resolveSSECaller(w http.ResponseWriter, r *http.Request) (identityHex string, scoped bool, ok bool) {
	tok := r.URL.Query().Get("token")
	if s.msgSessions != nil {
		if id, found := s.msgSessions.resolve(tok, time.Now()); found {
			return id, true, true
		}
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
