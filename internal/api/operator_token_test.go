package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestEitherOperatorHeaderAuthenticates: a request authenticates if EITHER
// X-Anvil-Auth or Authorization: Bearer carries the right token — not just
// whichever one a fixed precedence order happens to check first.
func TestEitherOperatorHeaderAuthenticates(t *testing.T) {
	s := &Server{authToken: "right-token"}

	req1 := httptest.NewRequest(http.MethodGet, "/mesh/status", nil)
	req1.Header.Set("X-Anvil-Auth", "right-token")
	if !s.isOperatorToken(req1) {
		t.Fatal("a correct X-Anvil-Auth alone should authenticate")
	}

	req2 := httptest.NewRequest(http.MethodGet, "/mesh/status", nil)
	req2.Header.Set("Authorization", "Bearer right-token")
	if !s.isOperatorToken(req2) {
		t.Fatal("a correct Authorization: Bearer alone should authenticate")
	}
}

// TestStaleOperatorHeaderDoesNotShadowCorrectOne: a wrong value in one
// header must never hide a correct value in the other. Before this fix,
// isOperatorToken (via operatorTokenFromRequest) checked X-Anvil-Auth
// first, unconditionally, and only fell back to Authorization when
// X-Anvil-Auth was empty — so a stale/wrong X-Anvil-Auth masked a correct
// Bearer token. Both headers must be checked independently.
func TestStaleOperatorHeaderDoesNotShadowCorrectOne(t *testing.T) {
	s := &Server{authToken: "right-token"}

	req := httptest.NewRequest(http.MethodGet, "/mesh/status", nil)
	req.Header.Set("X-Anvil-Auth", "stale-wrong-token")
	req.Header.Set("Authorization", "Bearer right-token")
	if !s.isOperatorToken(req) {
		t.Fatal("a correct Authorization: Bearer must authenticate even when X-Anvil-Auth carries a stale/wrong value")
	}

	// And the reverse: a stale/wrong Bearer must not hide a correct
	// X-Anvil-Auth either.
	req2 := httptest.NewRequest(http.MethodGet, "/mesh/status", nil)
	req2.Header.Set("X-Anvil-Auth", "right-token")
	req2.Header.Set("Authorization", "Bearer stale-wrong-token")
	if !s.isOperatorToken(req2) {
		t.Fatal("a correct X-Anvil-Auth must authenticate even when Authorization carries a stale/wrong value")
	}
}

// TestOperatorTokenRejectsWrongOrMissingCredential covers the negative
// cases: no header, both headers wrong, and no token configured at all.
func TestOperatorTokenRejectsWrongOrMissingCredential(t *testing.T) {
	s := &Server{authToken: "right-token"}

	noHeaders := httptest.NewRequest(http.MethodGet, "/mesh/status", nil)
	if s.isOperatorToken(noHeaders) {
		t.Fatal("no credential at all must not authenticate")
	}

	bothWrong := httptest.NewRequest(http.MethodGet, "/mesh/status", nil)
	bothWrong.Header.Set("X-Anvil-Auth", "wrong")
	bothWrong.Header.Set("Authorization", "Bearer also-wrong")
	if s.isOperatorToken(bothWrong) {
		t.Fatal("two wrong credentials must not authenticate")
	}

	unconfigured := &Server{authToken: ""}
	withToken := httptest.NewRequest(http.MethodGet, "/mesh/status", nil)
	withToken.Header.Set("X-Anvil-Auth", "anything")
	if unconfigured.isOperatorToken(withToken) {
		t.Fatal("no operator token configured must never authenticate, regardless of what the caller sends")
	}
}

// TestRequireAuthAndRequireAuthSSEShareTheSameCheck: both middlewares admit
// a request on either correct header, and both reject when the X-Anvil-Auth
// header is stale/wrong but Authorization: Bearer is correct — proving
// neither has its own, separately-ordered credential check.
func TestRequireAuthAndRequireAuthSSEShareTheSameCheck(t *testing.T) {
	s := &Server{authToken: "right-token"}
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }

	for _, mw := range []struct {
		name    string
		wrapped http.HandlerFunc
	}{
		{"requireAuth", s.requireAuth(ok)},
		{"requireAuthSSE", s.requireAuthSSE(ok)},
	} {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("X-Anvil-Auth", "stale-wrong-token")
		req.Header.Set("Authorization", "Bearer right-token")
		rec := httptest.NewRecorder()
		mw.wrapped(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: a correct Authorization: Bearer must authenticate even with a stale X-Anvil-Auth, got %d", mw.name, rec.Code)
		}

		badReq := httptest.NewRequest(http.MethodGet, "/x", nil)
		badReq.Header.Set("X-Anvil-Auth", "wrong")
		badRec := httptest.NewRecorder()
		mw.wrapped(badRec, badReq)
		if badRec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: a wrong credential must be rejected, got %d", mw.name, badRec.Code)
		}
	}
}

func TestOperatorCredentialRejectedFromSSEQuery(t *testing.T) {
	s := &Server{authToken: "right-token"}
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	t.Run("legacy gate", func(t *testing.T) {
		wrapped := s.requireAuthSSE(ok)
		req := httptest.NewRequest(http.MethodGet, "/data/subscribe?topic=x&token=right-token", nil)
		rec := httptest.NewRecorder()
		wrapped(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("operator credential in query authenticated SSE request: got %d, want 401", rec.Code)
		}

		req.Header.Set("Authorization", "Bearer right-token")
		rec = httptest.NewRecorder()
		wrapped(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("operator credential in header was rejected: got %d, want 200", rec.Code)
		}
	})

	t.Run("messagebox gate", func(t *testing.T) {
		s.msgSessions = newSessionTokenStore(messageSessionTTL)
		req := httptest.NewRequest(http.MethodGet, "/messages/subscribe?token=right-token", nil)
		w := httptest.NewRecorder()
		if _, _, accepted := s.resolveSSECaller(w, req); accepted {
			t.Fatal("messagebox SSE accepted operator credential from query")
		}
	})
}
