package dispatchers

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/canonical"
	"github.com/BSVanon/Anvil/internal/overlay/interop"
)

func loadBRC31File(t *testing.T) *interop.VectorFile {
	t.Helper()
	abs, err := filepath.Abs("../../../../docs/internal/conformance-vectors")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	files, err := interop.LoadAll(abs)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	for _, f := range files {
		if f.ID == "auth.brc31-handshake" {
			return f
		}
	}
	t.Fatal("auth.brc31-handshake file not found")
	return nil
}

func brc31Dispatcher() *BRC31Handshake {
	return NewBRC31Handshake(canonical.New(canonical.Config{Auth: canonical.AuthConfig{}}))
}

func runVector(t *testing.T, id string) interop.Result {
	t.Helper()
	file := loadBRC31File(t)
	for _, v := range file.Vectors {
		if v.ID == id {
			return brc31Dispatcher().Run(context.Background(), file, v)
		}
	}
	t.Fatalf("vector %q not found", id)
	return interop.Result{}
}

func TestBRC31_Vector1_Phase1HappyPath_BodyShape(t *testing.T) {
	res := runVector(t, "auth.brc31-handshake.1")
	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

func TestBRC31_Vector2_Phase1HappyPath_ResponseHeaders(t *testing.T) {
	res := runVector(t, "auth.brc31-handshake.2")
	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

func TestBRC31_Vector3_MissingIdentityKey(t *testing.T) {
	res := runVector(t, "auth.brc31-handshake.3")
	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

func TestBRC31_Vector4_MissingNonce(t *testing.T) {
	res := runVector(t, "auth.brc31-handshake.4")
	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

func TestBRC31_Vector9_AllowUnauthenticatedPassthrough(t *testing.T) {
	res := runVector(t, "auth.brc31-handshake.9")
	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

func TestBRC31_Vector12_AuthMessageSchema(t *testing.T) {
	res := runVector(t, "auth.brc31-handshake.12")
	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

func TestBRC31_Vector13_RequestIDLength(t *testing.T) {
	res := runVector(t, "auth.brc31-handshake.13")
	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

func TestBRC31_Vector15_PubKeyHexPattern(t *testing.T) {
	res := runVector(t, "auth.brc31-handshake.15")
	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

// BRC-31 Pass 2: structural assertions for vectors .5-.8, .10, .11, .14, .16
// matching the upstream auth.ts dispatcher convention. Each vector now PASSes
// via structural-only checks on its `expected` field. Real middleware behavior
// is hardened separately in canonical/auth.go unit tests.

func TestBRC31_Vector5_GeneralRequestHeaders(t *testing.T) {
	res := runVector(t, "auth.brc31-handshake.5")
	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

func TestBRC31_Vector6_GeneralRequestHeaders_POST(t *testing.T) {
	res := runVector(t, "auth.brc31-handshake.6")
	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

func TestBRC31_Vector7_MissingSignature(t *testing.T) {
	res := runVector(t, "auth.brc31-handshake.7")
	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

func TestBRC31_Vector8_BadSignature(t *testing.T) {
	res := runVector(t, "auth.brc31-handshake.8")
	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

func TestBRC31_Vector10_CertificateTimeout(t *testing.T) {
	res := runVector(t, "auth.brc31-handshake.10")
	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

func TestBRC31_Vector11_RequestedCertsHeader(t *testing.T) {
	res := runVector(t, "auth.brc31-handshake.11")
	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

func TestBRC31_Vector14_ReplayPrevention(t *testing.T) {
	res := runVector(t, "auth.brc31-handshake.14")
	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

func TestBRC31_Vector16_ResponseSigningFailure(t *testing.T) {
	res := runVector(t, "auth.brc31-handshake.16")
	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

// --- structural-assertion regression tests ---
//
// These prove the dispatcher catches malformed `expected` fields. If a vector
// got mutated to remove the error code, the dispatcher must FAIL rather than
// silently PASS. assertErrorEnvelope is the load-bearing helper here.

func TestAssertErrorEnvelope_MissingCode(t *testing.T) {
	exp := authVectorExpected{
		Status: 401,
		Body:   []byte(`{"status":"error"}`), // no code field
	}
	msg := assertErrorEnvelope(exp, 401, "error", "ERR_AUTH_FAILED")
	if msg == "" {
		t.Error("assertErrorEnvelope should reject missing code")
	}
	if !strings.Contains(msg, "code") {
		t.Errorf("mismatch message should mention code: %s", msg)
	}
}

func TestAssertErrorEnvelope_WrongStatus(t *testing.T) {
	exp := authVectorExpected{
		Status: 200, // wrong, vector said 401
		Body:   []byte(`{"status":"error","code":"ERR_AUTH_FAILED"}`),
	}
	msg := assertErrorEnvelope(exp, 401, "error", "ERR_AUTH_FAILED")
	if msg == "" {
		t.Error("assertErrorEnvelope should reject wrong status")
	}
	if !strings.Contains(msg, "status") {
		t.Errorf("mismatch message should mention status: %s", msg)
	}
}

func TestRunStructural_GeneralRequestHeaders_MissingSignatureHeader_Fails(t *testing.T) {
	// If the vector's response_headers_required omits x-bsv-auth-signature,
	// the dispatcher must FAIL (matches upstream auth.ts behavior).
	d := brc31Dispatcher()
	exp := authVectorExpected{
		ResponseHeadersRequired: []string{"x-bsv-auth-version"}, // no signature
	}
	r := d.runStructural_GeneralRequestHeaders(interop.Result{}, exp, requiredHeadersForVector6)
	if r.Status != interop.StatusFail {
		t.Errorf("status = %s, want FAIL (signature header missing from required list)", r.Status)
	}
}

// Codex ec2db518 regression tests: prove the tightened assertions catch
// regressed vector contracts.

func TestRunStructural_Vector5_MissingVersionHeader_Fails(t *testing.T) {
	// If the vector's required list is missing x-bsv-auth-version (one of the
	// 6 documented headers), the dispatcher must FAIL.
	d := brc31Dispatcher()
	exp := authVectorExpected{
		ResponseHeadersRequired: []string{
			// missing x-bsv-auth-version
			canonical.HeaderAuthIdentityKey,
			canonical.HeaderAuthNonce,
			canonical.HeaderAuthYourNonce,
			canonical.HeaderAuthRequestID,
			canonical.HeaderAuthSignature,
		},
	}
	r := d.runStructural_GeneralRequestHeaders(interop.Result{}, exp, requiredHeadersForVector5)
	if r.Status != interop.StatusFail {
		t.Errorf("status = %s, want FAIL — full .5 header set should be required", r.Status)
	}
	if !strings.Contains(r.Message, "x-bsv-auth-version") {
		t.Errorf("FAIL message should mention missing header: %s", r.Message)
	}
}

func TestRunStructural_Vector5_ExtraHeader_Fails(t *testing.T) {
	// Extra unexpected headers in the vector's required list should also FAIL —
	// the dispatcher asserts an exact match, not a subset.
	d := brc31Dispatcher()
	exp := authVectorExpected{
		ResponseHeadersRequired: append([]string{}, append(requiredHeadersForVector5, "x-some-unexpected-header")...),
	}
	r := d.runStructural_GeneralRequestHeaders(interop.Result{}, exp, requiredHeadersForVector5)
	if r.Status != interop.StatusFail {
		t.Errorf("status = %s, want FAIL — extra headers in required list should not be tolerated", r.Status)
	}
}

func TestAssertErrorEnvelope_MissingBodyStatus_Vector7(t *testing.T) {
	// Vector .7 documents body.status="error" AND body.code="UNAUTHORIZED". A
	// regressed vector lacking body.status should FAIL the tightened check.
	exp := authVectorExpected{
		Status: 401,
		Body:   []byte(`{"code":"UNAUTHORIZED"}`), // missing status field
	}
	msg := assertErrorEnvelope(exp, 401, "error", "UNAUTHORIZED")
	if msg == "" {
		t.Error("assertErrorEnvelope should reject missing body.status")
	}
}

func TestAssertErrorEnvelope_WrongBodyStatus(t *testing.T) {
	exp := authVectorExpected{
		Status: 401,
		Body:   []byte(`{"status":"warning","code":"UNAUTHORIZED"}`),
	}
	msg := assertErrorEnvelope(exp, 401, "error", "UNAUTHORIZED")
	if msg == "" {
		t.Error("assertErrorEnvelope should reject wrong body.status")
	}
	if !strings.Contains(msg, "status") {
		t.Errorf("mismatch message should mention status: %s", msg)
	}
}

func TestBRC31_AllVectorsCovered(t *testing.T) {
	// Every vector in the file should produce a non-zero Status — never
	// silent fall-through. PASS or PENDING or SKIP, but never empty.
	file := loadBRC31File(t)
	d := brc31Dispatcher()
	for _, v := range file.Vectors {
		res := d.Run(context.Background(), file, v)
		if res.Status == "" {
			t.Errorf("%s: empty Status (dispatcher fell through)", v.ID)
		}
		if res.Workstream == "" {
			t.Errorf("%s: empty Workstream", v.ID)
		}
	}
}

// --- Codex review 0ad931ee regression tests ---
//
// These tests inject deliberately-wrong handlers and verify the dispatcher
// reports FAIL instead of silently PASSing. If the dispatcher regresses to
// under-assert, one of these tests catches it.

// wrongPhase1Handler emits a Phase 1 response with overridable bad fields.
// Used to prove dispatcher catches wrong literal values + wrong nonce length.
type wrongPhase1Handler struct {
	overrideMessageType string
	overrideVersion     string
	nonce               string // if non-empty, emitted instead of a real nonce
}

func (h *wrongPhase1Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	msgType := canonical.MessageTypeInitialResponse
	if h.overrideMessageType != "" {
		msgType = h.overrideMessageType
	}
	version := canonical.AuthVersionV01
	if h.overrideVersion != "" {
		version = h.overrideVersion
	}
	nonce := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 44-char default
	if h.nonce != "" {
		nonce = h.nonce
	}

	w.Header().Set(canonical.HeaderAuthVersion, version)
	w.Header().Set(canonical.HeaderAuthMessageType, msgType)
	w.Header().Set(canonical.HeaderAuthIdentityKey, "020000000000000000000000000000000000000000000000000000000000000001")
	w.Header().Set(canonical.HeaderAuthNonce, nonce)
	w.Header().Set(canonical.HeaderAuthYourNonce, r.Header.Get(canonical.HeaderAuthNonce))
	w.Header().Set(canonical.HeaderAuthSignature, "AAAA")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	// Match body to headers.
	_, _ = w.Write([]byte(`{
		"messageType": "` + msgType + `",
		"version": "` + version + `",
		"identityKey": "020000000000000000000000000000000000000000000000000000000000000001",
		"nonce": "` + nonce + `",
		"yourNonce": "` + r.Header.Get(canonical.HeaderAuthNonce) + `",
		"signature": [0,0,0,0]
	}`))
}

func TestBRC31_Vector1_WrongMessageType_Fails(t *testing.T) {
	// Codex 0ad931ee MEDIUM: vector .1's body_shape has literal
	// messageType="initialResponse". A handler that returns the wrong
	// messageType (but right shape) must FAIL, not PASS.
	file := loadBRC31File(t)
	v := vectorByID(t, file, "auth.brc31-handshake.1")

	d := NewBRC31Handshake(&wrongPhase1Handler{overrideMessageType: "WRONG_TYPE"})
	res := d.Run(context.Background(), file, v)

	if res.Status != interop.StatusFail {
		t.Fatalf("status = %s (msg=%s), want FAIL — dispatcher should catch wrong literal messageType", res.Status, res.Message)
	}
	if !strings.Contains(res.Message, "messageType") {
		t.Errorf("FAIL message should mention messageType: %s", res.Message)
	}
}

func TestBRC31_Vector1_WrongVersion_Fails(t *testing.T) {
	// Same as above but for version literal.
	file := loadBRC31File(t)
	v := vectorByID(t, file, "auth.brc31-handshake.1")

	d := NewBRC31Handshake(&wrongPhase1Handler{overrideVersion: "9.9"})
	res := d.Run(context.Background(), file, v)

	if res.Status != interop.StatusFail {
		t.Fatalf("status = %s (msg=%s), want FAIL — dispatcher should catch wrong literal version", res.Status, res.Message)
	}
	if !strings.Contains(res.Message, "version") {
		t.Errorf("FAIL message should mention version: %s", res.Message)
	}
}

func TestBRC31_Vector13_WrongNonceLength_Fails(t *testing.T) {
	// Codex 0ad931ee LOW: vector .13's contract is "32 bytes base64-encoded
	// = 44 chars". If the implementation emits a shorter nonce, the
	// dispatcher must FAIL (the previous version probed only a hardcoded
	// literal and would have silently PASSed).
	file := loadBRC31File(t)
	v := vectorByID(t, file, "auth.brc31-handshake.13")

	// Inject a 28-char nonce — same length as the upstream caveat example.
	d := NewBRC31Handshake(&wrongPhase1Handler{nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAA=="})
	res := d.Run(context.Background(), file, v)

	if res.Status != interop.StatusFail {
		t.Fatalf("status = %s (msg=%s), want FAIL — dispatcher should catch wrong nonce length", res.Status, res.Message)
	}
	if !strings.Contains(res.Message, "nonce") {
		t.Errorf("FAIL message should mention nonce: %s", res.Message)
	}
}
