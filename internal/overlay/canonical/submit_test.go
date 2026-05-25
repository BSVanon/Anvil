package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func submitReq(body []byte, headers map[string]string) *http.Request {
	r := httptest.NewRequest("POST", "/submit", bytes.NewReader(body))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestSubmit_HappyPath_GenericSteak(t *testing.T) {
	// No Submit callback wired: handler returns generic empty-admittance STEAK
	// for each requested topic. Satisfies vectors .1, .2, .3 shape contract.
	h := New(Config{})
	rec := httptest.NewRecorder()
	r := submitReq([]byte{0x01, 0x00, 0xbe, 0xef}, map[string]string{
		"Content-Type": "application/octet-stream",
		"x-topics":     `["tm_ship","tm_slap"]`,
	})
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var got SubmitResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := got["tm_ship"]; !ok {
		t.Errorf("missing tm_ship in STEAK: %v", got)
	}
	if _, ok := got["tm_slap"]; !ok {
		t.Errorf("missing tm_slap in STEAK: %v", got)
	}
}

func TestSubmit_MissingTopicsHeader_400(t *testing.T) {
	h := New(Config{})
	rec := httptest.NewRecorder()
	r := submitReq([]byte{0x01}, map[string]string{
		"Content-Type": "application/octet-stream",
	})
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["status"] != "error" {
		t.Errorf("body.status = %v, want 'error'", got["status"])
	}
}

func TestSubmit_EmptyTopicsArray_400(t *testing.T) {
	h := New(Config{})
	rec := httptest.NewRecorder()
	r := submitReq([]byte{0x01}, map[string]string{
		"Content-Type": "application/octet-stream",
		"x-topics":     `[]`,
	})
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (empty x-topics)", rec.Code)
	}
}

func TestSubmit_EmptyBody_400(t *testing.T) {
	h := New(Config{})
	rec := httptest.NewRecorder()
	r := submitReq(nil, map[string]string{
		"Content-Type": "application/octet-stream",
		"x-topics":     `["tm_ship"]`,
	})
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (empty body)", rec.Code)
	}
}

func TestSubmit_NonJSONTopics_400(t *testing.T) {
	h := New(Config{})
	rec := httptest.NewRecorder()
	r := submitReq([]byte{0x01}, map[string]string{
		"Content-Type": "application/octet-stream",
		"x-topics":     "tm_ship", // not JSON
	})
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (non-JSON x-topics)", rec.Code)
	}
}

func TestSubmit_WrongContentType_400(t *testing.T) {
	h := New(Config{})
	rec := httptest.NewRecorder()
	r := submitReq([]byte("{}"), map[string]string{
		"Content-Type": "application/json", // wrong
		"x-topics":     `["tm_ship"]`,
	})
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (wrong Content-Type)", rec.Code)
	}
}

func TestSubmit_UnknownTopic_400_WhenKnownTopicsSet(t *testing.T) {
	h := New(Config{
		KnownTopics: func() []string { return []string{"tm_ship", "tm_slap"} },
	})
	rec := httptest.NewRecorder()
	r := submitReq([]byte{0x01}, map[string]string{
		"Content-Type": "application/octet-stream",
		"x-topics":     `["tm_unknown_xyz"]`,
	})
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (unknown topic)", rec.Code)
	}
}

func TestSubmit_UnknownTopic_Accepted_WhenKnownTopicsNotSet(t *testing.T) {
	// Without KnownTopics, the route accepts any topic and defers to the
	// callback or empty-STEAK fallback.
	h := New(Config{})
	rec := httptest.NewRecorder()
	r := submitReq([]byte{0x01}, map[string]string{
		"Content-Type": "application/octet-stream",
		"x-topics":     `["tm_anything"]`,
	})
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (no KnownTopics filter)", rec.Code)
	}
}

func TestSubmit_CallbackInvokedWithDecodedRequest(t *testing.T) {
	var captured SubmitRequest
	var called int
	h := New(Config{
		Submit: func(req SubmitRequest) (SubmitResponse, error) {
			called++
			captured = req
			return SubmitResponse{
				"tm_ship": {OutputsToAdmit: []uint32{0, 2}},
			}, nil
		},
	})
	rec := httptest.NewRecorder()
	r := submitReq([]byte{0xbe, 0xef}, map[string]string{
		"Content-Type":                 "application/octet-stream",
		"x-topics":                     `["tm_ship"]`,
		"x-includes-off-chain-values":  "true",
	})
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if called != 1 {
		t.Fatalf("callback invoked %d times, want 1", called)
	}
	if !captured.IncludesOffChainValues {
		t.Error("IncludesOffChainValues = false, want true")
	}
	if len(captured.Topics) != 1 || captured.Topics[0] != "tm_ship" {
		t.Errorf("Topics = %v", captured.Topics)
	}
	if !bytes.Equal(captured.Body, []byte{0xbe, 0xef}) {
		t.Errorf("Body = %x", captured.Body)
	}

	var got SubmitResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	admitted := got["tm_ship"].OutputsToAdmit
	if len(admitted) != 2 || admitted[0] != 0 || admitted[1] != 2 {
		t.Errorf("STEAK admittance = %v, want [0,2]", admitted)
	}
}

func TestSubmit_CallbackError_500(t *testing.T) {
	h := New(Config{
		Submit: func(req SubmitRequest) (SubmitResponse, error) {
			return nil, errors.New("engine error")
		},
	})
	rec := httptest.NewRecorder()
	r := submitReq([]byte{0x01}, map[string]string{
		"Content-Type": "application/octet-stream",
		"x-topics":     `["tm_ship"]`,
	})
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["status"] != "error" {
		t.Errorf("body.status = %v", got["status"])
	}
}

func TestSubmit_CallbackNotInvokedOnBadRequest(t *testing.T) {
	called := 0
	h := New(Config{
		Submit: func(req SubmitRequest) (SubmitResponse, error) {
			called++
			return SubmitResponse{}, nil
		},
	})
	rec := httptest.NewRecorder()
	r := submitReq(nil, map[string]string{ // empty body
		"Content-Type": "application/octet-stream",
		"x-topics":     `["tm_ship"]`,
	})
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if called != 0 {
		t.Errorf("callback invoked %d on bad request; expected 0", called)
	}
}

func TestSubmit_ErrorResponseHasMessageField(t *testing.T) {
	// Vector .12: error response body must include `message` (string).
	h := New(Config{})
	rec := httptest.NewRecorder()
	r := submitReq(nil, map[string]string{
		"Content-Type": "application/octet-stream",
	})
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	msg, ok := got["message"].(string)
	if !ok {
		t.Fatalf("error body missing 'message' string field: %v", got)
	}
	if strings.TrimSpace(msg) == "" {
		t.Error("error body 'message' field is empty")
	}
}
