package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/messaging"
)

func messageHandlerServer(t *testing.T, opts messaging.Options) (*Server, string) {
	t.Helper()
	srv := testServer(t)
	_, nodeHex, _ := newKeyWallet(t)
	srv.identityPub = nodeHex
	store, err := messaging.NewStore(t.TempDir(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	srv.msgStore = store
	return srv, nodeHex
}

func callMessageHandler(t *testing.T, handler http.HandlerFunc, payload any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer test-token")
	recorder := httptest.NewRecorder()
	handler(recorder, req)
	var body map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &body)
	return recorder, body
}

func TestMessageHTTPPairQuotaAndOtherRecipient(t *testing.T) {
	srv, _ := messageHandlerServer(t, messaging.Options{MaxPairMessages: 1, MaxStoreMessages: 10})
	_, recipientA, _ := newKeyWallet(t)
	_, recipientB, _ := newKeyWallet(t)
	post := func(recipient string) (*httptest.ResponseRecorder, map[string]any) {
		return callMessageHandler(t, srv.handleSendMessage, map[string]string{
			"recipient": recipient, "messageBox": "box", "body": "body",
		})
	}
	if response, body := post(recipientA); response.Code != http.StatusOK {
		t.Fatalf("first send = %d, %v", response.Code, body)
	}
	response, body := post(recipientA)
	if response.Code != http.StatusTooManyRequests || body["code"] != "ERR_SENDER_QUOTA_EXCEEDED" {
		t.Fatalf("pair quota = %d, %v", response.Code, body)
	}
	if body["description"] != body["error"] {
		t.Fatalf("coded error aliases differ: %v", body)
	}
	if response, body = post(recipientB); response.Code != http.StatusOK {
		t.Fatalf("other pair = %d, %v", response.Code, body)
	}
}

func TestMessageHTTPNodeAndInboxQuota(t *testing.T) {
	_, recipientA, _ := newKeyWallet(t)
	_, recipientB, _ := newKeyWallet(t)
	for _, tc := range []struct {
		name            string
		opts            messaging.Options
		secondRecipient string
		code            string
	}{
		{name: "node", opts: messaging.Options{MaxPairMessages: 10, MaxStoreMessages: 1}, secondRecipient: recipientB, code: "ERR_NODE_STORE_FULL"},
		{name: "inbox", opts: messaging.Options{MaxPairMessages: 10, MaxStoreMessages: 10, MaxInboxMessages: 1}, secondRecipient: recipientA, code: "ERR_INBOX_QUOTA_EXCEEDED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := messageHandlerServer(t, tc.opts)
			first, _ := callMessageHandler(t, srv.handleSendMessage, map[string]string{"recipient": recipientA, "messageBox": "box", "body": "one"})
			if first.Code != http.StatusOK {
				t.Fatalf("first = %d", first.Code)
			}
			second, body := callMessageHandler(t, srv.handleSendMessage, map[string]string{"recipient": tc.secondRecipient, "messageBox": "box", "body": "two"})
			if second.Code != http.StatusTooManyRequests || body["code"] != tc.code {
				t.Fatalf("second = %d, %v", second.Code, body)
			}
		})
	}
}

func TestMessageHTTPValidationAndEmptyList(t *testing.T) {
	srv, nodeHex := messageHandlerServer(t, messaging.Options{})
	response, body := callMessageHandler(t, srv.handleSendMessage, map[string]string{"recipient": "02bad", "messageBox": "box", "body": "x"})
	if response.Code != http.StatusBadRequest || body["code"] != "ERR_INVALID_RECIPIENT_KEY" {
		t.Fatalf("recipient validation = %d, %v", response.Code, body)
	}
	_, bodyRecipient, _ := newKeyWallet(t)
	response, body = callMessageHandler(t, srv.handleSendMessage, map[string]string{
		"recipient": bodyRecipient, "messageBox": "box", "body": strings.Repeat("x", messaging.MaxMessageBodyBytes),
	})
	if response.Code != http.StatusOK {
		t.Fatalf("maximum body = %d, %v", response.Code, body)
	}
	response, body = callMessageHandler(t, srv.handleSendMessage, map[string]string{
		"recipient": bodyRecipient, "messageBox": "box", "body": strings.Repeat("x", messaging.MaxMessageBodyBytes+1),
	})
	if response.Code != http.StatusRequestEntityTooLarge || body["code"] != "ERR_MESSAGE_BODY_TOO_LARGE" {
		t.Fatalf("oversized body = %d, %v", response.Code, body)
	}
	response, body = callMessageHandler(t, srv.handleListMessages, map[string]string{"recipient": nodeHex, "messageBox": string(make([]byte, 129))})
	if response.Code != http.StatusBadRequest || body["code"] != "ERR_MESSAGEBOX_TOO_LARGE" {
		t.Fatalf("box validation = %d, %v", response.Code, body)
	}
	ids := make([]string, 1001)
	response, body = callMessageHandler(t, srv.handleAcknowledgeMessage, map[string]any{"recipient": nodeHex, "messageIds": ids})
	if response.Code != http.StatusBadRequest || body["code"] != "ERR_INVALID_MESSAGE_ID" {
		t.Fatalf("ack validation = %d, %v", response.Code, body)
	}
	response, body = callMessageHandler(t, srv.handleListMessages, map[string]string{"recipient": nodeHex, "messageBox": "empty"})
	if response.Code != http.StatusOK {
		t.Fatalf("empty list = %d, %v", response.Code, body)
	}
	messages, ok := body["messages"].([]any)
	if !ok || len(messages) != 0 {
		t.Fatalf("messages should encode as []: %s", response.Body.String())
	}
}

func TestMessageHTTPSSEPushUsesStoredView(t *testing.T) {
	srv, _ := messageHandlerServer(t, messaging.Options{})
	_, recipient, _ := newKeyWallet(t)
	ch := make(chan *messaging.StoredMessage, 1)
	defer srv.msgHub.subscribe(recipient, "box", ch)()
	srv.msgStore.SetOnStoredMessage(srv.NotifyMessage)
	response, body := callMessageHandler(t, srv.handleSendMessage, map[string]string{
		"recipient": recipient, "messageBox": "box", "body": "body",
	})
	if response.Code != http.StatusOK {
		t.Fatalf("send = %d, %v", response.Code, body)
	}
	msg := <-ch
	if msg.AttestedBy != "local" || msg.ReceivedAt == 0 {
		t.Fatalf("SSE stored view = %+v", msg)
	}
}
