package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/BSVanon/Anvil/internal/messaging"
)

// handleSendMessage handles POST /sendMessage — send a message to a recipient.
// The caller provides their own pubkey as `sender`. Auth token gates API access;
// the sender field identifies who the message is from.
// BRC-33 pattern.
func (s *Server) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	if s.msgStore == nil {
		writeError(w, http.StatusServiceUnavailable, "messaging not enabled")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}

	var req struct {
		Sender     string `json:"sender"`
		Recipient  string `json:"recipient"`
		MessageBox string `json:"messageBox"`
		Body       string `json:"body"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	if len(req.Recipient) != 66 {
		writeError(w, http.StatusBadRequest, "recipient must be 66-char compressed pubkey hex")
		return
	}
	// Default sender to node identity if not provided.
	sender := req.Sender
	if sender == "" {
		sender = s.identityPub
	}
	if len(sender) != 66 {
		writeError(w, http.StatusBadRequest, "sender must be 66-char compressed pubkey hex")
		return
	}

	msg := &messaging.Message{
		Sender:     sender,
		Recipient:  req.Recipient,
		MessageBox: req.MessageBox,
		Body:       req.Body,
	}

	id, err := s.msgStore.Send(msg)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, fmt.Sprintf("send failed: %v", err))
		return
	}

	// Forward to mesh for cross-node delivery.
	if s.gossipMgr != nil {
		s.gossipMgr.ForwardSignedMessage(msg, "")
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "success",
		"messageId": id,
	})
}

// handleListMessages handles POST /listMessages — retrieve messages for
// a specific recipient identity. The caller provides their pubkey.
// Auth token gates API access; the recipient field scopes the query.
func (s *Server) handleListMessages(w http.ResponseWriter, r *http.Request) {
	if s.msgStore == nil {
		writeError(w, http.StatusServiceUnavailable, "messaging not enabled")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}

	var req struct {
		Recipient  string `json:"recipient"`
		MessageBox string `json:"messageBox"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}
	if req.MessageBox == "" {
		writeError(w, http.StatusBadRequest, "messageBox required")
		return
	}
	// Default recipient to node identity if not provided.
	recipient := req.Recipient
	if recipient == "" {
		recipient = s.identityPub
	}

	msgs, err := s.msgStore.List(recipient, req.MessageBox)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("list failed: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "success",
		"messages": msgs,
	})
}

// handleAcknowledgeMessage handles POST /acknowledgeMessage — delete messages
// after receipt. Caller provides their recipient pubkey to scope deletion.
func (s *Server) handleAcknowledgeMessage(w http.ResponseWriter, r *http.Request) {
	if s.msgStore == nil {
		writeError(w, http.StatusServiceUnavailable, "messaging not enabled")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}

	var req struct {
		Recipient  string   `json:"recipient"`
		MessageIDs []string `json:"messageIds"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}
	if len(req.MessageIDs) == 0 {
		writeError(w, http.StatusBadRequest, "messageIds required")
		return
	}
	// Default recipient to node identity if not provided.
	recipient := req.Recipient
	if recipient == "" {
		recipient = s.identityPub
	}

	n, err := s.msgStore.Acknowledge(recipient, req.MessageIDs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("acknowledge failed: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":       "success",
		"acknowledged": n,
	})
}
