package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/BSVanon/Anvil/internal/messaging"
)

// handleSendMessage handles POST /sendMessage — send a message to a recipient.
// Sender identity comes from the auth token (bearer) — the server knows who
// is making the request. BRC-33 pattern.
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

	msg := &messaging.Message{
		Sender:     s.identityPub, // node's identity is the sender for API-submitted messages
		Recipient:  req.Recipient,
		MessageBox: req.MessageBox,
		Body:       req.Body,
	}

	id, err := s.msgStore.Send(msg)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, fmt.Sprintf("send failed: %v", err))
		return
	}

	// Forward to mesh if recipient is not local.
	// Gossip manager handles cross-node delivery.
	if s.gossipMgr != nil {
		s.gossipMgr.ForwardMessage(msg)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "success",
		"messageId": id,
	})
}

// handleListMessages handles POST /listMessages — retrieve messages for the
// authenticated caller. Only returns messages where the caller's identity
// matches the recipient pubkey.
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

	// The caller retrieves their own messages using the node's identity.
	// In a full BRC-33 implementation, the caller's identity would come
	// from BRC-31 session auth. For now, we use the node's identity pubkey.
	recipient := s.identityPub

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
// after receipt. Only the recipient (node identity) can acknowledge.
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

	recipient := s.identityPub
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
