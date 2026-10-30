package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/BSVanon/Anvil/internal/messaging"
)

// handleSendMessage handles POST /sendMessage — send a message to a recipient.
// The sender is the BRC-31-authenticated caller identity (canonical messagebox
// model); under the operator-token fallback the sender is the node identity.
// BRC-33 pattern.
func (s *Server) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	if s.msgStore == nil {
		writeError(w, http.StatusServiceUnavailable, "messaging not enabled")
		return
	}

	caller, ok := s.resolveMessageCaller(w, r)
	if !ok {
		return
	}

	// JSON escaping can make a valid 1 MiB decoded body substantially larger on
	// the wire. Bound the request at the worst-case escape expansion, then apply
	// the exact decoded-body limit in messaging.Store.
	body, err := io.ReadAll(io.LimitReader(r.Body, 6*messaging.MaxMessageBodyBytes+(64<<10)))
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

	// Sender is the authenticated caller: their own identity under BRC-31, or
	// the node identity under the operator-token fallback. Either way the
	// forwarded message is signed by the node, so the hop is verifiable.
	sender := caller.identityHex

	msg := &messaging.Message{
		Sender:     sender,
		Recipient:  req.Recipient,
		MessageBox: req.MessageBox,
		Body:       req.Body,
	}

	id, err := s.msgStore.Send(msg, s.identityPub)
	if err != nil {
		writeMessagingError(w, err, http.StatusUnprocessableEntity)
		return
	}

	// Forward to mesh for cross-node delivery.
	// ForwardMessage signs with the node's identity key.
	if s.gossipMgr != nil {
		s.gossipMgr.ForwardMessage(msg)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "success",
		"messageId": id,
	})
}

// handleListMessages handles POST /listMessages — retrieve messages for the
// caller. Under BRC-31 the query is strictly scoped to the authenticated
// identity (you can only read your own inbox); under the operator-token
// fallback the recipient may be supplied in the body (defaulting to the node).
func (s *Server) handleListMessages(w http.ResponseWriter, r *http.Request) {
	if s.msgStore == nil {
		writeError(w, http.StatusServiceUnavailable, "messaging not enabled")
		return
	}

	caller, ok := s.resolveMessageCaller(w, r)
	if !ok {
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}

	var req struct {
		Recipient  string          `json:"recipient"`
		MessageBox string          `json:"messageBox"`
		Limit      json.RawMessage `json:"limit"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}
	if req.MessageBox == "" {
		writeCodedError(w, http.StatusBadRequest, "ERR_INVALID_MESSAGEBOX", "Invalid message box.")
		return
	}
	if len(req.MessageBox) > messaging.MaxMessageBoxBytes {
		writeCodedError(w, http.StatusBadRequest, "ERR_MESSAGEBOX_TOO_LARGE", "Message box names must not exceed 128 bytes.")
		return
	}
	limit := 0
	if len(req.Limit) != 0 {
		if err := json.Unmarshal(req.Limit, &limit); err != nil || limit < 0 {
			writeCodedError(w, http.StatusBadRequest, "ERR_INVALID_LIMIT", "limit must be a non-negative integer")
			return
		}
	}
	if limit > 100 {
		limit = 100
	}
	recipient := s.scopedRecipient(caller, req.Recipient)

	msgs, err := s.msgStore.ListN(recipient, req.MessageBox, limit)
	if err != nil {
		writeMessagingError(w, err, http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "success",
		"messages": msgs,
	})
}

// handleAcknowledgeMessage handles POST /acknowledgeMessage — delete messages
// after receipt. Under BRC-31 deletion is strictly scoped to the authenticated
// identity's inbox; under the operator-token fallback the recipient may be
// supplied in the body (defaulting to the node).
func (s *Server) handleAcknowledgeMessage(w http.ResponseWriter, r *http.Request) {
	if s.msgStore == nil {
		writeError(w, http.StatusServiceUnavailable, "messaging not enabled")
		return
	}

	caller, ok := s.resolveMessageCaller(w, r)
	if !ok {
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
		writeCodedError(w, http.StatusBadRequest, "ERR_MESSAGE_ID_REQUIRED", "Please provide the ID of the message(s) to acknowledge!")
		return
	}
	if len(req.MessageIDs) > 1000 {
		writeCodedError(w, http.StatusBadRequest, "ERR_INVALID_MESSAGE_ID", "Message IDs must be an array of at most 1000 non-empty strings.")
		return
	}
	recipient := s.scopedRecipient(caller, req.Recipient)

	n, err := s.msgStore.Acknowledge(recipient, req.MessageIDs)
	if err != nil {
		writeMessagingError(w, err, http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":       "success",
		"acknowledged": n,
	})
}
